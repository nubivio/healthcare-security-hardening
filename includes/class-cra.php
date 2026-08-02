<?php
/**
 * CRA plugin-readiness scanner.
 *
 * Queries the WordPress.org Plugins API for each active plugin and scores it
 * for update currency, compatibility and directory presence. All calls are
 * cached in transients and only run during an admin or cron triggered scan.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Registered domains of vendors that sell plugins outside the WordPress.org
 * directory. A plugin whose PluginURI/AuthorURI points at one of these is
 * commercial by design, not a removed or abandoned directory plugin.
 * Extend at runtime with the nubivio_hsh_commercial_vendors filter.
 */
if (!defined('NUBIVIO_HSH_COMMERCIAL_VENDORS_DEFAULT')) {
    define('NUBIVIO_HSH_COMMERCIAL_VENDORS_DEFAULT', implode(',', array(
        'rocketgenius.com',
        'gravityforms.com',
        'wpforms.com',
        'advancedcustomfields.com',
        'elegantthemes.com',
        'divi.com',
        'gravitywp.com',
        'gravityview.co',
        'yoast.com',
        'iconicwp.com',
        'wpmudev.com',
        'elementor.com',
        'astra.build',
        'wpastra.com',
        'brainstormforce.com',
        'automattic.com',
        'woocommerce.com',
        'jetpack.com',
        'convertkit.com',
        'mailerlite.com',
        'mailchimp.com',
        'sucuri.net',
        'wordfence.com',
        'kadencewp.com',
        'generatepress.com',
        'oxygenapp.com',
        'bricksbuilder.io',
        'wp-rocket.me',
        'imagify.io',
        'searchwp.com',
        'gravitywiz.com',
        'givewp.com',
        'soflyy.com',
    )));
}

class Nubivio_HSH_Cra {

    /** @var Nubivio_HSH */
    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    /**
     * Run the CRA plugin-readiness assessment.
     *
     * @return array{findings:array<int,array>,counts:array<string,int>}
     */
    public function run() {
        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $all    = get_plugins();
        $wp_ver = $this->wp_major();

        foreach ($all as $file => $data) {
            if (!is_plugin_active($file)) {
                continue;
            }
            // Skip this plugin itself gracefully.
            if (strpos($file, Nubivio_HSH::SLUG . '/') === 0) {
                continue;
            }

            $name = isset($data['Name']) ? $data['Name'] : $file;
            $slug = $this->slug_from_file($file);
            if ($slug === '') {
                continue;
            }

            $info = $this->fetch_plugin_info($slug);

            if (!is_array($info)) {
                $class = $this->classify_missing($file, $data, $slug, $info === 'closed');

                if ($class === 'commercial') {
                    $severity = 'low';
                    $message  = __('Commercial plugin. Not in the public WordPress.org directory. Verify updates via the vendor\'s own channel.', 'nubivio-healthcare-security-hardening');
                } elseif ($class === 'possibly_removed') {
                    $severity = 'high';
                    $message  = __('Was in the WordPress.org directory but appears to be removed or closed.', 'nubivio-healthcare-security-hardening');
                } else {
                    $severity = 'medium';
                    $message  = __('Not in the public WordPress.org directory. Verify this is a private or commercial plugin and that you have a trusted update path.', 'nubivio-healthcare-security-hardening');
                }

                $findings[] = $this->finding($name, $slug, $severity, $message);
                $counts[$severity]++;
                continue;
            }

            // last_updated staleness.
            if (!empty($info['last_updated'])) {
                $age_days = (int) floor((time() - strtotime($info['last_updated'])) / DAY_IN_SECONDS);
                if ($age_days > 730) {
                    $findings[] = $this->finding($name, $slug, 'high', sprintf(
                        /* translators: %d: number of days since last update. */
                        __('Not updated in %d days; likely abandoned.', 'nubivio-healthcare-security-hardening'),
                        $age_days
                    ));
                    $counts['high']++;
                } elseif ($age_days > 365) {
                    $findings[] = $this->finding($name, $slug, 'medium', sprintf(
                        /* translators: %d: number of days since last update. */
                        __('Stale: not updated in %d days.', 'nubivio-healthcare-security-hardening'),
                        $age_days
                    ));
                    $counts['medium']++;
                }
            }

            // WP "tested up to" lag against installed WP release (x.y counts as a major).
            if ($wp_ver > 0 && !empty($info['tested'])) {
                $tested_major = $this->major_of($info['tested']);
                $lag = ($wp_ver - $tested_major) / 10;
                if ($lag >= 2) {
                    $findings[] = $this->finding($name, $slug, 'medium', sprintf(
                        /* translators: %s: WordPress version the plugin was tested up to. */
                        __('Tested only up to WordPress %s; two or more major versions behind.', 'nubivio-healthcare-security-hardening'),
                        $info['tested']
                    ));
                    $counts['medium']++;
                } elseif ($lag >= 1) {
                    $findings[] = $this->finding($name, $slug, 'low', sprintf(
                        /* translators: %s: WordPress version the plugin was tested up to. */
                        __('Tested only up to WordPress %s; one major version behind.', 'nubivio-healthcare-security-hardening'),
                        $info['tested']
                    ));
                    $counts['low']++;
                }
            }

            // requires_php EOL.
            if (!empty($info['requires_php']) && version_compare($info['requires_php'], '7.4', '<')) {
                $findings[] = $this->finding($name, $slug, 'medium', sprintf(
                    /* translators: %s: minimum PHP version required by the plugin. */
                    __('Requires PHP %s, which is end of life.', 'nubivio-healthcare-security-hardening'),
                    $info['requires_php']
                ));
                $counts['medium']++;
            }

            // Support thread resolution.
            if (isset($info['support_threads'], $info['support_threads_resolved'])
                && (int) $info['support_threads'] >= 10) {
                $threads   = (int) $info['support_threads'];
                $resolved  = (int) $info['support_threads_resolved'];
                $rate      = $threads > 0 ? ($resolved / $threads) : 1;
                if ($rate < 0.30) {
                    $findings[] = $this->finding($name, $slug, 'low', sprintf(
                        /* translators: %d: percentage of resolved support threads. */
                        __('Low support resolution rate (%d%% of recent threads resolved).', 'nubivio-healthcare-security-hardening'),
                        (int) round($rate * 100)
                    ));
                    $counts['low']++;
                }
            }

            // Rating (0-100 scale) over enough ratings.
            if (isset($info['rating'], $info['num_ratings'])
                && (int) $info['num_ratings'] >= 50
                && (float) $info['rating'] < 60) {
                $stars = round(((float) $info['rating'] / 100) * 5, 1);
                $findings[] = $this->finding($name, $slug, 'low', sprintf(
                    /* translators: %s: average star rating out of 5. */
                    __('Low average rating (%s of 5).', 'nubivio-healthcare-security-hardening'),
                    $stars
                ));
                $counts['low']++;
            }

            // Active installs.
            if (isset($info['active_installs']) && (int) $info['active_installs'] < 100 && (int) $info['active_installs'] >= 0) {
                $findings[] = $this->finding($name, $slug, 'low', __('Very small install base (under 100 active installs).', 'nubivio-healthcare-security-hardening'));
                $counts['low']++;
            }
        }

        return array('findings' => $findings, 'counts' => $counts);
    }

    /**
     * Retrieve plugin metadata from the WordPress.org Plugins API.
     *
     * @param string $slug Plugin slug.
     * @return array|string Array of info, 'closed' if removed/404, or 'unknown' if not in directory.
     */
    private function fetch_plugin_info($slug) {
        $key    = 'nubivio_hsh_wporg_' . $slug;
        $cached = get_transient($key);
        if ($cached !== false) {
            return $cached;
        }

        $url = 'https://api.wordpress.org/plugins/info/1.0/' . rawurlencode($slug) . '.json';
        $res = wp_remote_get($url, array('timeout' => 8, 'sslverify' => true));

        if (is_wp_error($res)) {
            // Do not cache transient network failures for the full 12h.
            set_transient($key, 'unknown', HOUR_IN_SECONDS);
            return 'unknown';
        }

        $code = (int) wp_remote_retrieve_response_code($res);
        $body = wp_remote_retrieve_body($res);

        if ($code === 404) {
            set_transient($key, 'closed', 12 * HOUR_IN_SECONDS);
            return 'closed';
        }

        $data = json_decode($body, true);
        if (!is_array($data) || isset($data['error'])) {
            // API returns {"error":"..."} for closed/removed plugins.
            if (is_array($data) && isset($data['error'])) {
                set_transient($key, 'closed', 12 * HOUR_IN_SECONDS);
                return 'closed';
            }
            set_transient($key, 'unknown', 12 * HOUR_IN_SECONDS);
            return 'unknown';
        }

        set_transient($key, $data, 12 * HOUR_IN_SECONDS);
        return $data;
    }

    /**
     * Decide why a plugin is absent from the WordPress.org directory.
     *
     * First signal to hit wins, strongest trust first.
     *
     * @param string $file    Plugin file, e.g. "gravityforms/gravityforms.php".
     * @param array  $data    Plugin header data from get_plugins().
     * @param string $slug    Directory slug derived from $file.
     * @param bool   $is_404  Whether the Plugins API answered "not found".
     * @return string 'commercial'|'possibly_removed'|'unknown'
     */
    private function classify_missing($file, $data, $slug, $is_404) {
        // 1. User allowlist: the site owner has vouched for this slug.
        if (in_array($slug, $this->private_plugin_slugs(), true)) {
            return 'commercial';
        }

        // 2. Vendor domain fingerprint from the plugin headers.
        $vendors = $this->commercial_vendors();
        foreach (array('PluginURI', 'AuthorURI') as $field) {
            if (empty($data[$field])) {
                continue;
            }
            $domain = $this->registered_domain($data[$field]);
            if ($domain !== '' && in_array($domain, $vendors, true)) {
                return 'commercial';
            }
        }

        // 3. Update package served from somewhere other than WordPress.org.
        $updates = get_site_transient('update_plugins');
        if (is_object($updates)) {
            foreach (array('response', 'no_update') as $bucket) {
                $entries = isset($updates->$bucket) ? $updates->$bucket : null;
                if (!is_array($entries) || empty($entries[$file]->package)) {
                    continue;
                }
                $host = strtolower((string) wp_parse_url($entries[$file]->package, PHP_URL_HOST));
                if ($host !== '' && $host !== 'downloads.wordpress.org') {
                    return 'commercial';
                }
            }
        }

        // 4. The plugin itself claims WordPress.org membership, but the API says no.
        if ($is_404 && !empty($data['UpdateURI'])) {
            $host = strtolower((string) wp_parse_url($data['UpdateURI'], PHP_URL_HOST));
            if ($host === 'w.org' || $host === 'wordpress.org' || substr($host, -14) === '.wordpress.org') {
                return 'possibly_removed';
            }
        }

        return 'unknown';
    }

    /**
     * Slugs the site owner marked as private or commercial.
     *
     * Stored as an array by the settings form; a comma or newline separated
     * string is accepted too so hand-edited options still work.
     *
     * @return array<int,string>
     */
    private function private_plugin_slugs() {
        $o    = $this->core->get_options();
        $list = isset($o['private_plugin_slugs']) ? $o['private_plugin_slugs'] : array();
        if (!is_array($list)) {
            $list = preg_split('/[\s,]+/', (string) $list);
        }
        $out = array();
        foreach ($list as $item) {
            $item = sanitize_key($item);
            if ($item !== '') {
                $out[] = $item;
            }
        }
        return $out;
    }

    /**
     * @return array<int,string> Lower-case registered domains.
     */
    private function commercial_vendors() {
        $vendors = preg_split('/[\s,]+/', NUBIVIO_HSH_COMMERCIAL_VENDORS_DEFAULT);
        $vendors = apply_filters('nubivio_hsh_commercial_vendors', $vendors);
        $out = array();
        foreach ((array) $vendors as $vendor) {
            $vendor = strtolower(trim((string) $vendor));
            if ($vendor !== '') {
                $out[] = $vendor;
            }
        }
        return $out;
    }

    /**
     * Registered domain of a URL: the last two labels, or three for the
     * handful of ccSLDs that would otherwise collapse to "co.uk".
     *
     * @param string $url
     * @return string Lower-case domain, or '' when the URL has no host.
     */
    private function registered_domain($url) {
        $host = strtolower((string) wp_parse_url((string) $url, PHP_URL_HOST));
        if ($host === '') {
            return '';
        }
        $cc_slds = array('co.uk', 'org.uk', 'me.uk', 'com.au', 'net.au', 'co.nz', 'co.za', 'co.jp', 'com.br');
        foreach ($cc_slds as $sld) {
            if (substr($host, -(strlen($sld) + 1)) === '.' . $sld) {
                if (preg_match('/([a-z0-9-]+\.' . preg_quote($sld, '/') . ')$/i', $host, $m)) {
                    return strtolower($m[1]);
                }
            }
        }
        if (preg_match('/([a-z0-9-]+\.[a-z]{2,})$/i', $host, $m)) {
            return strtolower($m[1]);
        }
        return $host;
    }

    private function slug_from_file($file) {
        if (strpos($file, '/') !== false) {
            $parts = explode('/', $file);
            return sanitize_key($parts[0]);
        }
        // Single-file plugin: use the basename without extension.
        return sanitize_key(basename($file, '.php'));
    }

    private function wp_major() {
        return $this->major_of(get_bloginfo('version'));
    }

    /**
     * Release ordinal where each x.y counts as a WordPress "major" step.
     * Example: 6.4 => 64, 6.7 => 67, so 6.7 is three steps ahead of 6.4.
     */
    private function major_of($version) {
        $version = preg_replace('/[^0-9.].*$/', '', (string) $version);
        $parts   = explode('.', $version);
        $major   = isset($parts[0]) ? (int) $parts[0] : 0;
        $minor   = isset($parts[1]) ? (int) $parts[1] : 0;
        return ($major * 10) + $minor;
    }

    private function finding($name, $slug, $severity, $message) {
        return array(
            'plugin'   => $name,
            'slug'     => $slug,
            'severity' => $severity,
            'message'  => $message,
        );
    }
}
