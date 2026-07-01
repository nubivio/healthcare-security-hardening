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

            if ($info === 'closed') {
                $findings[] = $this->finding(
                    $name,
                    $slug,
                    'high',
                    __('Plugin not found in the WordPress.org directory; may be removed or closed.', 'nubivio-healthcare-security-hardening')
                );
                $counts['high']++;
                continue;
            }

            if ($info === 'unknown' || !is_array($info)) {
                // Premium or otherwise not in the public directory: informational.
                $findings[] = $this->finding(
                    $name,
                    $slug,
                    'low',
                    __('Not in the public WordPress.org directory; cannot verify update or compatibility status.', 'nubivio-healthcare-security-hardening')
                );
                $counts['low']++;
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
