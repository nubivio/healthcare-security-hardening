<?php
/**
 * Salus-native site health checks, including a live header probe that verifies
 * the plugin's configured headers are actually sent on a real response.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Health {

    /** @var Nubivio_HSH */
    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    /**
     * @return array{checks:array<int,array>,fails:int}
     */
    public function run() {
        $checks = array();

        // security.txt resolvable and non-expired.
        $status = $this->core->security_txt_status();
        if ($status['mode'] === 'dynamic') {
            $checks[] = $this->check(
                __('security.txt', 'nubivio-healthcare-security-hardening'),
                'pass',
                __('Served dynamically (docroot not writable). Still resolvable.', 'nubivio-healthcare-security-hardening')
            );
        } elseif ($status['days'] !== null && $status['days'] > 0) {
            $checks[] = $this->check(
                __('security.txt', 'nubivio-healthcare-security-hardening'),
                'pass',
                sprintf(
                    /* translators: %d: days until security.txt expires. */
                    __('Present and valid, %d days until expiry.', 'nubivio-healthcare-security-hardening'),
                    (int) $status['days']
                )
            );
        } else {
            $checks[] = $this->check(
                __('security.txt', 'nubivio-healthcare-security-hardening'),
                'fail',
                __('Not created or expired.', 'nubivio-healthcare-security-hardening')
            );
        }

        // Live header probe.
        $probe = $this->probe_headers();
        if (!$probe['ok']) {
            $checks[] = $this->check(
                __('Live header verification', 'nubivio-healthcare-security-hardening'),
                'warn',
                __('Could not verify live; showing configured values. A hardened host may block self-requests.', 'nubivio-healthcare-security-hardening')
            );
        } else {
            $configured = $this->core->preview_headers();
            foreach ($configured as $name => $val) {
                $sent = isset($probe['present'][strtolower($name)]);
                $checks[] = $this->check(
                    sprintf(
                        /* translators: %s: HTTP header name. */
                        __('Header: %s', 'nubivio-healthcare-security-hardening'),
                        $name
                    ),
                    $sent ? 'pass' : 'fail',
                    $sent
                        ? __('Configured and sent on a live response.', 'nubivio-healthcare-security-hardening')
                        : __('Configured but not sent; a proxy or theme may strip it.', 'nubivio-healthcare-security-hardening')
                );
            }
        }

        // WP core currency.
        $checks[] = $this->check_core_currency();

        // PHP version support window.
        if (version_compare(PHP_VERSION, '7.4', '<')) {
            $checks[] = $this->check(__('PHP version', 'nubivio-healthcare-security-hardening'), 'fail', sprintf(
                /* translators: %s: PHP version. */
                __('PHP %s is end of life.', 'nubivio-healthcare-security-hardening'),
                PHP_VERSION
            ));
        } elseif (version_compare(PHP_VERSION, '8.0', '<')) {
            $checks[] = $this->check(__('PHP version', 'nubivio-healthcare-security-hardening'), 'warn', sprintf(
                /* translators: %s: PHP version. */
                __('PHP %s is approaching end of life; plan an upgrade.', 'nubivio-healthcare-security-hardening'),
                PHP_VERSION
            ));
        } else {
            $checks[] = $this->check(__('PHP version', 'nubivio-healthcare-security-hardening'), 'pass', sprintf(
                /* translators: %s: PHP version. */
                __('PHP %s is in the supported window.', 'nubivio-healthcare-security-hardening'),
                PHP_VERSION
            ));
        }

        // SSL/TLS presence.
        $https = is_ssl() || wp_parse_url(home_url(), PHP_URL_SCHEME) === 'https';
        $checks[] = $this->check(
            __('HTTPS', 'nubivio-healthcare-security-hardening'),
            $https ? 'pass' : 'fail',
            $https
                ? __('Site is served over HTTPS.', 'nubivio-healthcare-security-hardening')
                : __('Site is not served over HTTPS.', 'nubivio-healthcare-security-hardening')
        );

        // Debug in production.
        if (defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_DISPLAY') && WP_DEBUG_DISPLAY) {
            $checks[] = $this->check(
                __('Debug display', 'nubivio-healthcare-security-hardening'),
                'warn',
                __('WP_DEBUG_DISPLAY is on; errors may leak to visitors.', 'nubivio-healthcare-security-hardening')
            );
        } else {
            $checks[] = $this->check(
                __('Debug display', 'nubivio-healthcare-security-hardening'),
                'pass',
                __('Debug output is not displayed to visitors.', 'nubivio-healthcare-security-hardening')
            );
        }

        // XML-RPC exposure.
        $xmlrpc = apply_filters('xmlrpc_enabled', true);
        $checks[] = $this->check(
            __('XML-RPC', 'nubivio-healthcare-security-hardening'),
            $xmlrpc ? 'warn' : 'pass',
            $xmlrpc
                ? __('XML-RPC appears enabled; consider disabling if unused.', 'nubivio-healthcare-security-hardening')
                : __('XML-RPC is disabled.', 'nubivio-healthcare-security-hardening')
        );

        // REST user enumeration.
        $checks[] = $this->check_rest_users();

        $fails = 0;
        foreach ($checks as $c) {
            if ($c['status'] === 'fail') {
                $fails++;
            }
        }

        return array('checks' => $checks, 'fails' => $fails);
    }

    /**
     * Loopback probe of the home URL. Cached for 10 minutes.
     *
     * @return array{ok:bool,present:array<string,string>,error:string|null}
     */
    public function probe_headers() {
        $cached = get_transient('nubivio_hsh_headers_probe');
        if (is_array($cached)) {
            return $cached;
        }

        $res = wp_remote_get(home_url('/'), array('timeout' => 8, 'sslverify' => false));
        if (is_wp_error($res)) {
            $out = array('ok' => false, 'present' => array(), 'error' => $res->get_error_message());
            set_transient('nubivio_hsh_headers_probe', $out, 10 * MINUTE_IN_SECONDS);
            return $out;
        }

        $headers = wp_remote_retrieve_headers($res);
        $present  = array();
        if ($headers) {
            $arr = is_object($headers) && method_exists($headers, 'getAll') ? $headers->getAll() : (array) $headers;
            foreach ($arr as $name => $val) {
                $present[strtolower($name)] = is_array($val) ? implode(', ', $val) : (string) $val;
            }
        }
        $out = array('ok' => true, 'present' => $present, 'error' => null);
        set_transient('nubivio_hsh_headers_probe', $out, 10 * MINUTE_IN_SECONDS);
        return $out;
    }

    private function check_core_currency() {
        $current = get_bloginfo('version');
        $cached  = get_transient('nubivio_hsh_core_latest');
        if ($cached === false) {
            $res = wp_remote_get('https://api.wordpress.org/core/version-check/1.7/', array('timeout' => 8));
            $cached = '';
            if (!is_wp_error($res)) {
                $data = json_decode(wp_remote_retrieve_body($res), true);
                if (is_array($data) && !empty($data['offers'][0]['current'])) {
                    $cached = (string) $data['offers'][0]['current'];
                }
            }
            set_transient('nubivio_hsh_core_latest', $cached, 12 * HOUR_IN_SECONDS);
        }

        if ($cached === '') {
            return $this->check(
                __('WordPress core', 'nubivio-healthcare-security-hardening'),
                'warn',
                __('Could not determine the latest WordPress version.', 'nubivio-healthcare-security-hardening')
            );
        }

        $cur_major = $this->major_index($current);
        $lat_major = $this->major_index($cached);
        if ($cur_major < $lat_major - 10) {
            $status = 'fail';
        } elseif (version_compare($current, $cached, '<')) {
            $status = 'warn';
        } else {
            $status = 'pass';
        }
        return $this->check(
            __('WordPress core', 'nubivio-healthcare-security-hardening'),
            $status,
            sprintf(
                /* translators: 1: installed version, 2: latest version. */
                __('Running %1$s; latest is %2$s.', 'nubivio-healthcare-security-hardening'),
                $current,
                $cached
            )
        );
    }

    private function check_rest_users() {
        $res = wp_remote_get(rest_url('wp/v2/users'), array('timeout' => 8, 'sslverify' => false));
        if (is_wp_error($res)) {
            return $this->check(
                __('REST user enumeration', 'nubivio-healthcare-security-hardening'),
                'pass',
                __('Could not enumerate users over REST.', 'nubivio-healthcare-security-hardening')
            );
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        $data = json_decode(wp_remote_retrieve_body($res), true);
        if ($code === 200 && is_array($data) && !empty($data)) {
            return $this->check(
                __('REST user enumeration', 'nubivio-healthcare-security-hardening'),
                'warn',
                __('The REST users endpoint lists users publicly.', 'nubivio-healthcare-security-hardening')
            );
        }
        return $this->check(
            __('REST user enumeration', 'nubivio-healthcare-security-hardening'),
            'pass',
            __('The REST users endpoint does not expose users publicly.', 'nubivio-healthcare-security-hardening')
        );
    }

    private function major_index($version) {
        $version = preg_replace('/[^0-9.].*$/', '', (string) $version);
        $parts   = explode('.', $version);
        $major   = isset($parts[0]) ? (int) $parts[0] : 0;
        $minor   = isset($parts[1]) ? (int) $parts[1] : 0;
        return ($major * 10) + $minor;
    }

    private function check($label, $status, $detail) {
        return array('label' => $label, 'status' => $status, 'detail' => $detail);
    }
}
