<?php
/**
 * GDPR posture scanner: third-party scripts, form plugins and consent tooling.
 *
 * Cross-references the plugin's own Content-Security-Policy so that an enforced
 * self-only policy with leaking third-party scripts is flagged as a contradiction.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Gdpr {

    /** @var Nubivio_HSH */
    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    /**
     * @return array{findings:array<int,array>,counts:array<string,int>}
     */
    public function run() {
        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);

        $consent_active = $this->has_active_plugin($this->consent_slugs());
        $external_hosts = $this->external_script_hosts();

        // Third-party script detection.
        if (!empty($external_hosts) && !$consent_active) {
            foreach ($external_hosts as $host) {
                $findings[] = array(
                    'severity' => 'medium',
                    'message'  => sprintf(
                        /* translators: %s: external host serving a script. */
                        __('Third-party script from %s loads without a detected consent mechanism.', 'nubivio-healthcare-security-hardening'),
                        $host
                    ),
                );
                $counts['medium']++;
            }
        }

        // Cross-reference the plugin's own CSP.
        $o          = $this->core->get_options();
        $csp_on     = !empty($o['csp_enabled']) && empty($o['csp_report_only']) && trim((string) $o['csp_policy']) !== '';
        $csp_policy = (string) $o['csp_policy'];
        $csp_self   = $csp_on && $this->csp_is_self_only($csp_policy);

        if ($csp_self && !empty($external_hosts)) {
            $findings[] = array(
                'severity' => 'high',
                'message'  => __('CSP enforces self only, but third-party scripts are loading: contradiction. Review the policy or the scripts.', 'nubivio-healthcare-security-hardening'),
            );
            $counts['high']++;
        } elseif ($csp_self && empty($external_hosts)) {
            $findings[] = array(
                'severity' => 'ok',
                'message'  => __('Enforced CSP restricts scripts to first party and no third-party scripts were detected.', 'nubivio-healthcare-security-hardening'),
            );
        }

        // Form plugin detection without consent.
        if ($this->has_active_plugin($this->form_slugs()) && !$consent_active) {
            $findings[] = array(
                'severity' => 'medium',
                'message'  => __('Forms collect personal data but no consent mechanism was detected.', 'nubivio-healthcare-security-hardening'),
            );
            $counts['medium']++;
        }

        return array('findings' => $findings, 'counts' => $counts);
    }

    /**
     * List of external script hosts, from the passive front-end snapshot or a
     * cached loopback request as a fallback.
     *
     * @return array<int,string>
     */
    private function external_script_hosts() {
        $snapshot = get_transient('nubivio_hsh_frontend_scripts');
        if (is_array($snapshot)) {
            return $snapshot;
        }

        // Fallback: one cached loopback fetch of the home page.
        $cache_key = 'nubivio_hsh_frontend_scripts';
        $res = wp_remote_get(home_url('/'), array('timeout' => 8, 'sslverify' => false));
        if (is_wp_error($res)) {
            set_transient($cache_key, array(), HOUR_IN_SECONDS);
            return array();
        }
        $body = wp_remote_retrieve_body($res);
        $site_host = wp_parse_url(home_url(), PHP_URL_HOST);
        $hosts = array();
        if (preg_match_all('#<script[^>]+src=["\']https?://([^/"\']+)#i', (string) $body, $m)) {
            foreach ($m[1] as $h) {
                $h = strtolower($h);
                if ($h !== '' && $h !== strtolower((string) $site_host) && !in_array($h, $hosts, true)) {
                    $hosts[] = $h;
                }
            }
        }
        set_transient($cache_key, $hosts, 12 * HOUR_IN_SECONDS);
        return $hosts;
    }

    private function csp_is_self_only($policy) {
        // True when script-src (or default-src fallback) is 'self' with no external hosts.
        if (preg_match('/script-src\s+([^;]+)/i', $policy, $m)) {
            $val = $m[1];
        } elseif (preg_match('/default-src\s+([^;]+)/i', $policy, $m)) {
            $val = $m[1];
        } else {
            return false;
        }
        // No scheme or domain tokens beyond keywords like 'self' 'none' data:.
        return !preg_match('#https?://#i', $val);
    }

    private function has_active_plugin(array $slugs) {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        foreach (array_keys(get_plugins()) as $file) {
            if (!is_plugin_active($file)) {
                continue;
            }
            $slug = strpos($file, '/') !== false ? explode('/', $file)[0] : basename($file, '.php');
            if (in_array($slug, $slugs, true)) {
                return true;
            }
        }
        return false;
    }

    private function consent_slugs() {
        return apply_filters('nubivio_hsh_gdpr_consent_plugins', array(
            'complianz-gdpr',
            'cookie-notice',
            'cookie-law-info',
            'gdpr-cookie-compliance',
            'borlabs-cookie',
            'iubenda-cookie-law-solution',
        ));
    }

    private function form_slugs() {
        return apply_filters('nubivio_hsh_gdpr_form_plugins', array(
            'gravityforms',
            'contact-form-7',
            'wpforms-lite',
            'ninja-forms',
            'formidable',
        ));
    }
}
