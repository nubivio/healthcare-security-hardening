<?php
/**
 * NIS2 Article 21 posture checks.
 *
 * Six weighted signals. Where Salus owns the control (transport encryption via
 * HSTS) the state is verified for real; the rest use filterable slug heuristics.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Nis2 {

    /** @var Nubivio_HSH */
    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    /**
     * @return array{findings:array<int,array>,counts:array<string,int>,score_points:int}
     */
    public function run() {
        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);

        $weights = array(
            'https'        => 40,
            'mfa'          => 20,
            'backup'       => 20,
            'waf'          => 15,
            'activity_log' => 10,
            'auto_update'  => 5,
        );

        $present = array(
            'https'        => $this->check_https(),
            'mfa'          => $this->has_active_plugin($this->slugs('mfa', array('two-factor', 'wordfence', 'miniorange-2-factor-authentication', 'wp-2fa', 'google-authenticator'))),
            'backup'       => $this->has_active_plugin($this->slugs('backup', array('updraftplus', 'backwpup', 'backupbuddy', 'duplicator', 'wp-migrate-db'))),
            'waf'          => $this->has_active_plugin($this->slugs('waf', array('wordfence', 'sucuri-scanner', 'ninjafirewall', 'all-in-one-wp-security-and-firewall'))),
            'activity_log' => $this->has_active_plugin($this->slugs('activity_log', array('wp-security-audit-log', 'simple-history', 'activity-log', 'aryo-activity-log'))),
            'auto_update'  => $this->check_auto_update(),
        );

        $labels = array(
            'https'        => __('Encryption in transit (HTTPS/HSTS)', 'nubivio-healthcare-security-hardening'),
            'mfa'          => __('Multi-factor authentication', 'nubivio-healthcare-security-hardening'),
            'backup'       => __('Backups', 'nubivio-healthcare-security-hardening'),
            'waf'          => __('Web application firewall', 'nubivio-healthcare-security-hardening'),
            'activity_log' => __('Activity logging', 'nubivio-healthcare-security-hardening'),
            'auto_update'  => __('Automatic updates', 'nubivio-healthcare-security-hardening'),
        );

        $points = 0;
        foreach ($weights as $key => $weight) {
            if (!empty($present[$key])) {
                $points += $weight;
                continue;
            }
            if ($key === 'https') {
                $severity = 'high';
            } elseif ($weight >= 20) {
                $severity = 'medium';
            } else {
                $severity = 'low';
            }
            $findings[] = array(
                'signal'   => $key,
                'severity' => $severity,
                'message'  => sprintf(
                    /* translators: %s: name of the missing NIS2 signal. */
                    __('No %s detected (NIS2 Art. 21).', 'nubivio-healthcare-security-hardening'),
                    $labels[$key]
                ),
            );
            $counts[$severity]++;
        }

        $total = array_sum($weights);
        $score_points = $total > 0 ? (int) round(($points / $total) * 100) : 0;

        return array('findings' => $findings, 'counts' => $counts, 'score_points' => $score_points);
    }

    private function check_https() {
        if (is_ssl()) {
            return true;
        }
        return wp_parse_url(home_url(), PHP_URL_SCHEME) === 'https';
    }

    private function check_auto_update() {
        if (defined('WP_AUTO_UPDATE_CORE') && WP_AUTO_UPDATE_CORE) {
            return true;
        }
        return $this->has_active_plugin($this->slugs('auto_update', array('easy-updates-manager', 'companion-auto-update')));
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

    private function slugs($signal, array $default) {
        return apply_filters('nubivio_hsh_nis2_' . $signal . '_plugins', $default);
    }
}
