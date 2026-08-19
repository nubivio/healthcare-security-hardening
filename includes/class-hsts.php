<?php
/**
 * HSTS preload readiness check.
 *
 * @package Nubivio_HSH
 */
if (!defined('ABSPATH')) { exit; }

class Nubivio_HSH_Hsts {
    private $core;
    public function __construct($core) { $this->core = $core; }

    public function run() {
        $host = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        $summary = array('host' => $host, 'header_present' => false, 'max_age' => 0, 'max_age_ok' => false, 'include_subdomains' => false, 'preload' => false, 'ready_for_preload' => false);
        $findings = array();
        $counts = array('high' => 0, 'medium' => 0, 'low' => 0);
        if ($host === '') {
            return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
        }
        $key = 'nubivio_hsh_hsts_' . md5($host);
        $cached = get_transient($key);
        if (is_array($cached)) {
            $summary = $cached;
        } else {
            $res = wp_remote_get(home_url('/'), array('timeout' => 8));
            if (!is_wp_error($res)) {
                $headers = wp_remote_retrieve_headers($res);
                $headers = is_object($headers) && method_exists($headers, 'getAll') ? $headers->getAll() : (array) $headers;
                $value = '';
                foreach ($headers as $name => $header) {
                    if (strtolower((string) $name) === 'strict-transport-security') { $value = is_array($header) ? implode('; ', $header) : (string) $header; break; }
                }
                if ($value !== '') {
                    $summary['header_present'] = true;
                    if (preg_match('/(?:^|;)\s*max-age\s*=\s*(\d+)/i', $value, $m)) { $summary['max_age'] = (int) $m[1]; }
                    $summary['max_age_ok'] = $summary['max_age'] >= 31536000;
                    $summary['include_subdomains'] = (bool) preg_match('/(?:^|;)\s*includesubdomains(?:\s*;|$)/i', $value);
                    $summary['preload'] = (bool) preg_match('/(?:^|;)\s*preload(?:\s*;|$)/i', $value);
                }
            }
            $summary['ready_for_preload'] = $summary['header_present'] && $summary['max_age_ok'] && $summary['include_subdomains'] && $summary['preload'];
            set_transient($key, $summary, HOUR_IN_SECONDS);
        }
        if (!$summary['header_present']) { $this->add($findings, $counts, 'high', __('HSTS header not present in response. HSTS is a foundational protection against HTTPS downgrade.', 'nubivio-healthcare-security-hardening')); }
        elseif (!$summary['max_age_ok']) { $this->add($findings, $counts, 'medium', __('HSTS max-age is too short for preload eligibility. Set at least 31536000.', 'nubivio-healthcare-security-hardening')); }
        if ($summary['header_present'] && !$summary['include_subdomains']) { $this->add($findings, $counts, 'medium', __('HSTS is missing includeSubDomains; required for preload.', 'nubivio-healthcare-security-hardening')); }
        if ($summary['header_present'] && !$summary['preload']) { $this->add($findings, $counts, 'low', __('HSTS is missing the preload directive; add only when you are certain all subdomains serve valid HTTPS.', 'nubivio-healthcare-security-hardening')); }
        return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
    }

    public static function health_row($summary) {
        return array('label' => __('HSTS preload readiness', 'nubivio-healthcare-security-hardening'), 'status' => !empty($summary['ready_for_preload']) ? 'pass' : 'warn', 'detail' => !empty($summary['ready_for_preload']) ? __('All HSTS preload requirements are present.', 'nubivio-healthcare-security-hardening') : __('HSTS is not yet ready for preload.', 'nubivio-healthcare-security-hardening'));
    }
    private function add(&$findings, &$counts, $severity, $message) { $findings[] = array('severity' => $severity, 'message' => $message); $counts[$severity]++; }
}
