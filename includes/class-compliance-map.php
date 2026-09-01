<?php
/**
 * Indicative mapping from passive scan findings to control identifiers in
 * NEN 7510-2:2024 and ISO 27001:2022 Annex A.
 *
 * The module never invents findings of its own; it consumes the frameworks
 * output produced by the scanner and returns coverage numbers per norm. Only
 * control identifiers and short internal titles are stored here. Normative
 * text from either standard is copyrighted and is deliberately not reproduced.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Compliance_Map {

    /** @var Nubivio_HSH */
    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    /**
     * The passive-assessable control set. Kept intentionally compact: only
     * controls a headers and DNS scan can meaningfully signal on. The short
     * titles are our own descriptive labels; they are not normative text.
     *
     * @return array<string,array<string,array<string,string>>>
     */
    public static function assessable_controls() {
        return array(
            'iso27001' => array(
                'A.5.14' => __('Information transfer (email authentication and transport security)', 'nubivio-healthcare-security-hardening'),
                'A.5.30' => __('ICT readiness (certificate and domain freshness)', 'nubivio-healthcare-security-hardening'),
                'A.5.34' => __('Privacy and PII protection (cookies and trackers before consent)', 'nubivio-healthcare-security-hardening'),
                'A.8.5'  => __('Secure authentication (login exposure and password quality)', 'nubivio-healthcare-security-hardening'),
                'A.8.8'  => __('Management of technical vulnerabilities (plugin and core currency)', 'nubivio-healthcare-security-hardening'),
                'A.8.9'  => __('Configuration management (security headers and hardening)', 'nubivio-healthcare-security-hardening'),
                'A.8.20' => __('Network security (DNS resilience and NS redundancy)', 'nubivio-healthcare-security-hardening'),
                'A.8.21' => __('Security of network services (TLS, HSTS, SPF, DKIM, DMARC)', 'nubivio-healthcare-security-hardening'),
                'A.8.24' => __('Use of cryptography (TLS, HSTS, DKIM key strength, CAA)', 'nubivio-healthcare-security-hardening'),
                'A.8.26' => __('Application security requirements (CSP and response headers)', 'nubivio-healthcare-security-hardening'),
            ),
            'nen7510' => array(
                'A.5.14' => __('Information transfer for patient data (email authentication)', 'nubivio-healthcare-security-hardening'),
                'A.5.30' => __('ICT readiness for care continuity (certificate and DNS)', 'nubivio-healthcare-security-hardening'),
                'A.5.34' => __('Patient privacy (cookies, trackers, disclosure)', 'nubivio-healthcare-security-hardening'),
                'A.8.5'  => __('Secure authentication for healthcare users', 'nubivio-healthcare-security-hardening'),
                'A.8.8'  => __('Vulnerability management for medical WordPress sites', 'nubivio-healthcare-security-hardening'),
                'A.8.9'  => __('Configuration management (headers, hardening, disclosure)', 'nubivio-healthcare-security-hardening'),
                'A.8.20' => __('Network security for care communication (DNS resilience)', 'nubivio-healthcare-security-hardening'),
                'A.8.21' => __('Security of network services used in care (TLS, email)', 'nubivio-healthcare-security-hardening'),
                'A.8.24' => __('Cryptography protecting health data in transit', 'nubivio-healthcare-security-hardening'),
                'A.8.26' => __('Application security for patient-facing web', 'nubivio-healthcare-security-hardening'),
            ),
        );
    }

    /**
     * Run the mapping over an already-scanned frameworks array. Returns no
     * findings of its own; keeps the same shape as other modules by returning
     * an empty findings list plus a populated summary.
     *
     * @param array $frameworks Frameworks section from the scanner result.
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function run($frameworks) {
        $frameworks = is_array($frameworks) ? $frameworks : array();
        $sets       = self::assessable_controls();
        $summary    = array();

        foreach ($sets as $norm => $controls) {
            $covered = array();
            foreach ($frameworks as $module => $data) {
                if (!is_array($data) || empty($data['findings'])) {
                    continue;
                }
                foreach ($data['findings'] as $finding) {
                    $msg  = isset($finding['message']) ? (string) $finding['message'] : '';
                    $sev  = isset($finding['severity']) ? (string) $finding['severity'] : 'low';
                    if ($sev === 'info' || $sev === 'ok') {
                        continue;
                    }
                    $ids = $this->classify((string) $module, $msg);
                    foreach ($ids as $id) {
                        if (!isset($controls[$id])) {
                            continue;
                        }
                        if (!isset($covered[$id])) {
                            $covered[$id] = array();
                        }
                        $covered[$id][] = array(
                            'severity' => $sev,
                            'message'  => $msg,
                            'module'   => (string) $module,
                        );
                    }
                }
            }
            $total = count($controls);
            $cov   = count($covered);
            $summary[$norm] = array(
                'assessable'   => $controls,
                'covered'      => $covered,
                'pass_count'   => max(0, $total - $cov),
                'total_count'  => $total,
                'coverage_pct' => $total > 0 ? (int) round(($total - $cov) * 100 / $total) : 100,
            );
        }

        return array(
            'findings' => array(),
            'counts'   => array('high' => 0, 'medium' => 0, 'low' => 0),
            'summary'  => $summary,
        );
    }

    /**
     * Public disclaimer text for use in the compliance UI.
     *
     * @return string
     */
    public static function disclaimer_text() {
        $parts = array(
            __('Indicative mapping based on technical signals.', 'nubivio-healthcare-security-hardening'),
            __('Not evidence of compliance and not a substitute for an audit by a certified party.', 'nubivio-healthcare-security-hardening'),
            __('NEN 7510 and ISO 27001 controls are only referenced by ID and short label; normative text is copyrighted and is not included.', 'nubivio-healthcare-security-hardening'),
        );
        return implode(' ', $parts);
    }

    /**
     * Map a finding to zero or more control IDs.
     *
     * The plugin's existing findings only carry severity + message, so this
     * classifier reads the module name plus a set of case-insensitive
     * substrings in the message text. The intent is conservative: prefer
     * missing a control mapping over asserting an unrelated one.
     *
     * @param string $module  Frameworks key (dns, csp, cookies, ...).
     * @param string $message Message text of the finding.
     * @return array<int,string>
     */
    public function classify($module, $message) {
        $module = strtolower($module);
        $msg    = strtolower($message);
        $ids    = array();

        if ($module === 'dns') {
            if (self::has_any($msg, array('spf', 'dkim', 'dmarc', 'mta-sts', 'tls-rpt', 'bimi'))) {
                $ids[] = 'A.5.14';
                $ids[] = 'A.8.21';
            }
            if (self::has_any($msg, array('caa', 'dnssec'))) {
                $ids[] = 'A.8.24';
            }
            if (self::has_any($msg, array('ns record', 'soa', 'nameserver'))) {
                $ids[] = 'A.8.20';
            }
        }
        if ($module === 'tls') {
            $ids[] = 'A.8.24';
            $ids[] = 'A.5.30';
        }
        if ($module === 'hsts') {
            $ids[] = 'A.8.24';
            $ids[] = 'A.8.21';
        }
        if ($module === 'csp') {
            $ids[] = 'A.8.26';
            $ids[] = 'A.8.9';
        }
        if ($module === 'cookies') {
            $ids[] = 'A.5.34';
            $ids[] = 'A.8.26';
        }
        if ($module === 'access') {
            $ids[] = 'A.8.5';
        }
        if ($module === 'integrity' || $module === 'cra') {
            $ids[] = 'A.8.8';
        }
        if ($module === 'docs' || $module === 'gdpr' || $module === 'nis2') {
            $ids[] = 'A.8.9';
            if (self::has_any($msg, array('cookie', 'tracker', 'consent'))) {
                $ids[] = 'A.5.34';
            }
        }
        if (self::has_any($msg, array('certificate', 'expires'))) {
            $ids[] = 'A.5.30';
        }
        if (self::has_any($msg, array('tls', 'https'))) {
            $ids[] = 'A.8.24';
        }

        return array_values(array_unique($ids));
    }

    private static function has_any($haystack, $needles) {
        foreach ((array) $needles as $n) {
            if ($n !== '' && strpos($haystack, (string) $n) !== false) {
                return true;
            }
        }
        return false;
    }
}
