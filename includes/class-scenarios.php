<?php
/**
 * v2.6.0 Risk scenarios. Combines signals that other modules already
 * collected into a short list of attack scenarios, each with the
 * underlying signals and a first step.
 *
 * This module adds no findings and does not change the score or the
 * counts. It makes no network requests: it only reads the scanner
 * results, the plugin options and transients that other modules cached.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Scenarios {

    /** Certificate days left below which scenario 6 applies. */
    const CERT_DAYS = 30;

    /** Domain registration days left below which scenario 6 applies. */
    const DOMAIN_DAYS = 60;

    /** @var Nubivio_HSH */
    private $core;

    /**
     * @param Nubivio_HSH $core Plugin core.
     */
    public function __construct($core) {
        $this->core = $core;
    }

    /**
     * Fixed caveat shown above the scenarios.
     *
     * @return string
     */
    public static function caveat() {
        return __(
            'Scenarios based on signals, not confirmed vulnerabilities or intrusions.',
            'nubivio-healthcare-security-hardening'
        );
    }

    /**
     * Build the scenarios from the scanner results.
     *
     * @param array $results Framework results assembled by the scanner.
     * @return array{findings:array,counts:array,summary:array}
     */
    public function run($results) {
        $results   = is_array($results) ? $results : array();
        $scenarios = array();
        $builders  = array(
            'server_takeover',
            'supply_chain',
            'mail_spoofing',
            'compromise',
            'account_takeover',
            'availability',
            'targeted_attack',
        );
        foreach ($builders as $priority => $method) {
            $scenario = $this->$method($results);
            if (!$scenario) {
                continue;
            }
            $scenario['id']       = $method;
            $scenario['priority'] = $priority + 1;
            $scenarios[]          = $scenario;
        }

        return array(
            'findings' => array(),
            'counts'   => array('high' => 0, 'medium' => 0, 'low' => 0),
            'summary'  => array(
                'scenarios' => $scenarios,
                'caveat'    => self::caveat(),
            ),
        );
    }

    /**
     * Scenario 1: PHP2Shell plus a reachable upload path or XML-RPC.
     *
     * @param array $r Results.
     * @return array|null
     */
    private function server_takeover($r) {
        $sum = isset($r['php_runtime']['summary']) ? (array) $r['php_runtime']['summary'] : array();
        if (!isset($sum['status']) || $sum['status'] !== 'affected') {
            return null;
        }

        $signals  = array();
        $fixed_in = '';
        foreach ((array) (isset($sum['advisories']) ? $sum['advisories'] : array()) as $adv) {
            if (isset($adv['status']) && $adv['status'] === 'affected') {
                $signals[] = (string) $adv['message'];
                $fixed_in  = isset($adv['fixed_in']) ? (string) $adv['fixed_in'] : '';
            }
        }

        $entry = array();
        if ($this->xmlrpc_reachable($r)) {
            $entry[] = __('XML-RPC is enabled.', 'nubivio-healthcare-security-hardening');
        }
        if ($this->homepage_has_file_input()) {
            $entry[] = __('The homepage contains a file upload field.', 'nubivio-healthcare-security-hardening');
        }
        $plugins = $this->active_upload_form_plugins();
        if ($plugins) {
            $entry[] = sprintf(
                /* translators: %s: comma-separated plugin slugs. */
                __(
                    'Active form plugin with file upload support: %s (upload fields not verified).',
                    'nubivio-healthcare-security-hardening'
                ),
                implode(', ', $plugins)
            );
        }
        if (!$entry) {
            return null;
        }

        if ($fixed_in !== '') {
            $step = sprintf(
                /* translators: %s: first fixed PHP version. */
                __(
                    'Ask your hosting provider today to update PHP to %s or later. Until then set session.upload_progress.enabled=0 and disable XML-RPC if you do not use it.',
                    'nubivio-healthcare-security-hardening'
                ),
                $fixed_in
            );
        } else {
            $step = __(
                'Ask your hosting provider today to update PHP. Until then set session.upload_progress.enabled=0 and disable XML-RPC if you do not use it.',
                'nubivio-healthcare-security-hardening'
            );
        }

        return array(
            'severity'   => 'high',
            'title'      => __(
                'Remote takeover of the server without logging in is possible',
                'nubivio-healthcare-security-hardening'
            ),
            'signals'    => array_merge($signals, $entry),
            'first_step' => $step,
        );
    }

    /**
     * Scenario 2: external scripts without SRI and no enforcing CSP.
     *
     * @param array $r Results.
     * @return array|null
     */
    private function supply_chain($r) {
        $scripts = $this->external_scripts_without_sri();
        if (!$scripts || $this->csp_enforced()) {
            return null;
        }

        $hosts = array();
        foreach ($scripts as $url) {
            $host = wp_parse_url($url, PHP_URL_HOST);
            if ($host && !in_array($host, $hosts, true)) {
                $hosts[] = $host;
            }
        }

        return array(
            'severity'   => 'medium',
            'title'      => __('Supply-chain risk via external scripts', 'nubivio-healthcare-security-hardening'),
            'signals'    => array(
                sprintf(
                    /* translators: 1: number of scripts, 2: comma-separated host names. */
                    _n(
                        '%1$d external script loads without Subresource Integrity (%2$s).',
                        '%1$d external scripts load without Subresource Integrity (%2$s).',
                        count($scripts),
                        'nubivio-healthcare-security-hardening'
                    ),
                    count($scripts),
                    implode(', ', array_slice($hosts, 0, 5))
                ),
                __('No enforcing Content-Security-Policy is active.', 'nubivio-healthcare-security-hardening'),
            ),
            'first_step' => __(
                'Add integrity attributes to the external scripts or host them yourself, then move the CSP from Report-Only to enforcing.',
                'nubivio-healthcare-security-hardening'
            ),
        );
    }

    /**
     * Scenario 3: missing SPF or DMARC, or SPF softfail without DMARC reject.
     *
     * @param array $r Results.
     * @return array|null
     */
    private function mail_spoofing($r) {
        $sum = isset($r['dns']['summary']) ? (array) $r['dns']['summary'] : array();
        // DNS lookups disabled or no host: the records were never read.
        if (!isset($sum['spf']['records']) || !isset($sum['dmarc']['records'])) {
            return null;
        }

        $spf      = (array) $sum['spf']['records'];
        $dmarc    = (array) $sum['dmarc']['records'];
        $softfail = isset($sum['spf']['policy']) && $sum['spf']['policy'] === 'softfail';
        $reject   = (bool) preg_match('/\bp\s*=\s*reject\b/i', implode(';', $dmarc));

        $signals = array();
        if (!$spf) {
            $signals[] = __('No SPF record found.', 'nubivio-healthcare-security-hardening');
        }
        if (!$dmarc) {
            $signals[] = __('No DMARC record found.', 'nubivio-healthcare-security-hardening');
        }
        if ($spf && $dmarc && $softfail && !$reject) {
            $signals[] = __('SPF ends in ~all (softfail).', 'nubivio-healthcare-security-hardening');
            $signals[] = __('DMARC does not use p=reject.', 'nubivio-healthcare-security-hardening');
        }
        if (!$signals) {
            return null;
        }

        return array(
            'severity'   => 'medium',
            'title'      => __('Phishing and spoofing in your name', 'nubivio-healthcare-security-hardening'),
            'signals'    => $signals,
            'first_step' => __(
                'Publish a DMARC record (start with p=none and rua reports, then move to p=reject) and end SPF with -all.',
                'nubivio-healthcare-security-hardening'
            ),
        );
    }

    /**
     * Scenario 4: recently created administrator plus core checksum deviation.
     *
     * @param array $r Results.
     * @return array|null
     */
    private function compromise($r) {
        $recent   = $this->pick($r, array('access', 'report', 'recent_admins'));
        $modified = $this->pick($r, array('integrity', 'summary', 'modified'));
        if (!$recent || !$modified) {
            return null;
        }

        return array(
            'severity'   => 'high',
            'title'      => __('Possible compromise', 'nubivio-healthcare-security-hardening'),
            'signals'    => array(
                sprintf(
                    /* translators: %s: comma-separated user logins. */
                    __('Administrator created in the last 30 days: %s.', 'nubivio-healthcare-security-hardening'),
                    implode(', ', $recent)
                ),
                sprintf(
                    /* translators: %d: number of files. */
                    _n(
                        '%d WordPress core file differs from the official checksums.',
                        '%d WordPress core files differ from the official checksums.',
                        count($modified),
                        'nubivio-healthcare-security-hardening'
                    ),
                    count($modified)
                ),
            ),
            'first_step' => __(
                'Check who created the administrator account. If nobody knows, reinstall WordPress core via Dashboard, Updates and change all administrator passwords.',
                'nubivio-healthcare-security-hardening'
            ),
        );
    }

    /**
     * Scenario 5: application password on an administrator and no 2FA signal.
     *
     * @param array $r Results.
     * @return array|null
     */
    private function account_takeover($r) {
        // The access module only collects application passwords of administrator accounts.
        $pws = $this->pick($r, array('access', 'report', 'app_passwords'));
        if (!$pws || !$this->mfa_missing($r)) {
            return null;
        }

        $logins = array();
        foreach ($pws as $pw) {
            if (isset($pw['login']) && !in_array($pw['login'], $logins, true)) {
                $logins[] = (string) $pw['login'];
            }
        }

        return array(
            'severity'   => 'medium',
            'title'      => __(
                'Account takeover path via application passwords',
                'nubivio-healthcare-security-hardening'
            ),
            'signals'    => array(
                sprintf(
                    /* translators: 1: number of application passwords, 2: comma-separated user logins. */
                    _n(
                        '%1$d application password on administrator accounts (%2$s).',
                        '%1$d application passwords on administrator accounts (%2$s).',
                        count($pws),
                        'nubivio-healthcare-security-hardening'
                    ),
                    count($pws),
                    implode(', ', $logins)
                ),
                __('No two-factor authentication plugin detected.', 'nubivio-healthcare-security-hardening'),
            ),
            'first_step' => __(
                'Revoke application passwords you do not use (Users, Profile) and turn on two-factor authentication for every administrator.',
                'nubivio-healthcare-security-hardening'
            ),
        );
    }

    /**
     * Scenario 6: certificate or domain registration expires soon.
     *
     * @param array $r Results.
     * @return array|null
     */
    private function availability($r) {
        $signals = array();
        $tls     = isset($r['tls']['summary']) ? (array) $r['tls']['summary'] : array();
        $tls_ok  = !empty($tls['available']) && isset($tls['days_remaining']);
        if ($tls_ok && (int) $tls['days_remaining'] < self::CERT_DAYS) {
            $signals[] = sprintf(
                /* translators: %d: days. */
                __('The TLS certificate expires in %d days.', 'nubivio-healthcare-security-hardening'),
                (int) $tls['days_remaining']
            );
        }
        // Domain expiry is only known when the opt-in RDAP check ran.
        $rdap = isset($r['rdap']['summary']) ? (array) $r['rdap']['summary'] : array();
        if (!empty($rdap['enabled']) && !empty($rdap['available']) && isset($rdap['expires_days'])) {
            if ((int) $rdap['expires_days'] < self::DOMAIN_DAYS) {
                $signals[] = sprintf(
                    /* translators: %d: days. */
                    __('The domain registration expires in %d days.', 'nubivio-healthcare-security-hardening'),
                    (int) $rdap['expires_days']
                );
            }
        }
        if (!$signals) {
            return null;
        }

        return array(
            'severity'   => 'medium',
            'title'      => __(
                'Availability risk: certificate or domain expires soon',
                'nubivio-healthcare-security-hardening'
            ),
            'signals'    => $signals,
            'first_step' => __(
                'Check automatic renewal with your hosting provider or registrar and renew before the expiry date.',
                'nubivio-healthcare-security-hardening'
            ),
        );
    }

    /**
     * Scenario 7: exposed .git, .env or config backup plus user enumeration.
     *
     * @param array $r Results.
     * @return array|null
     */
    private function targeted_attack($r) {
        $checks = isset($r['exposure']['summary']['checks']) ? (array) $r['exposure']['summary']['checks'] : array();
        $files  = array();
        $enum   = array();
        foreach ($checks as $c) {
            if (empty($c['hit']) || !isset($c['id'])) {
                continue;
            }
            if (in_array($c['id'], array('git', 'env', 'config_backup'), true)) {
                $files[] = (string) $c['path'];
            }
            if (in_array($c['id'], array('rest_users', 'author_enum'), true)) {
                $enum[] = (string) $c['path'];
            }
        }
        if (!$files || !$enum) {
            return null;
        }

        return array(
            'severity'   => 'high',
            'title'      => __('Targeted attack more likely', 'nubivio-healthcare-security-hardening'),
            'signals'    => array(
                sprintf(
                    /* translators: %s: comma-separated paths. */
                    __('Publicly reachable: %s.', 'nubivio-healthcare-security-hardening'),
                    implode(', ', $files)
                ),
                sprintf(
                    /* translators: %s: comma-separated paths. */
                    __('Usernames can be listed via %s.', 'nubivio-healthcare-security-hardening'),
                    implode(', ', $enum)
                ),
            ),
            'first_step' => __(
                'Block access to the exposed files on the web server, change any secrets they contain, then stop user enumeration.',
                'nubivio-healthcare-security-hardening'
            ),
        );
    }

    /* Signal helpers. None of them makes a network request. */

    /**
     * Nested array value from the results, or an empty array.
     *
     * @param array    $r    Results.
     * @param string[] $keys Path of keys.
     * @return array
     */
    private function pick($r, $keys) {
        $node = $r;
        foreach ($keys as $key) {
            if (!is_array($node) || !isset($node[$key])) {
                return array();
            }
            $node = $node[$key];
        }
        return (array) $node;
    }

    /**
     * XML-RPC reachable: enabled through the filter, or the exposure probe found it.
     *
     * @param array $r Results.
     * @return bool
     */
    private function xmlrpc_reachable($r) {
        $checks = isset($r['exposure']['summary']['checks']) ? (array) $r['exposure']['summary']['checks'] : array();
        foreach ($checks as $c) {
            if (isset($c['id']) && $c['id'] === 'xmlrpc' && !empty($c['hit'])) {
                return true;
            }
        }
        return (bool) apply_filters('xmlrpc_enabled', true);
    }

    /**
     * Homepage HTML as cached by the CSP inventory, or an empty string.
     *
     * @return string
     */
    private function cached_homepage_html() {
        $html = get_transient('nubivio_hsh_csp_html_' . md5((string) home_url('/')));
        return is_string($html) ? $html : '';
    }

    /**
     * Whether the cached homepage HTML has an <input type="file">.
     *
     * @return bool
     */
    private function homepage_has_file_input() {
        $html = $this->cached_homepage_html();
        return $html !== '' && (bool) preg_match('/<input\b[^>]*\btype\s*=\s*["\']?file\b/i', $html);
    }

    /**
     * Active form plugins that support file upload fields.
     *
     * @return string[]
     */
    private function active_upload_form_plugins() {
        /**
         * Plugin slugs whose forms can accept file uploads.
         *
         * @param string[] $slugs Plugin directory names.
         */
        $slugs = (array) apply_filters('nubivio_hsh_scenario_upload_plugins', array(
            'gravityforms',
            'contact-form-7',
            'wpforms',
            'wpforms-lite',
            'ninja-forms',
            'formidable',
            'forminator',
            'fluentform',
        ));
        return $this->active_plugins_from($slugs);
    }

    /**
     * Active plugins whose directory name is in the list.
     *
     * @param string[] $slugs Plugin directory names.
     * @return string[]
     */
    private function active_plugins_from($slugs) {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $out = array();
        foreach (array_keys(get_plugins()) as $file) {
            if (!is_plugin_active($file)) {
                continue;
            }
            $slug = strpos($file, '/') !== false ? strstr($file, '/', true) : basename($file, '.php');
            if (in_array($slug, $slugs, true) && !in_array($slug, $out, true)) {
                $out[] = $slug;
            }
        }
        return $out;
    }

    /**
     * External <script src> tags on the cached homepage without an integrity attribute.
     *
     * @return string[]
     */
    private function external_scripts_without_sri() {
        $html = $this->cached_homepage_html();
        if ($html === '' || !preg_match_all('/<script\b[^>]*>/i', $html, $m)) {
            return array();
        }
        $site = strtolower((string) wp_parse_url(home_url('/'), PHP_URL_HOST));
        $out  = array();
        foreach ($m[0] as $tag) {
            if (!preg_match('/\bsrc\s*=\s*["\']([^"\']+)["\']/i', $tag, $src)) {
                continue;
            }
            if (preg_match('/\bintegrity\s*=/i', $tag)) {
                continue;
            }
            $url  = strpos($src[1], '//') === 0 ? 'https:' . $src[1] : $src[1];
            $host = strtolower((string) wp_parse_url($url, PHP_URL_HOST));
            if ($host === '' || $host === $site || substr($host, -strlen('.' . $site)) === '.' . $site) {
                continue;
            }
            if (!in_array($url, $out, true)) {
                $out[] = $url;
            }
        }
        return $out;
    }

    /**
     * Whether an enforcing CSP is active: from the plugin options or a cached header probe.
     *
     * @return bool
     */
    private function csp_enforced() {
        $o = $this->core->get_options();
        if (!empty($o['csp_enabled'])) {
            // CSP builder with enforcement switched on.
            if (!empty($o['csp_inventory_at']) && !empty($o['csp_enforce_enabled'])) {
                return true;
            }
            // Manual policy that is not in Report-Only mode.
            if (empty($o['csp_report_only']) && isset($o['csp_policy']) && trim((string) $o['csp_policy']) !== '') {
                return true;
            }
        }
        // A server or CDN may send the header itself; use the last header probe if one is cached.
        $probe = get_transient('nubivio_hsh_headers_probe');
        return is_array($probe) && !empty($probe['present']['content-security-policy']);
    }

    /**
     * True when no 2FA plugin is active, as reported by NIS2 or checked here.
     *
     * @param array $r Results.
     * @return bool
     */
    private function mfa_missing($r) {
        if (isset($r['nis2']['findings'])) {
            foreach ((array) $r['nis2']['findings'] as $f) {
                if (isset($f['signal']) && $f['signal'] === 'mfa') {
                    return true;
                }
            }
            return false;
        }
        // NIS2 scan is off: same plugin list and filter as the NIS2 module.
        $slugs = (array) apply_filters('nubivio_hsh_nis2_mfa_plugins', array(
            'two-factor',
            'wordfence',
            'miniorange-2-factor-authentication',
            'wp-2fa',
            'google-authenticator',
        ));
        return !$this->active_plugins_from($slugs);
    }
}
