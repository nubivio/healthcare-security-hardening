<?php
/**
 * Certificate Transparency check via crt.sh (v2.6.0, opt-in).
 *
 * Lists the certificate issuers that Certificate Transparency logs show
 * for the site's registered domain and its subdomains, and compares them
 * with a stored baseline and with the CAA record from the DNS module.
 *
 * External service (only when the `ct_enabled` option is on, only from the
 * manual scan or the existing scan cron, never on a page load): crt.sh,
 * operated by Sectigo. Two GET requests, ?q=%25.{domain} and ?q={domain},
 * with output=json and exclude=expired. Only the domain name is sent.
 * Timeout 10 s, 2 MB response limit, at most 500 entries parsed, cached
 * 24 hours. crt.sh is often slow: errors give "CT source temporarily not
 * available" and never a finding.
 *
 * Baseline: the first successful run stores the issuer set (issuer O, or CN
 * when there is no O) in the plugin options. A certificate from an issuer
 * outside that set, issued in the last 30 days, is a medium finding. The
 * admin can mark the current issuers as known.
 *
 * CAA cross-check: issuer organisations are mapped to CAA identifiers with
 * the list SSLMate publishes for its CAA generator
 * (https://sslmate.com/caa/). Unknown issuers are not compared.
 *
 * Subdomain names (max 50) are kept in the summary for a later release; no
 * DNS or HTTP request is made to them.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Ct {

    const ENDPOINT      = 'https://crt.sh/';
    const TIMEOUT       = 10;
    const MAX_BYTES     = 2097152;
    const MAX_ENTRIES   = 500;
    const MAX_SUBS      = 50;
    const CACHE_TTL     = 86400;
    const NEW_DAYS      = 30;
    const MARK_ACTION   = 'nubivio_hsh_ct_mark_known';

    /** @var Nubivio_HSH|null */
    private $core;

    /**
     * @param Nubivio_HSH|null $core Plugin core.
     */
    public function __construct($core = null) {
        $this->core = $core;
    }

    /**
     * Wire the "mark issuers as known" action.
     *
     * @param Nubivio_HSH $core Plugin core.
     * @return void
     */
    public static function register_hooks($core) {
        $self = new self($core);
        add_action('admin_post_' . self::MARK_ACTION, array($self, 'handle_mark_known'));
    }

    /**
     * Whether the module is switched on.
     *
     * @return bool
     */
    public static function enabled() {
        $o = get_option(Nubivio_HSH::OPTION, array());
        return is_array($o) && !empty($o['ct_enabled']);
    }

    /**
     * Cache key for a domain.
     *
     * @param string $domain Registered domain.
     * @return string
     */
    public static function cache_key($domain) {
        return 'nubivio_hsh_ct_' . md5((string) $domain);
    }

    /**
     * CAA identifiers per issuer organisation, from SSLMate's CAA issuer list.
     * Keys are matched case-insensitively against the issuer O value.
     *
     * @return array<string,array<int,string>>
     */
    public static function caa_map() {
        $map = array(
            "let's encrypt"         => array('letsencrypt.org'),
            'google trust services' => array('pki.goog'),
            'digicert'              => array(
                'digicert.com',
                'www.digicert.com',
                'symantec.com',
                'thawte.com',
                'geotrust.com',
                'rapidssl.com',
            ),
            'geotrust'              => array('digicert.com', 'geotrust.com'),
            'thawte'                => array('digicert.com', 'thawte.com'),
            'rapidssl'              => array('digicert.com', 'rapidssl.com'),
            'sectigo'               => array(
                'sectigo.com',
                'comodo.com',
                'comodoca.com',
                'usertrust.com',
                'trust-provider.com',
            ),
            'comodo'                => array('sectigo.com', 'comodo.com', 'comodoca.com'),
            'globalsign'            => array('globalsign.com'),
            'amazon'                => array('amazon.com', 'amazontrust.com', 'awstrust.com', 'amazonaws.com', 'aws.amazon.com'),
            'entrust'               => array('entrust.net', 'affirmtrust.com'),
            'godaddy'               => array('godaddy.com', 'starfieldtech.com'),
            'starfield'             => array('godaddy.com', 'starfieldtech.com'),
            'buypass'               => array('buypass.com', 'buypass.no'),
            'ssl corporation'       => array('ssl.com'),
            'actalis'               => array('actalis.it'),
            'certum'                => array('certum.pl', 'certum.eu'),
            'asseco'                => array('certum.pl', 'certum.eu'),
            'hellenic academic'     => array('harica.gr'),
            'harica'                => array('harica.gr'),
        );
        $filtered = apply_filters('nubivio_hsh_ct_caa_map', $map);
        return is_array($filtered) ? $filtered : $map;
    }

    /**
     * Run the check.
     *
     * @param array $caa_records CAA records from the DNS module summary.
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function run($caa_records = array()) {
        $domain  = class_exists('Nubivio_HSH_Rdap') ? Nubivio_HSH_Rdap::site_domain() : '';
        $summary = array(
            'enabled'   => self::enabled(),
            'domain'    => $domain,
            'available' => false,
        );
        if (!$summary['enabled'] || $domain === '' || strpos($domain, '.') === false) {
            return $this->evaluate($summary, $caa_records);
        }
        $key    = self::cache_key($domain);
        $cached = get_transient($key);
        if (is_array($cached) && isset($cached['domain'])) {
            $cached['enabled'] = true;
            return $this->evaluate($cached, $caa_records);
        }
        $summary = array_merge($summary, $this->collect($domain));
        set_transient($key, $summary, $summary['available'] ? self::CACHE_TTL : HOUR_IN_SECONDS);
        return $this->evaluate($summary, $caa_records);
    }

    /**
     * Query crt.sh and reduce the entries to issuers and subdomain names.
     *
     * @param string $domain Registered domain.
     * @return array<string,mixed>
     */
    private function collect($domain) {
        $out = array(
            'domain'     => $domain,
            'available'  => false,
            'issuers'    => array(),
            'subdomains' => array(),
            'entries'    => 0,
            'truncated'  => false,
            'checked_at' => time(),
        );
        $rows = array();
        $ok   = 0;
        foreach (array('%.' . $domain, $domain) as $query) {
            $url    = self::ENDPOINT . '?q=' . rawurlencode($query) . '&output=json&exclude=expired';
            $result = $this->fetch($url);
            if ($result === null) {
                // Both answers are needed for a complete issuer set; a half answer is treated as unavailable.
                return $out;
            }
            $ok++;
            foreach ($result['rows'] as $row) {
                $id = isset($row['id']) ? (string) $row['id'] : md5(wp_json_encode($row));
                if (!isset($rows[$id])) {
                    $rows[$id] = $row;
                }
            }
            if ($result['truncated']) {
                $out['truncated'] = true;
            }
        }
        $out['available'] = $ok === 2;
        if (count($rows) > self::MAX_ENTRIES) {
            $rows             = array_slice($rows, 0, self::MAX_ENTRIES, true);
            $out['truncated'] = true;
        }
        $out['entries'] = count($rows);

        $subs = array();
        foreach ($rows as $row) {
            $issuer = self::issuer_key(isset($row['issuer_name']) ? (string) $row['issuer_name'] : '');
            if ($issuer === '') {
                continue;
            }
            $from  = isset($row['not_before']) ? (int) strtotime((string) $row['not_before'] . ' UTC') : 0;
            $until = isset($row['not_after']) ? (int) strtotime((string) $row['not_after'] . ' UTC') : 0;
            if (!isset($out['issuers'][$issuer])) {
                $out['issuers'][$issuer] = array('count' => 0, 'latest' => 0, 'valid' => false);
            }
            $out['issuers'][$issuer]['count']++;
            $out['issuers'][$issuer]['latest'] = max($out['issuers'][$issuer]['latest'], $from);
            if ($until > time()) {
                $out['issuers'][$issuer]['valid'] = true;
            }
            $names = isset($row['name_value']) ? preg_split('/\s+/', strtolower((string) $row['name_value'])) : array();
            foreach ((array) $names as $name) {
                $name = preg_replace('/^\*\./', '', trim($name));
                if ($name === '' || $name === $domain || count($subs) >= self::MAX_SUBS) {
                    continue;
                }
                if (substr($name, -strlen('.' . $domain)) === '.' . $domain && preg_match('/^[a-z0-9.-]+$/', $name)) {
                    $subs[$name] = true;
                }
            }
        }
        ksort($subs);
        $out['subdomains'] = array_keys($subs);
        return $out;
    }

    /**
     * One crt.sh request. A body cut off at the size limit is repaired to
     * the last complete entry.
     *
     * @param string $url crt.sh URL.
     * @return array{rows:array,truncated:bool}|null Null on error or timeout.
     */
    private function fetch($url) {
        $res = wp_remote_get(
            $url,
            array(
                'timeout'             => self::TIMEOUT,
                'redirection'         => 0,
                'limit_response_size' => self::MAX_BYTES,
                'headers'             => array('Accept' => 'application/json'),
            )
        );
        if (is_wp_error($res) || (int) wp_remote_retrieve_response_code($res) !== 200) {
            return null;
        }
        $body = trim((string) wp_remote_retrieve_body($res));
        // crt.sh answers with an empty body when no certificate is logged.
        if ($body === '') {
            return array('rows' => array(), 'truncated' => false);
        }
        $rows = json_decode($body, true);
        if (is_array($rows)) {
            return array('rows' => $rows, 'truncated' => false);
        }
        $cut = strrpos($body, '},');
        if (strpos($body, '[') === 0 && $cut !== false) {
            $rows = json_decode(substr($body, 0, $cut + 1) . ']', true);
            if (is_array($rows)) {
                return array('rows' => $rows, 'truncated' => true);
            }
        }
        return null;
    }

    /**
     * Issuer O from an issuer DN such as "C=US, O=Let's Encrypt, CN=R11",
     * or CN when there is no O.
     *
     * @param string $dn Issuer distinguished name.
     * @return string
     */
    public static function issuer_key($dn) {
        $attrs = array();
        $re    = '/(?:^|,\s*)(C|ST|L|O|OU|CN|emailAddress)=((?:[^,]|,(?!\s*(?:C|ST|L|O|OU|CN|emailAddress)=))*)/';
        if (preg_match_all($re, (string) $dn, $m, PREG_SET_ORDER)) {
            foreach ($m as $part) {
                if (!isset($attrs[$part[1]])) {
                    $attrs[$part[1]] = trim(trim($part[2]), '"');
                }
            }
        }
        if (!empty($attrs['O'])) {
            return sanitize_text_field($attrs['O']);
        }
        return !empty($attrs['CN']) ? sanitize_text_field($attrs['CN']) : '';
    }

    /**
     * CAA identifiers for an issuer, or null when the issuer is not in the map.
     *
     * @param string $issuer Issuer key.
     * @return array<int,string>|null
     */
    public static function caa_ids_for($issuer) {
        $issuer = strtolower((string) $issuer);
        foreach (self::caa_map() as $needle => $ids) {
            if ($needle !== '' && strpos($issuer, (string) $needle) !== false) {
                return array_map('strtolower', (array) $ids);
            }
        }
        return null;
    }

    /**
     * Issuer domains allowed by CAA "issue" and "issuewild" records.
     *
     * @param array $records CAA records as returned by dns_get_record().
     * @return array<int,string>
     */
    public static function caa_allowed($records) {
        $allowed = array();
        foreach ((array) $records as $record) {
            $tag = isset($record['tag']) ? strtolower((string) $record['tag']) : '';
            if ($tag !== 'issue' && $tag !== 'issuewild') {
                continue;
            }
            $value = isset($record['value']) ? (string) $record['value'] : '';
            $value = strtolower(trim(strtok($value, ';')));
            if ($value !== '') {
                $allowed[] = $value;
            }
        }
        return array_values(array_unique($allowed));
    }

    /**
     * Compare with the baseline and CAA. The first successful run stores the
     * baseline.
     *
     * @param array $summary     Summary from collect().
     * @param array $caa_records CAA records from the DNS module.
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function evaluate($summary, $caa_records = array()) {
        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);
        if (empty($summary['enabled']) || empty($summary['available'])) {
            return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
        }

        $o     = get_option(Nubivio_HSH::OPTION, array());
        $o     = is_array($o) ? $o : array();
        $known = isset($o['ct_known_issuers']) && is_array($o['ct_known_issuers']) ? $o['ct_known_issuers'] : array();
        if (empty($o['ct_baseline_at']) && !empty($summary['issuers'])) {
            $known                 = array_keys($summary['issuers']);
            $o['ct_known_issuers'] = $known;
            $o['ct_baseline_at']   = time();
            update_option(Nubivio_HSH::OPTION, $o);
        }
        $summary['baseline_at'] = isset($o['ct_baseline_at']) ? (int) $o['ct_baseline_at'] : 0;
        $summary['known']       = array_values($known);

        $cutoff  = time() - self::NEW_DAYS * DAY_IN_SECONDS;
        $allowed = self::caa_allowed($caa_records);
        $summary['caa_allowed'] = $allowed;

        foreach ((array) $summary['issuers'] as $issuer => $info) {
            if (!in_array($issuer, $known, true) && (int) $info['latest'] >= $cutoff) {
                $this->add(
                    $findings,
                    $counts,
                    'medium',
                    sprintf(
                        /* translators: 1: certificate issuer, 2: domain name. */
                        __('Unknown certificate issuer %1$s for %2$s in the last 30 days; check that this is correct.', 'nubivio-healthcare-security-hardening'),
                        $issuer,
                        $summary['domain']
                    )
                );
            }
            if (!$allowed || empty($info['valid'])) {
                continue;
            }
            $ids = self::caa_ids_for($issuer);
            if ($ids === null || array_intersect($ids, $allowed)) {
                continue;
            }
            $this->add(
                $findings,
                $counts,
                'medium',
                sprintf(
                    /* translators: 1: certificate issuer, 2: CAA issuer list. */
                    __('A valid certificate from %1$s is logged, but the CAA record only allows %2$s. Check the certificate or update CAA.', 'nubivio-healthcare-security-hardening'),
                    $issuer,
                    implode(', ', $allowed)
                )
            );
        }

        return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
    }

    /**
     * Mark the issuers in the cached CT summary as known.
     *
     * @return void
     */
    public function handle_mark_known() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to perform this action.', 'nubivio-healthcare-security-hardening'));
        }
        $nonce = isset($_POST['_wpnonce']) ? sanitize_text_field(wp_unslash($_POST['_wpnonce'])) : '';
        if (!$nonce || !wp_verify_nonce($nonce, self::MARK_ACTION)) {
            wp_die(esc_html__('Security check failed.', 'nubivio-healthcare-security-hardening'));
        }
        $domain = class_exists('Nubivio_HSH_Rdap') ? Nubivio_HSH_Rdap::site_domain() : '';
        $cached = get_transient(self::cache_key($domain));
        $o      = get_option(Nubivio_HSH::OPTION, array());
        $o      = is_array($o) ? $o : array();
        if (is_array($cached) && !empty($cached['issuers'])) {
            $known = isset($o['ct_known_issuers']) && is_array($o['ct_known_issuers']) ? $o['ct_known_issuers'] : array();
            $known = array_merge($known, array_keys($cached['issuers']));

            $o['ct_known_issuers'] = array_values(array_unique($known));
            $o['ct_baseline_at']   = time();
            update_option(Nubivio_HSH::OPTION, $o);
        }
        wp_safe_redirect(add_query_arg(array('page' => Nubivio_HSH::SLUG, 'tab' => 'compliance'), admin_url('options-general.php')));
        exit;
    }

    /**
     * Row for the plugin's own Site health card.
     *
     * @param array $result Result of run().
     * @return array{label:string,status:string,detail:string}|null Null when the module is off.
     */
    public static function health_row($result) {
        $summary = isset($result['summary']) ? (array) $result['summary'] : array();
        if (empty($summary['enabled'])) {
            return null;
        }
        $label = __('Certificate Transparency (crt.sh)', 'nubivio-healthcare-security-hardening');
        if (empty($summary['available'])) {
            return array(
                'label'  => $label,
                'status' => 'warn',
                'detail' => __('CT source temporarily not available; the scan continued without it.', 'nubivio-healthcare-security-hardening'),
            );
        }
        $medium = isset($result['counts']['medium']) ? (int) $result['counts']['medium'] : 0;
        return array(
            'label'  => $label,
            'status' => $medium > 0 ? 'warn' : 'pass',
            'detail' => $medium > 0
                ? __('Certificates from unexpected issuers were found; review them on the dashboard.', 'nubivio-healthcare-security-hardening')
                : __('No unexpected certificate issuers found in the CT logs.', 'nubivio-healthcare-security-hardening'),
        );
    }

    /**
     * Append a finding and bump its counter.
     *
     * @param array  $findings Findings list.
     * @param array  $counts   Counters.
     * @param string $severity high, medium or low.
     * @param string $message  Message.
     * @return void
     */
    private function add(&$findings, &$counts, $severity, $message) {
        $findings[] = array(
            'severity' => $severity,
            'message'  => $message,
            'controls' => array('A.8.24'),
        );
        $counts[$severity]++;
    }
}
