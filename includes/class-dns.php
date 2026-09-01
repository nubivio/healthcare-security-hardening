<?php
/**
 * DNS health dashboard.
 *
 * @package Nubivio_HSH
 */
if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Dns {

    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    public function run() {
        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);
        $host     = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        $summary  = array(
            'host'    => $host,
            'spf'     => array(),
            'dmarc'   => array(),
            'dkim'    => array(),
            'caa'     => array(),
            'mta_sts' => array(),
            'dnssec'  => array(),
            'aaaa'    => array(),
            'ns'      => array(),
            'soa'     => array(),
            'tls_rpt' => array(),
            'bimi'    => array(),
            'no_mail' => false,
        );

        if (!function_exists('dns_get_record')) {
            $findings[] = array(
                'severity' => 'warn',
                'message'  => __('DNS lookups are disabled on this server; skipping DNS health check.', 'nubivio-healthcare-security-hardening'),
            );
            return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
        }
        if ($host === '') {
            return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
        }

        // SPF.
        $txt = $this->dns($host, DNS_TXT, 'spf');
        $spf = array();
        foreach ($txt as $r) {
            $value = $this->txt($r);
            if (stripos($value, 'v=spf1') === 0) {
                $spf[] = $value;
            }
        }
        $spf_policy  = '';
        $spf_lookups = 0;
        if (count($spf) === 1) {
            $spf_policy  = $this->spf_policy($spf[0]);
            $spf_lookups = $this->spf_count_lookups($spf[0], $host);
        }
        $summary['spf'] = array(
            'records' => $spf,
            'policy'  => $spf_policy,
            'lookups' => $spf_lookups,
        );
        if (count($spf) === 0) {
            $this->add($findings, $counts, 'medium', __('No SPF record found. Suggested minimal record: `v=spf1 -all` (deny all outbound mail).', 'nubivio-healthcare-security-hardening'));
        } elseif (count($spf) > 1) {
            $this->add($findings, $counts, 'high', __('Multiple SPF records found. RFC 7208 requires exactly one; mail authentication will fail. Merge into a single record.', 'nubivio-healthcare-security-hardening'));
        } else {
            if ($spf_policy === 'softfail') {
                $this->add(
                    $findings,
                    $counts,
                    'low',
                    __('SPF uses softfail (~all); consider tightening to -all once monitoring confirms no legitimate sender is missed.', 'nubivio-healthcare-security-hardening')
                );
            } elseif ($spf_policy === 'neutral') {
                $this->add(
                    $findings,
                    $counts,
                    'medium',
                    __('SPF policy is neutral (?all); receivers will not treat unauthorised senders as spoofed. Move to ~all or -all.', 'nubivio-healthcare-security-hardening')
                );
            } elseif ($spf_policy === 'pass' || $spf_policy === 'none') {
                $this->add(
                    $findings,
                    $counts,
                    'high',
                    __('SPF ends with +all or is missing an all-mechanism; the domain authorises every sender. Set -all after review.', 'nubivio-healthcare-security-hardening')
                );
            }
            if ($spf_lookups > 10) {
                $this->add(
                    $findings,
                    $counts,
                    'high',
                    sprintf(
                        /* translators: %d: DNS lookup count. */
                        __('SPF exceeds the RFC 7208 limit of 10 DNS lookups (counted %d); SPF will fail with permerror. Consolidate includes.', 'nubivio-healthcare-security-hardening'),
                        $spf_lookups
                    )
                );
            }
        }

        // DMARC.
        $dmarc_txt = $this->dns('_dmarc.' . $host, DNS_TXT, 'dmarc');
        $dmarc     = array();
        foreach ($dmarc_txt as $r) {
            $v = $this->txt($r);
            if (stripos($v, 'v=DMARC1') === 0) {
                $dmarc[] = $v;
            }
        }
        $summary['dmarc'] = array('records' => $dmarc);
        if (!$dmarc) {
            $this->add(
                $findings,
                $counts,
                'medium',
                sprintf(
                    __('No DMARC record found. Suggested template: _dmarc.%1$s. IN TXT "v=DMARC1; p=none; rua=mailto:security@%1$s; ruf=mailto:security@%1$s; fo=1"', 'nubivio-healthcare-security-hardening'),
                    $host
                )
            );
        } elseif (preg_match('/\bp\s*=\s*none\b/i', implode(';', $dmarc))) {
            $this->add($findings, $counts, 'low', __('DMARC policy is `none` (monitor only). Consider strengthening to `quarantine` or `reject` after reviewing reports.', 'nubivio-healthcare-security-hardening'));
        }

        // DKIM.
        $selectors = array('default', 'google', 'k1', 's1', 's2', 'selector1', 'selector2', 'mail');
        $o         = $this->core->get_options();
        $custom    = isset($o['dns_dkim_selectors']) ? (string) $o['dns_dkim_selectors'] : '';
        foreach (preg_split('/[\s,]+/', $custom) as $s) {
            $s = sanitize_key($s);
            if ($s !== '' && !in_array($s, $selectors, true)) {
                $selectors[] = $s;
            }
        }
        $matched  = array();
        $strength = array();
        foreach ($selectors as $selector) {
            $records = $this->dns($selector . '._domainkey.' . $host, DNS_TXT, 'dkim_' . $selector);
            $value   = '';
            foreach ($records as $r) {
                $txt = $this->txt($r);
                if ($txt !== '') {
                    $value = $txt;
                    break;
                }
            }
            if ($value === '') {
                continue;
            }
            $matched[]         = $selector;
            $detail            = $this->dkim_key_strength($value, $selector);
            $strength[$selector] = $detail;
            if ($detail['status'] === 'weak') {
                $this->add(
                    $findings,
                    $counts,
                    'high',
                    sprintf(
                        /* translators: 1: DKIM selector, 2: RSA key size in bits. */
                        __('DKIM selector `%1$s` uses an RSA key of only %2$d bits; upgrade to at least 2048 bits.', 'nubivio-healthcare-security-hardening'),
                        $selector,
                        (int) $detail['bits']
                    )
                );
            } elseif ($detail['status'] === 'parse_error') {
                $findings[] = array(
                    'severity' => 'warn',
                    'message'  => sprintf(
                        /* translators: %s: DKIM selector. */
                        __('DKIM public key for selector `%s` could not be parsed; check the TXT record formatting.', 'nubivio-healthcare-security-hardening'),
                        $selector
                    ),
                );
            }
        }
        $summary['dkim'] = array('matched' => $matched, 'strength' => $strength);
        if (!$matched) {
            $this->add($findings, $counts, 'low', __('No DKIM record found for common selectors. Provide your DKIM selector in DNS health settings.', 'nubivio-healthcare-security-hardening'));
        }

        // CAA.
        $caa_type    = defined('DNS_CAA') ? DNS_CAA : DNS_ANY;
        $caa         = $this->dns($host, $caa_type, 'caa');
        $caa_entries = array();
        foreach ($caa as $r) {
            if ((isset($r['type']) && $r['type'] === 'CAA') || isset($r['value'])) {
                $caa_entries[] = $r;
            }
        }
        $summary['caa'] = array('records' => $caa_entries);
        if (!$caa_entries) {
            $this->add(
                $findings,
                $counts,
                'low',
                sprintf(
                    __('%1$s has no CAA record. Suggested template: %2$s. IN CAA 0 issue "letsencrypt.org"', 'nubivio-healthcare-security-hardening'),
                    $host,
                    $host
                )
            );
        }

        // MTA-STS.
        $mta_txt     = $this->dns('_mta-sts.' . $host, DNS_TXT, 'mta_sts_txt');
        $mta_records = array();
        foreach ($mta_txt as $r) {
            $v = $this->txt($r);
            if (stripos($v, 'v=STSv1') === 0) {
                $mta_records[] = $v;
            }
        }
        $mta      = $this->http('https://mta-sts.' . $host . '/.well-known/mta-sts.txt', 'mta_sts_http', 8);
        $code     = !is_wp_error($mta) ? (int) wp_remote_retrieve_response_code($mta) : 0;
        $policy   = ($code >= 200 && $code < 300) ? wp_remote_retrieve_body($mta) : '';
        preg_match_all('/^mx:\s*(.+)$/mi', $policy, $mx);
        $summary['mta_sts'] = array(
            'records' => $mta_records,
            'mx'      => isset($mx[1]) ? $mx[1] : array(),
        );
        if (!$mta_records && $policy === '') {
            $this->add(
                $findings,
                $counts,
                'low',
                sprintf(
                    __('MTA-STS is not configured. TXT template: _mta-sts.%1$s. IN TXT "v=STSv1; id=$(date +%%Y%%m%%d%%H%%M)". Policy template: version: STSv1; mode: enforce; mx: mail.%1$s; max_age: 604800', 'nubivio-healthcare-security-hardening'),
                    $host
                )
            );
        }

        // DNSSEC indicator (native, and optional DoH validation).
        $authns = array();
        $addtl  = array();
        $any    = $this->dns_any($host, 'dnssec', $authns, $addtl);
        $signed = false;
        foreach (array_merge($any, $addtl) as $r) {
            if (isset($r['type']) && $r['type'] === 'RRSIG') {
                $signed = true;
                break;
            }
        }
        $summary['dnssec'] = array('indicator' => $signed, 'doh' => null);
        if (!$signed) {
            $this->add($findings, $counts, 'low', __('No DNSSEC indicators found. Ask your DNS provider to enable DNSSEC on this zone.', 'nubivio-healthcare-security-hardening'));
        }
        if (!empty($o['dns_use_doh'])) {
            $doh  = $this->http(
                'https://cloudflare-dns.com/dns-query?name=' . rawurlencode($host) . '&type=A',
                'doh',
                8,
                array('Accept' => 'application/dns-json')
            );
            $data = !is_wp_error($doh) ? json_decode(wp_remote_retrieve_body($doh), true) : null;
            $ad   = is_array($data) && !empty($data['AD']);
            $summary['dnssec']['doh'] = $ad;
            if (!$ad) {
                $this->add($findings, $counts, 'medium', __('DNSSEC not validated by DoH resolver; the record may be present but not signed correctly.', 'nubivio-healthcare-security-hardening'));
            }
        }

        // AAAA.
        $aaaa            = $this->dns($host, DNS_AAAA, 'aaaa');
        $summary['aaaa'] = array('records' => $aaaa);
        if (!$aaaa) {
            $this->add($findings, $counts, 'low', __('No AAAA record. Your site is not reachable over IPv6.', 'nubivio-healthcare-security-hardening'));
        }

        // TLS-RPT.
        $tls_rpt_txt = $this->dns('_smtp._tls.' . $host, DNS_TXT, 'tls_rpt');
        $tls_rpt     = array();
        foreach ($tls_rpt_txt as $r) {
            $v = $this->txt($r);
            if (stripos($v, 'v=TLSRPTv1') === 0) {
                $tls_rpt[] = $v;
            }
        }
        $summary['tls_rpt'] = array('records' => $tls_rpt);
        $mta_sts_present    = !empty($mta_records) || $policy !== '';
        if (!$tls_rpt && $mta_sts_present) {
            $this->add(
                $findings,
                $counts,
                'low',
                __('MTA-STS is configured but TLS-RPT is missing; add a `_smtp._tls` TXT record to receive delivery-failure reports.', 'nubivio-healthcare-security-hardening')
            );
        }

        // BIMI.
        $bimi_txt = $this->dns('default._bimi.' . $host, DNS_TXT, 'bimi');
        $bimi     = array();
        foreach ($bimi_txt as $r) {
            $v = $this->txt($r);
            if (stripos($v, 'v=BIMI1') === 0) {
                $bimi[] = $v;
            }
        }
        $summary['bimi'] = array('records' => $bimi);
        if ($bimi) {
            $findings[] = array(
                'severity' => 'info',
                'message'  => __('BIMI record is published; supported mailbox providers can display your brand indicator.', 'nubivio-healthcare-security-hardening'),
            );
        }

        // No-mail domain detection.
        $mx_records = $this->dns($host, DNS_MX, 'mx');
        if (
            count($spf) === 1
            && preg_match('/^\s*v=spf1\s+-all\s*$/i', $spf[0])
            && !$mx_records
            && !$dmarc
        ) {
            $summary['no_mail'] = true;
            $findings[]         = array(
                'severity' => 'info',
                'message'  => __('Domain appears not to send mail; SPF -all with no MX records is the recommended configuration.', 'nubivio-healthcare-security-hardening'),
            );
        }

        // NS redundancy.
        $ns_records  = $this->dns($host, DNS_NS, 'ns');
        $ns_targets  = array();
        foreach ($ns_records as $r) {
            if (isset($r['target']) && $r['target'] !== '') {
                $ns_targets[] = strtolower((string) $r['target']);
            }
        }
        $ns_targets      = array_values(array_unique($ns_targets));
        $summary['ns']   = array('records' => $ns_targets);
        if (count($ns_targets) < 2) {
            $this->add(
                $findings,
                $counts,
                'medium',
                __('Fewer than two nameservers detected; single point of failure for DNS resolution.', 'nubivio-healthcare-security-hardening')
            );
        }

        // SOA.
        $soa_type    = defined('DNS_SOA') ? DNS_SOA : DNS_ANY;
        $soa_records = $this->dns($host, $soa_type, 'soa');
        $soa_entry   = null;
        foreach ($soa_records as $r) {
            if (isset($r['type']) && $r['type'] === 'SOA') {
                $soa_entry = $r;
                break;
            }
        }
        $summary['soa'] = array('record' => $soa_entry);
        if (!$soa_entry) {
            $this->add(
                $findings,
                $counts,
                'medium',
                __('No SOA record found for the zone; DNS delegation may be misconfigured.', 'nubivio-healthcare-security-hardening')
            );
        } else {
            $serial = isset($soa_entry['serial']) ? (int) $soa_entry['serial'] : 0;
            $age    = $this->soa_serial_age($serial);
            if ($age !== null && $age < 3 * DAY_IN_SECONDS) {
                $this->add(
                    $findings,
                    $counts,
                    'low',
                    __('SOA serial changed within the last 3 days; the zone may be unstable or actively edited.', 'nubivio-healthcare-security-hardening')
                );
            }
        }

        return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
    }

    /**
     * Grade the final SPF mechanism to a policy string.
     *
     * @param string $record Full SPF record value.
     * @return string One of pass, softfail, neutral, none.
     */
    private function spf_policy($record) {
        $normal = trim((string) $record);
        if (preg_match('/(^|\s)([-~?+]?)all\s*$/i', $normal, $m)) {
            $qualifier = $m[2] !== '' ? $m[2] : '+';
            switch ($qualifier) {
                case '-':
                    return 'pass';
                case '~':
                    return 'softfail';
                case '?':
                    return 'neutral';
                case '+':
                default:
                    return 'pass';
            }
        }
        return 'none';
    }

    /**
     * Count SPF DNS lookups per RFC 7208 section 4.6.4.
     *
     * Traverses `include`, `redirect`, `a`, `mx`, `exists` and `ptr` mechanisms.
     * Recursion depth is capped at 2 and the total number of lookups at 20 to
     * bound run-time and prevent malicious records from stalling the scan.
     *
     * @param string $record SPF record value.
     * @param string $host   Domain the record was fetched from.
     * @return int Total lookups counted.
     */
    private function spf_count_lookups($record, $host) {
        $total = 0;
        $this->spf_walk($record, $host, 0, $total);
        return $total;
    }

    /**
     * Recursive helper that accumulates SPF DNS lookups.
     *
     * @param string $record Current SPF record value.
     * @param string $host   Domain the record belongs to.
     * @param int    $depth  Recursion depth (0 for the root record).
     * @param int    $total  Running total, updated by reference.
     */
    private function spf_walk($record, $host, $depth, &$total) {
        if ($depth > 2 || $total > 20) {
            return;
        }
        $terms = preg_split('/\s+/', trim((string) $record));
        if (!is_array($terms)) {
            return;
        }
        foreach ($terms as $term) {
            if ($total > 20) {
                return;
            }
            $term = ltrim($term, '+-~?');
            $low  = strtolower($term);
            if ($low === 'a' || strpos($low, 'a:') === 0 || strpos($low, 'a/') === 0) {
                $total++;
            } elseif ($low === 'mx' || strpos($low, 'mx:') === 0 || strpos($low, 'mx/') === 0) {
                $total++;
            } elseif (strpos($low, 'exists:') === 0) {
                $total++;
            } elseif ($low === 'ptr' || strpos($low, 'ptr:') === 0) {
                $total++;
            } elseif (strpos($low, 'include:') === 0) {
                $total++;
                $target = substr($term, 8);
                if ($target !== '' && $total <= 20) {
                    $this->spf_walk_target($target, $depth + 1, $total);
                }
            } elseif (strpos($low, 'redirect=') === 0) {
                $total++;
                $target = substr($term, 9);
                if ($target !== '' && $total <= 20) {
                    $this->spf_walk_target($target, $depth + 1, $total);
                }
            }
        }
        unset($host);
    }

    /**
     * Fetch and walk the SPF record for an included or redirected target.
     *
     * @param string $target Domain to resolve.
     * @param int    $depth  Depth counter passed to spf_walk().
     * @param int    $total  Running total, updated by reference.
     */
    private function spf_walk_target($target, $depth, &$total) {
        $key    = 'spf_lookups_' . sanitize_key($target);
        $txt    = $this->dns($target, DNS_TXT, $key);
        $record = '';
        foreach ($txt as $r) {
            $value = $this->txt($r);
            if (stripos($value, 'v=spf1') === 0) {
                $record = $value;
                break;
            }
        }
        if ($record !== '') {
            $this->spf_walk($record, $target, $depth, $total);
        }
    }

    /**
     * Determine the strength of a DKIM public key.
     *
     * Parses the `p=` tag out of a DKIM TXT record, decodes the base64 payload
     * and asks OpenSSL for the key type and bit length. Returns a status of
     * `strong`, `weak`, `parse_error` or `unsupported` together with the raw
     * details reported by OpenSSL.
     *
     * @param string $record   DKIM TXT record value.
     * @param string $selector Selector name, used only for the transient key.
     * @return array{status:string,bits:int,type:string}
     */
    private function dkim_key_strength($record, $selector) {
        $out = array('status' => 'unknown', 'bits' => 0, 'type' => '');
        $key = 'nubivio_hsh_dns_' . md5($this->host() . '|dkim_strength_' . $selector);
        $cached = get_transient($key);
        if (is_array($cached)) {
            return $cached;
        }
        if (!function_exists('openssl_pkey_get_public') || !function_exists('openssl_pkey_get_details')) {
            $out['status'] = 'unsupported';
            set_transient($key, $out, 6 * HOUR_IN_SECONDS);
            return $out;
        }
        $tags  = array();
        $parts = preg_split('/;\s*/', (string) $record);
        foreach ($parts as $part) {
            $pos = strpos($part, '=');
            if ($pos === false) {
                continue;
            }
            $name  = strtolower(trim(substr($part, 0, $pos)));
            $value = trim(substr($part, $pos + 1));
            $tags[$name] = $value;
        }
        $key_type = isset($tags['k']) ? strtolower($tags['k']) : 'rsa';
        $p        = isset($tags['p']) ? $tags['p'] : '';
        if ($p === '') {
            $out['status'] = 'parse_error';
            set_transient($key, $out, HOUR_IN_SECONDS);
            return $out;
        }
        $p_clean = preg_replace('/\s+/', '', $p);
        $pem     = "-----BEGIN PUBLIC KEY-----\n" . chunk_split((string) $p_clean, 64) . "-----END PUBLIC KEY-----\n";
        $res     = @openssl_pkey_get_public($pem);
        if (!$res) {
            $out['status'] = 'parse_error';
            set_transient($key, $out, HOUR_IN_SECONDS);
            return $out;
        }
        $details = @openssl_pkey_get_details($res);
        if (function_exists('openssl_free_key')) {
            @openssl_free_key($res);
        }
        if (!is_array($details)) {
            $out['status'] = 'parse_error';
            set_transient($key, $out, HOUR_IN_SECONDS);
            return $out;
        }
        $bits = isset($details['bits']) ? (int) $details['bits'] : 0;
        $type = isset($details['type']) ? (int) $details['type'] : -1;
        $out['bits'] = $bits;
        if (defined('OPENSSL_KEYTYPE_RSA') && $type === OPENSSL_KEYTYPE_RSA) {
            $out['type']   = 'rsa';
            $out['status'] = $bits >= 2048 ? 'strong' : 'weak';
        } elseif ($key_type === 'ed25519') {
            $out['type']   = 'ed25519';
            $out['status'] = 'strong';
        } else {
            $out['type']   = $key_type !== '' ? $key_type : 'unknown';
            $out['status'] = $bits >= 2048 ? 'strong' : 'weak';
        }
        set_transient($key, $out, 6 * HOUR_IN_SECONDS);
        return $out;
    }

    /**
     * Estimate the age of an SOA serial number in seconds.
     *
     * Serials that follow the YYYYMMDDNN convention decode into a timestamp;
     * anything else returns null so the caller can skip the freshness check.
     *
     * @param int $serial Raw SOA serial number.
     * @return int|null Age in seconds, or null when the serial is not a date.
     */
    private function soa_serial_age($serial) {
        if ($serial < 1000000000) {
            return null;
        }
        $text = (string) $serial;
        if (strlen($text) < 8) {
            return null;
        }
        $year  = (int) substr($text, 0, 4);
        $month = (int) substr($text, 4, 2);
        $day   = (int) substr($text, 6, 2);
        if ($year < 1990 || $year > 2100 || $month < 1 || $month > 12 || $day < 1 || $day > 31) {
            return null;
        }
        $ts = gmmktime(0, 0, 0, $month, $day, $year);
        if (!is_int($ts) || $ts <= 0) {
            return null;
        }
        $age = time() - $ts;
        return $age >= 0 ? $age : null;
    }

    public static function health_row($summary) {
        $issues = empty($summary['host'])
            || empty($summary['spf']['records'])
            || empty($summary['dmarc']['records']);
        return array(
            'label'  => __('DNS health', 'nubivio-healthcare-security-hardening'),
            'status' => $issues ? 'warn' : 'pass',
            'detail' => $issues
                ? __('Review DNS health findings for mail and transport protections.', 'nubivio-healthcare-security-hardening')
                : __('Core DNS health records are present.', 'nubivio-healthcare-security-hardening'),
        );
    }

    public static function clear_cache($host) {
        $checks    = array(
            'spf',
            'dmarc',
            'caa',
            'mta_sts_txt',
            'mta_sts_http',
            'dnssec',
            'doh',
            'aaaa',
            'ns',
            'soa',
            'tls_rpt',
            'bimi',
            'mx',
        );
        $selectors = array('default', 'google', 'k1', 's1', 's2', 'selector1', 'selector2', 'mail');
        $options   = get_option('nubivio_hsh_options', array());
        $custom    = isset($options['dns_dkim_selectors']) ? (string) $options['dns_dkim_selectors'] : '';
        foreach (preg_split('/[\s,]+/', $custom) as $selector) {
            $selector = sanitize_key($selector);
            if ($selector !== '' && !in_array($selector, $selectors, true)) {
                $selectors[] = $selector;
            }
        }
        foreach ($selectors as $selector) {
            $checks[] = 'dkim_' . $selector;
            $checks[] = 'dkim_strength_' . $selector;
            $checks[] = 'spf_lookups_' . $selector;
        }
        $checks[] = 'spf_lookups';
        foreach ($checks as $check) {
            delete_transient('nubivio_hsh_dns_' . md5($host . '|' . $check));
        }
    }

    private function dns($host, $type, $check) {
        $key    = 'nubivio_hsh_dns_' . md5($this->host() . '|' . $check);
        $cached = get_transient($key);
        if (is_array($cached)) {
            return $cached;
        }
        $records = @dns_get_record($host, $type);
        $records = is_array($records) ? $records : array();
        set_transient($key, $records, 6 * HOUR_IN_SECONDS);
        return $records;
    }

    private function dns_any($host, $check, &$authns, &$addtl) {
        $key    = 'nubivio_hsh_dns_' . md5($this->host() . '|' . $check);
        $cached = get_transient($key);
        if (is_array($cached)) {
            $authns = isset($cached['authns']) ? $cached['authns'] : array();
            $addtl  = isset($cached['addtl']) ? $cached['addtl'] : array();
            return isset($cached['records']) ? $cached['records'] : array();
        }
        $type    = defined('DNS_ANY') ? DNS_ANY : DNS_TXT;
        $records = @dns_get_record($host, $type, $authns, $addtl);
        $records = is_array($records) ? $records : array();
        set_transient(
            $key,
            array('records' => $records, 'authns' => $authns, 'addtl' => $addtl),
            6 * HOUR_IN_SECONDS
        );
        return $records;
    }

    private function http($url, $check, $timeout, $headers = array()) {
        $key    = 'nubivio_hsh_dns_' . md5($this->host() . '|' . $check);
        $cached = get_transient($key);
        if (is_array($cached)) {
            return $cached;
        }
        $res = wp_remote_get($url, array('timeout' => $timeout, 'headers' => $headers));
        if (!is_wp_error($res)) {
            set_transient($key, $res, 6 * HOUR_IN_SECONDS);
        }
        return $res;
    }

    private function host() {
        return strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
    }

    private function txt($record) {
        if (isset($record['txt'])) {
            return (string) $record['txt'];
        }
        if (isset($record['entries']) && is_array($record['entries'])) {
            return implode('', $record['entries']);
        }
        return '';
    }

    private function add(&$findings, &$counts, $severity, $message) {
        $findings[]        = array('severity' => $severity, 'message' => $message);
        $counts[$severity]++;
    }
}
