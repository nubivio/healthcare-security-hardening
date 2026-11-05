<?php
/**
 * RDAP domain security check (v2.6.0, opt-in).
 *
 * Looks up the registration of the site's registered domain over RDAP:
 * registrar, creation date, age, expiry date, status flags and the
 * registry's DNSSEC delegation flag.
 *
 * External services (only when the `rdap_enabled` option is on, only from
 * the manual scan or the existing scan cron, never on a page load):
 * - IANA RDAP bootstrap https://data.iana.org/rdap/dns.json, to find the
 *   RDAP server of the top-level domain (cached 7 days);
 * - that registry's RDAP server, {base}domain/{domain} (cached 24 hours).
 * Only the domain name is sent. Unreachable or slow sources give a
 * "not available" note and the scan continues.
 *
 * Registered domain: the last two labels of the home host. This is wrong
 * for second-level registries such as .co.uk or .com.au; override with the
 * `nubivio_hsh_registered_domain` filter.
 *
 * Some registries do not publish an expiry date or transfer lock statuses.
 * SIDN (.nl) publishes neither; that gives an info note, not a finding.
 * Filter `nubivio_hsh_rdap_no_lock_status_tlds` lists such TLDs.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Rdap {

    const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
    const BOOTSTRAP_TTL = 604800;
    const DOMAIN_TTL    = 86400;
    const TIMEOUT       = 10;
    const MAX_BYTES     = 262144;

    /** @var Nubivio_HSH|null */
    private $core;

    /**
     * @param Nubivio_HSH|null $core Plugin core.
     */
    public function __construct($core = null) {
        $this->core = $core;
    }

    /**
     * Whether the module is switched on.
     *
     * @return bool
     */
    public static function enabled() {
        $o = get_option(Nubivio_HSH::OPTION, array());
        return is_array($o) && !empty($o['rdap_enabled']);
    }

    /**
     * Registered domain of a host: the last two labels, filterable.
     *
     * @param string $host Host name.
     * @return string
     */
    public static function registered_domain($host) {
        $host   = strtolower(trim((string) $host, '.'));
        $labels = $host === '' ? array() : explode('.', $host);
        $domain = count($labels) > 2 ? implode('.', array_slice($labels, -2)) : $host;
        /**
         * Filter the registered domain used for RDAP and certificate transparency.
         *
         * @param string $domain Last two labels of the host.
         * @param string $host   Full home host.
         */
        $filtered = apply_filters('nubivio_hsh_registered_domain', $domain, $host);
        return is_string($filtered) && $filtered !== '' ? strtolower($filtered) : $domain;
    }

    /**
     * Registered domain of the site.
     *
     * @return string
     */
    public static function site_domain() {
        return self::registered_domain((string) wp_parse_url(home_url(), PHP_URL_HOST));
    }

    /**
     * Run the check.
     *
     * @param bool|null $dnssec_seen DNSSEC indicator from the DNS module, null when unknown.
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function run($dnssec_seen = null) {
        $domain  = self::site_domain();
        $summary = array(
            'enabled'   => self::enabled(),
            'domain'    => $domain,
            'available' => false,
            'error'     => '',
        );
        if (!$summary['enabled'] || $domain === '' || strpos($domain, '.') === false) {
            return $this->evaluate($summary, $dnssec_seen);
        }

        $key    = 'nubivio_hsh_rdap_' . md5($domain);
        $cached = get_transient($key);
        if (is_array($cached) && isset($cached['domain'])) {
            $cached['enabled'] = true;
            return $this->evaluate($cached, $dnssec_seen);
        }

        $summary = array_merge($summary, $this->lookup($domain));
        // Cache failures briefly so a slow registry does not slow every scan, but retry soon.
        set_transient($key, $summary, $summary['available'] ? self::DOMAIN_TTL : HOUR_IN_SECONDS);
        return $this->evaluate($summary, $dnssec_seen);
    }

    /**
     * RDAP base URL for a TLD from the IANA bootstrap.
     *
     * @param string $tld Top-level domain.
     * @return string|null Base URL, empty string when the TLD has no RDAP server, null when IANA is unreachable.
     */
    private function base_for($tld) {
        $key    = 'nubivio_hsh_rdap_base_' . md5($tld);
        $cached = get_transient($key);
        if (is_string($cached)) {
            return $cached;
        }
        $data = $this->get_json(self::BOOTSTRAP_URL);
        if (!is_array($data) || empty($data['services']) || !is_array($data['services'])) {
            return null;
        }
        $base = '';
        foreach ($data['services'] as $service) {
            if (!is_array($service) || count($service) < 2 || !is_array($service[0]) || !is_array($service[1])) {
                continue;
            }
            if (!in_array($tld, array_map('strtolower', $service[0]), true)) {
                continue;
            }
            foreach ($service[1] as $url) {
                if (stripos((string) $url, 'https://') === 0) {
                    $base = (string) $url;
                    break;
                }
            }
            break;
        }
        if ($base !== '' && substr($base, -1) !== '/') {
            $base .= '/';
        }
        // An empty string is cached too: "this TLD has no RDAP server" is a valid answer.
        set_transient($key, $base, self::BOOTSTRAP_TTL);
        return $base;
    }

    /**
     * Look up the domain and reduce the RDAP answer to the summary fields.
     *
     * @param string $domain Registered domain.
     * @return array<string,mixed>
     */
    private function lookup($domain) {
        $labels = explode('.', $domain);
        $tld    = strtolower((string) end($labels));
        $out    = array(
            'domain'      => $domain,
            'tld'         => $tld,
            'available'   => false,
            'error'       => '',
            'registrar'   => '',
            'created'     => 0,
            'expires'     => 0,
            'status'      => array(),
            'signed'      => null,
            'server'      => '',
            'checked_at'  => time(),
        );
        $base = $this->base_for($tld);
        if ($base === null) {
            $out['error'] = 'unavailable';
            return $out;
        }
        if ($base === '') {
            $out['error'] = 'no_server';
            return $out;
        }
        $out['server'] = (string) wp_parse_url($base, PHP_URL_HOST);
        $data          = $this->get_json($base . 'domain/' . rawurlencode($domain));
        if (!is_array($data) || !isset($data['objectClassName'])) {
            $out['error'] = 'unavailable';
            return $out;
        }
        $out['available'] = true;
        foreach ((array) (isset($data['events']) ? $data['events'] : array()) as $event) {
            $action = isset($event['eventAction']) ? strtolower((string) $event['eventAction']) : '';
            $date   = isset($event['eventDate']) ? strtotime((string) $event['eventDate']) : false;
            if (!$date) {
                continue;
            }
            if ($action === 'registration') {
                $out['created'] = (int) $date;
            } elseif ($action === 'expiration') {
                $out['expires'] = (int) $date;
            }
        }
        foreach ((array) (isset($data['status']) ? $data['status'] : array()) as $status) {
            $out['status'][] = strtolower(trim((string) $status));
        }
        if (isset($data['secureDNS']) && is_array($data['secureDNS']) && isset($data['secureDNS']['delegationSigned'])) {
            $out['signed'] = (bool) $data['secureDNS']['delegationSigned'];
        }
        $out['registrar'] = self::registrar_name(isset($data['entities']) ? (array) $data['entities'] : array());
        return $out;
    }

    /**
     * Name (vCard fn) of the entity with the registrar role.
     *
     * @param array $entities RDAP entities.
     * @return string
     */
    private static function registrar_name($entities) {
        foreach ($entities as $entity) {
            if (!is_array($entity) || empty($entity['roles']) || !in_array('registrar', (array) $entity['roles'], true)) {
                continue;
            }
            $card = isset($entity['vcardArray'][1]) && is_array($entity['vcardArray'][1]) ? $entity['vcardArray'][1] : array();
            foreach ($card as $prop) {
                if (is_array($prop) && isset($prop[0], $prop[3]) && $prop[0] === 'fn' && is_string($prop[3])) {
                    return sanitize_text_field($prop[3]);
                }
            }
        }
        return '';
    }

    /**
     * GET a JSON document with the module's limits.
     *
     * @param string $url URL.
     * @return array|null
     */
    private function get_json($url) {
        $res = wp_remote_get(
            $url,
            array(
                'timeout'             => self::TIMEOUT,
                'redirection'         => 2,
                'limit_response_size' => self::MAX_BYTES,
                'headers'             => array('Accept' => 'application/rdap+json, application/json'),
            )
        );
        if (is_wp_error($res) || (int) wp_remote_retrieve_response_code($res) !== 200) {
            return null;
        }
        $data = json_decode((string) wp_remote_retrieve_body($res), true);
        return is_array($data) ? $data : null;
    }

    /**
     * Turn the summary into findings and notes.
     *
     * @param array     $summary     Summary.
     * @param bool|null $dnssec_seen DNSSEC indicator from the DNS module.
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function evaluate($summary, $dnssec_seen = null) {
        $findings         = array();
        $counts           = array('high' => 0, 'medium' => 0, 'low' => 0);
        $summary['notes'] = array();
        if (empty($summary['enabled']) || empty($summary['available'])) {
            return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
        }
        $domain = (string) $summary['domain'];

        $summary['age_days']     = $summary['created'] ? (int) floor((time() - $summary['created']) / DAY_IN_SECONDS) : null;
        $summary['expires_days'] = $summary['expires'] ? (int) floor(($summary['expires'] - time()) / DAY_IN_SECONDS) : null;

        if ($summary['expires_days'] === null) {
            $summary['notes'][] = __(
                'The registry does not publish an expiry date for this domain (SIDN does not for .nl, for example). Check the renewal with your registrar.',
                'nubivio-healthcare-security-hardening'
            );
        } elseif ($summary['expires_days'] < 60) {
            $this->add(
                $findings,
                $counts,
                $summary['expires_days'] < 30 ? 'high' : 'medium',
                sprintf(
                    /* translators: 1: domain name, 2: number of days, 3: date. */
                    __('The domain %1$s expires in %2$d days (%3$s). Renew it with your registrar so the site and email keep working.', 'nubivio-healthcare-security-hardening'),
                    $domain,
                    $summary['expires_days'],
                    date_i18n(get_option('date_format'), (int) $summary['expires'])
                )
            );
        }

        $no_lock_tlds = (array) apply_filters('nubivio_hsh_rdap_no_lock_status_tlds', array('nl'));
        if (in_array((string) $summary['tld'], $no_lock_tlds, true)) {
            $summary['notes'][] = __(
                'This registry does not publish transfer lock statuses, so the transfer lock cannot be checked here. Ask your registrar how transfers are protected.',
                'nubivio-healthcare-security-hardening'
            );
        } elseif (!in_array('client transfer prohibited', (array) $summary['status'], true)
            && !in_array('server transfer prohibited', (array) $summary['status'], true)) {
            $this->add(
                $findings,
                $counts,
                'low',
                sprintf(
                    /* translators: %s: domain name. */
                    __('%s has no transfer lock (client transfer prohibited). Ask your registrar to enable it to make domain hijacking harder.', 'nubivio-healthcare-security-hardening'),
                    $domain
                )
            );
        }

        if ($summary['signed'] === false && $dnssec_seen === true) {
            $this->add(
                $findings,
                $counts,
                'low',
                __(
                    'The DNS answers carry DNSSEC signatures, but the registry has no DS record (delegationSigned is false). DNSSEC is not active until your registrar publishes the DS record.',
                    'nubivio-healthcare-security-hardening'
                )
            );
        }

        return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
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
        $label = __('Domain registration (RDAP)', 'nubivio-healthcare-security-hardening');
        if (empty($summary['available'])) {
            $detail = isset($summary['error']) && $summary['error'] === 'no_server'
                ? __('The registry of this domain offers no RDAP service, so registration data cannot be checked.', 'nubivio-healthcare-security-hardening')
                : __('RDAP source not available right now; the scan continued without it.', 'nubivio-healthcare-security-hardening');
            return array(
                'label'  => $label,
                'status' => 'warn',
                'detail' => $detail,
            );
        }
        $counts = isset($result['counts']) ? (array) $result['counts'] : array();
        if (!empty($counts['high'])) {
            $status = 'fail';
        } elseif (!empty($counts['medium']) || !empty($counts['low'])) {
            $status = 'warn';
        } else {
            $status = 'pass';
        }
        $detail = array();
        foreach ((array) $result['findings'] as $finding) {
            $detail[] = $finding['message'];
        }
        if (!$detail) {
            $detail[] = __('No domain registration issues found.', 'nubivio-healthcare-security-hardening');
        }
        return array(
            'label'  => $label,
            'status' => $status,
            'detail' => implode(' ', $detail),
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
            'controls' => array('A.5.30'),
        );
        $counts[$severity]++;
    }
}
