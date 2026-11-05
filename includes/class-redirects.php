<?php
/**
 * Security headers across the redirect chain (v2.6.0).
 *
 * The HSTS module only looks at the final homepage response. This module
 * follows the chain from http://<host>/ and from the www or non-www
 * variant (only when that variant has an A or AAAA record) hop by hop and
 * records, per hop, the URL, status, Location and whether HSTS was sent.
 * It runs next to the HSTS check and does not replace it.
 *
 * Findings:
 * - an https hop without Strict-Transport-Security (medium);
 * - the first step from http does not go to https on the same host (low);
 * - a chain longer than 3 hops (low);
 * - a redirect to another domain (low, reported only, not followed).
 *
 * Safety: only hosts inside the site's registered domain are requested.
 * GET, timeout 8 s, redirection 0, 1 KB body limit, at most 5 hops per
 * start point. Only URLs, status codes and an HSTS yes/no are stored.
 * Cached for 12 hours.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Redirects {

    const CACHE_TTL   = 43200;
    const MAX_HOPS    = 5;
    const LONG_CHAIN  = 3;
    const TIMEOUT     = 8;
    const USER_AGENT  = 'Nubivio-HSH/2.6 redirects';

    /** @var Nubivio_HSH|null */
    private $core;

    /**
     * @param Nubivio_HSH|null $core Plugin core.
     */
    public function __construct($core = null) {
        $this->core = $core;
    }

    /**
     * Transient key for a host.
     *
     * @param string $host Home host.
     * @return string
     */
    public static function cache_key($host) {
        return 'nubivio_hsh_redirects_' . md5((string) $host);
    }

    /**
     * Forget the cached chains for the current site.
     *
     * @return void
     */
    public static function clear_cache() {
        delete_transient(self::cache_key(strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST))));
    }

    /**
     * Run the redirect chain check (cached for 12 hours).
     *
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function run() {
        $host = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        if ($host === '') {
            return $this->evaluate(array('host' => '', 'domain' => '', 'chains' => array()));
        }
        $key    = self::cache_key($host);
        $cached = get_transient($key);
        if (is_array($cached) && isset($cached['chains'])) {
            return $this->evaluate($cached);
        }
        $summary = $this->probe($host);
        set_transient($key, $summary, self::CACHE_TTL);
        return $this->evaluate($summary);
    }

    /**
     * The www or non-www counterpart of a host.
     *
     * @param string $host Host.
     * @return string
     */
    public static function variant($host) {
        $host = strtolower((string) $host);
        return strpos($host, 'www.') === 0 ? substr($host, 4) : 'www.' . $host;
    }

    /**
     * Approximate registered domain without a public suffix list: the last
     * two labels, or three when the second-level label is a common
     * registry label under a two-letter country code (co.uk, com.au).
     *
     * @param string $host Host.
     * @return string
     */
    public static function registered_domain($host) {
        $labels = explode('.', strtolower(trim((string) $host, '.')));
        $count  = count($labels);
        if ($count <= 2) {
            return implode('.', $labels);
        }
        $second = $labels[$count - 2];
        $tld    = $labels[$count - 1];
        $sld    = array('co', 'com', 'org', 'net', 'ac', 'gov', 'edu', 'nhs', 'ltd', 'plc', 'or', 'ne', 'gv');
        if (strlen($tld) === 2 && in_array($second, $sld, true)) {
            return implode('.', array_slice($labels, -3));
        }
        return implode('.', array_slice($labels, -2));
    }

    /**
     * Whether a host has an A or AAAA record.
     *
     * @param string $host Host.
     * @return bool
     */
    private static function resolves($host) {
        if (!function_exists('dns_get_record')) {
            return false;
        }
        foreach (array(DNS_A, DNS_AAAA) as $type) {
            $records = @dns_get_record($host, $type); // phpcs:ignore WordPress.PHP.NoSilencedErrors
            if (is_array($records) && !empty($records)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Follow each start point hop by hop.
     *
     * @param string $host Home host.
     * @return array<string,mixed>
     */
    private function probe($host) {
        $domain  = self::registered_domain($host);
        $variant = self::variant($host);
        $starts  = array('http://' . $host . '/');
        /**
         * Filter whether the www or non-www variant resolves (tests, split DNS).
         *
         * @param bool   $resolves Result of the A/AAAA lookup.
         * @param string $variant  Variant host.
         */
        if (apply_filters('nubivio_hsh_redirects_variant_resolves', self::resolves($variant), $variant)) {
            $starts[] = 'http://' . $variant . '/';
        }
        $chains = array();
        foreach ($starts as $start) {
            $chains[] = $this->follow($start, $domain);
        }
        return array(
            'host'    => $host,
            'domain'  => $domain,
            'variant' => $variant,
            'chains'  => $chains,
            'time'    => time(),
        );
    }

    /**
     * Follow one chain without letting the HTTP API redirect for us.
     *
     * @param string $start  Start URL.
     * @param string $domain Registered domain; only hosts inside it are requested.
     * @return array{start:string,hops:array,end:string}
     */
    private function follow($start, $domain) {
        $hops = array();
        $url  = $start;
        $seen = array();
        $end  = 'ok';
        while (true) {
            if (count($hops) >= self::MAX_HOPS) {
                $end = 'too_many';
                break;
            }
            if (isset($seen[$url])) {
                $end = 'loop';
                break;
            }
            $seen[$url] = true;
            $res        = wp_remote_get(
                $url,
                array(
                    'timeout'             => self::TIMEOUT,
                    'redirection'         => 0,
                    'limit_response_size' => 1024,
                    'user-agent'          => self::USER_AGENT,
                )
            );
            if (is_wp_error($res)) {
                $end = count($hops) === 0 ? 'unreachable' : 'error';
                break;
            }
            $code     = (int) wp_remote_retrieve_response_code($res);
            $location = trim((string) wp_remote_retrieve_header($res, 'location'));
            $hsts     = trim((string) wp_remote_retrieve_header($res, 'strict-transport-security')) !== '';
            $next     = '';
            if ($code >= 300 && $code < 400 && $location !== '') {
                $next = self::resolve($url, $location);
            }
            $hops[] = array(
                'url'      => $url,
                'status'   => $code,
                'location' => $next,
                'hsts'     => $hsts,
            );
            if ($next === '') {
                break;
            }
            if (!self::in_domain(strtolower((string) wp_parse_url($next, PHP_URL_HOST)), $domain)) {
                $end = 'external';
                break;
            }
            $url = $next;
        }
        return array(
            'start' => $start,
            'hops'  => $hops,
            'end'   => $end,
        );
    }

    /**
     * Resolve a Location header against the current URL.
     *
     * @param string $base     Current URL.
     * @param string $location Location header value.
     * @return string
     */
    public static function resolve($base, $location) {
        $location = trim($location);
        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $location)) {
            return $location;
        }
        $parts  = wp_parse_url($base);
        $scheme = isset($parts['scheme']) ? $parts['scheme'] : 'https';
        $host   = isset($parts['host']) ? $parts['host'] : '';
        $port   = isset($parts['port']) ? ':' . $parts['port'] : '';
        if (strpos($location, '//') === 0) {
            return $scheme . ':' . $location;
        }
        if (strpos($location, '/') === 0) {
            return $scheme . '://' . $host . $port . $location;
        }
        $path = isset($parts['path']) ? $parts['path'] : '/';
        $dir  = substr($path, 0, (int) strrpos($path, '/') + 1);
        return $scheme . '://' . $host . $port . $dir . $location;
    }

    /**
     * Whether a host belongs to the registered domain.
     *
     * @param string $host   Host.
     * @param string $domain Registered domain.
     * @return bool
     */
    private static function in_domain($host, $domain) {
        if ($host === '' || $domain === '') {
            return false;
        }
        return $host === $domain || substr($host, -strlen('.' . $domain)) === '.' . $domain;
    }

    /**
     * Turn chains into findings.
     *
     * @param array $summary Summary from probe().
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function evaluate($summary) {
        $findings  = array();
        $counts    = array('high' => 0, 'medium' => 0, 'low' => 0);
        $home_host = isset($summary['host']) ? (string) $summary['host'] : '';

        foreach ((array) $summary['chains'] as $chain) {
            $hops  = isset($chain['hops']) ? (array) $chain['hops'] : array();
            $start = (string) $chain['start'];
            if (!$hops) {
                continue;
            }
            $this->check_first_hop($findings, $counts, $start, $hops[0]);

            foreach ($hops as $i => $hop) {
                if (strpos((string) $hop['url'], 'https://') !== 0 || !empty($hop['hsts'])) {
                    continue;
                }
                $hop_host = strtolower((string) wp_parse_url($hop['url'], PHP_URL_HOST));
                $is_final = $i === count($hops) - 1 && $hop['location'] === '';
                // The final homepage response is already covered by the HSTS module.
                if ($is_final && $hop_host === $home_host) {
                    continue;
                }
                $this->add(
                    $findings,
                    $counts,
                    'medium',
                    sprintf(
                        /* translators: 1: URL, 2: HTTP status code. */
                        __(
                            '%1$s (HTTP %2$d) does not send Strict-Transport-Security. Every HTTPS response in the redirect chain needs the header, including redirects.',
                            'nubivio-healthcare-security-hardening'
                        ),
                        $hop['url'],
                        (int) $hop['status']
                    )
                );
            }

            if (count($hops) > self::LONG_CHAIN || $chain['end'] === 'loop' || $chain['end'] === 'too_many') {
                $this->add(
                    $findings,
                    $counts,
                    'low',
                    sprintf(
                        /* translators: 1: start URL, 2: maximum advised number of hops. */
                        __('The redirect chain from %1$s needs more than %2$d steps or loops. Redirect in fewer steps.', 'nubivio-healthcare-security-hardening'),
                        $start,
                        self::LONG_CHAIN
                    )
                );
            }
            if ($chain['end'] === 'external') {
                $last = $hops[count($hops) - 1];
                $this->add(
                    $findings,
                    $counts,
                    'low',
                    sprintf(
                        /* translators: 1: start URL, 2: redirect target outside the site's domain. */
                        __('The redirect chain from %1$s leaves your domain for %2$s. That target was not checked.', 'nubivio-healthcare-security-hardening'),
                        $start,
                        $last['location']
                    )
                );
            }
        }

        return array(
            'findings' => $findings,
            'counts'   => $counts,
            'summary'  => $summary,
        );
    }

    /**
     * The first response for an http:// start must redirect to https on
     * the same host (the order hstspreload.org and internet.nl expect).
     *
     * @param array  $findings Findings list.
     * @param array  $counts   Counters.
     * @param string $start    Start URL.
     * @param array  $first    First hop.
     * @return void
     */
    private function check_first_hop(&$findings, &$counts, $start, $first) {
        $start_host = strtolower((string) wp_parse_url($start, PHP_URL_HOST));
        $next       = (string) $first['location'];
        $expected   = 'https://' . $start_host . '/';
        if ($next !== '' && strpos($next, 'https://') === 0
            && strtolower((string) wp_parse_url($next, PHP_URL_HOST)) === $start_host) {
            return;
        }
        if ($next === '') {
            $message = sprintf(
                /* translators: 1: start URL, 2: HTTP status code, 3: expected https URL. */
                __('%1$s answers with HTTP %2$d instead of redirecting to %3$s.', 'nubivio-healthcare-security-hardening'),
                $start,
                (int) $first['status'],
                $expected
            );
        } else {
            $message = sprintf(
                /* translators: 1: start URL, 2: redirect target, 3: expected https URL on the same host. */
                __('%1$s redirects to %2$s. Redirect to %3$s first, so that host can set HSTS.', 'nubivio-healthcare-security-hardening'),
                $start,
                $next,
                $expected
            );
        }
        $this->add($findings, $counts, 'low', $message);
    }

    /**
     * Row for the plugin's own Site health card.
     *
     * @param array $result Result of run().
     * @return array{label:string,status:string,detail:string}
     */
    public static function health_row($result) {
        $label   = __('Redirect chain security headers', 'nubivio-healthcare-security-hardening');
        $counts  = isset($result['counts']) ? (array) $result['counts'] : array();
        $chains  = isset($result['summary']['chains']) ? (array) $result['summary']['chains'] : array();
        $reached = 0;
        foreach ($chains as $chain) {
            if (!empty($chain['hops'])) {
                $reached++;
            }
        }
        if ($reached === 0) {
            return array(
                'label'  => $label,
                'status' => 'warn',
                'detail' => __('The http start points could not be requested, so the redirect chain was not checked.', 'nubivio-healthcare-security-hardening'),
            );
        }
        $high   = isset($counts['high']) ? (int) $counts['high'] : 0;
        $medium = isset($counts['medium']) ? (int) $counts['medium'] : 0;
        $low    = isset($counts['low']) ? (int) $counts['low'] : 0;
        if ($high + $medium + $low === 0) {
            return array(
                'label'  => $label,
                'status' => 'pass',
                'detail' => __('http redirects to HTTPS on the same host and every HTTPS hop sends HSTS.', 'nubivio-healthcare-security-hardening'),
            );
        }
        return array(
            'label'  => $label,
            'status' => $high > 0 ? 'fail' : 'warn',
            'detail' => sprintf(
                /* translators: 1: high findings, 2: medium findings, 3: low findings. */
                __('Redirect chain findings: %1$d high, %2$d medium, %3$d low.', 'nubivio-healthcare-security-hardening'),
                $high,
                $medium,
                $low
            ),
        );
    }

    /**
     * Append a finding once and bump its counter.
     *
     * @param array  $findings Findings list.
     * @param array  $counts   Counters.
     * @param string $severity high, medium or low.
     * @param string $message  Message.
     * @return void
     */
    private function add(&$findings, &$counts, $severity, $message) {
        foreach ($findings as $existing) {
            if ($existing['message'] === $message) {
                return;
            }
        }
        $findings[] = array(
            'severity' => $severity,
            'message'  => $message,
            'controls' => array('A.8.21', 'A.8.24'),
        );
        $counts[$severity]++;
    }
}
