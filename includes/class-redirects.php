<?php
/**
 * Security headers across the redirect chain (v2.6.0).
 *
 * The HSTS module only looks at the final homepage response. This module
 * follows the redirect chain for the four entry variants (http and https,
 * with and without www) hop by hop and checks:
 * - http entry points redirect to https on the same host first (the order
 *   hstspreload.org and internet.nl expect), preferably with 301 or 308;
 * - every https hop, including intermediate redirects, sends
 *   Strict-Transport-Security;
 * - chains do not end on plain http, loop, or exceed five hops.
 * It runs next to the HSTS check and does not replace it.
 *
 * Safety: only hosts inside the site's own domain are requested (apex and
 * subdomains); a redirect to any other host is recorded and not followed.
 * GET with timeout 5, redirection 0 and limit_response_size 1024. Only
 * URLs, status codes and an HSTS yes/no are stored.
 *
 * @package Nubivio_HSH
 */
if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Redirects {

    const CACHE_TTL = 21600;
    const MAX_HOPS  = 5;

    /** @var Nubivio_HSH */
    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    public static function cache_key($host) {
        return 'nubivio_hsh_redirects_' . md5((string) $host);
    }

    public static function clear_cache($host) {
        delete_transient(self::cache_key($host));
    }

    /**
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function run() {
        $host = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        if ($host === '') {
            return $this->evaluate(array('host' => '', 'chains' => array()));
        }
        $key    = self::cache_key($host);
        $cached = get_transient($key);
        if (is_array($cached) && isset($cached['chains'])) {
            $summary = $cached;
        } else {
            $summary = $this->probe($host);
            set_transient($key, $summary, self::CACHE_TTL);
        }
        return $this->evaluate($summary);
    }

    /**
     * Apex and www host for the site host.
     *
     * @param string $host Home host.
     * @return array{apex:string,www:string}
     */
    public static function host_variants($host) {
        $host = strtolower((string) $host);
        $apex = strpos($host, 'www.') === 0 ? substr($host, 4) : $host;
        return array('apex' => $apex, 'www' => 'www.' . $apex);
    }

    /**
     * Follow each entry variant hop by hop.
     *
     * @param string $host Home host.
     * @return array<string,mixed>
     */
    private function probe($host) {
        $variants = self::host_variants($host);
        $starts   = array(
            'http://' . $variants['apex'] . '/',
            'http://' . $variants['www'] . '/',
            'https://' . $variants['apex'] . '/',
            'https://' . $variants['www'] . '/',
        );
        $chains = array();
        foreach ($starts as $start) {
            $chains[] = $this->follow($start, $variants['apex']);
        }
        return array('host' => $host, 'apex' => $variants['apex'], 'chains' => $chains);
    }

    /**
     * Follow one chain without letting the HTTP API redirect for us.
     *
     * @param string $start Start URL.
     * @param string $apex  Apex domain; only hosts inside it are requested.
     * @return array{start:string,hops:array,end:string}
     */
    private function follow($start, $apex) {
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
            $res = wp_remote_get(
                $url,
                array(
                    'timeout'             => 5,
                    'redirection'         => 0,
                    'limit_response_size' => 1024,
                )
            );
            if (is_wp_error($res)) {
                $end = count($hops) === 0 ? 'unreachable' : 'error';
                break;
            }
            $code     = (int) wp_remote_retrieve_response_code($res);
            $location = (string) wp_remote_retrieve_header($res, 'location');
            $hsts     = trim((string) wp_remote_retrieve_header($res, 'strict-transport-security')) !== '';
            $next     = ($code >= 300 && $code < 400 && $location !== '') ? self::resolve($url, $location) : '';
            $hops[]   = array(
                'url'      => $url,
                'status'   => $code,
                'hsts'     => $hsts,
                'location' => $next,
            );
            if ($next === '') {
                break;
            }
            $next_host = strtolower((string) wp_parse_url($next, PHP_URL_HOST));
            if (!self::in_domain($next_host, $apex)) {
                $end = 'external';
                break;
            }
            $url = $next;
        }
        return array('start' => $start, 'hops' => $hops, 'end' => $end);
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

    private static function in_domain($host, $apex) {
        if ($host === '' || $apex === '') {
            return false;
        }
        return $host === $apex || substr($host, -strlen('.' . $apex)) === '.' . $apex;
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
        $seen_hsts = array();

        foreach ((array) $summary['chains'] as $chain) {
            $hops = isset($chain['hops']) ? (array) $chain['hops'] : array();
            if (!$hops) {
                continue;
            }
            $first = $hops[0];
            $start = (string) $chain['start'];

            if (strpos($start, 'http://') === 0) {
                $this->check_http_entry($findings, $counts, $start, $first);
            }

            foreach ($hops as $i => $hop) {
                if (strpos((string) $hop['url'], 'https://') !== 0 || !empty($hop['hsts'])) {
                    continue;
                }
                $is_last  = $i === count($hops) - 1;
                $hop_host = strtolower((string) wp_parse_url($hop['url'], PHP_URL_HOST));
                // The final homepage response is already covered by the HSTS module.
                if ($is_last && $hop_host === $home_host && empty($hop['location'])) {
                    continue;
                }
                if (isset($seen_hsts[$hop['url']])) {
                    continue;
                }
                $seen_hsts[$hop['url']] = true;
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

            $last = $hops[count($hops) - 1];
            if ($chain['end'] === 'loop' || $chain['end'] === 'too_many') {
                $this->add(
                    $findings,
                    $counts,
                    'medium',
                    sprintf(
                        /* translators: 1: start URL, 2: maximum number of hops. */
                        __('The redirect chain from %1$s loops or needs more than %2$d hops. Redirect each variant in one or two steps.', 'nubivio-healthcare-security-hardening'),
                        $start,
                        self::MAX_HOPS
                    )
                );
            } elseif (
                $chain['end'] === 'ok'
                && empty($last['location'])
                && strpos((string) $last['url'], 'http://') === 0
                && count($hops) > 1
            ) {
                $this->add(
                    $findings,
                    $counts,
                    'high',
                    sprintf(
                        /* translators: 1: start URL, 2: final URL. */
                        __('The redirect chain from %1$s ends on plain HTTP (%2$s). Visitors are moved away from HTTPS.', 'nubivio-healthcare-security-hardening'),
                        $start,
                        $last['url']
                    )
                );
            }
        }

        return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
    }

    /**
     * Rules for an http:// entry point.
     */
    private function check_http_entry(&$findings, &$counts, $start, $first) {
        $status = (int) $first['status'];
        $next   = (string) $first['location'];
        if ($next === '') {
            if ($status >= 200 && $status < 300) {
                $this->add(
                    $findings,
                    $counts,
                    'high',
                    sprintf(
                        /* translators: %s: start URL. */
                        __('%s serves content over plain HTTP instead of redirecting to HTTPS.', 'nubivio-healthcare-security-hardening'),
                        $start
                    )
                );
            }
            return;
        }
        $start_host = strtolower((string) wp_parse_url($start, PHP_URL_HOST));
        $next_host  = strtolower((string) wp_parse_url($next, PHP_URL_HOST));
        $next_https = strpos($next, 'https://') === 0;

        if (!$next_https) {
            $this->add(
                $findings,
                $counts,
                'medium',
                sprintf(
                    /* translators: 1: start URL, 2: redirect target. */
                    __('%1$s redirects to %2$s over plain HTTP. Redirect to HTTPS on the same host first.', 'nubivio-healthcare-security-hardening'),
                    $start,
                    $next
                )
            );
        } elseif ($next_host !== $start_host) {
            $this->add(
                $findings,
                $counts,
                'medium',
                sprintf(
                    /* translators: 1: start URL, 2: redirect target, 3: expected https URL on the same host. */
                    __('%1$s redirects straight to %2$s. Redirect to %3$s first so that host can set HSTS; HSTS preload requires this order.', 'nubivio-healthcare-security-hardening'),
                    $start,
                    $next,
                    'https://' . $start_host . '/'
                )
            );
        }
        if ($status === 302 || $status === 303 || $status === 307) {
            $this->add(
                $findings,
                $counts,
                'low',
                sprintf(
                    /* translators: 1: start URL, 2: HTTP status code. */
                    __('%1$s uses a temporary redirect (HTTP %2$d) to HTTPS. Use a permanent redirect (301 or 308).', 'nubivio-healthcare-security-hardening'),
                    $start,
                    $status
                )
            );
        }
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
                'detail' => __('None of the http/https and www variants could be requested, so the redirect chain was not checked.', 'nubivio-healthcare-security-hardening'),
            );
        }
        $high   = isset($counts['high']) ? (int) $counts['high'] : 0;
        $medium = isset($counts['medium']) ? (int) $counts['medium'] : 0;
        $low    = isset($counts['low']) ? (int) $counts['low'] : 0;
        if ($high + $medium + $low === 0) {
            return array(
                'label'  => $label,
                'status' => 'pass',
                'detail' => __('All variants redirect to HTTPS correctly and every HTTPS hop sends HSTS.', 'nubivio-healthcare-security-hardening'),
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

    private function add(&$findings, &$counts, $severity, $message) {
        foreach ($findings as $existing) {
            if ($existing['message'] === $message) {
                return;
            }
        }
        $findings[]        = array('severity' => $severity, 'message' => $message, 'controls' => array('A.8.21', 'A.8.24'));
        $counts[$severity]++;
    }
}
