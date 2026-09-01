<?php
/**
 * CSP report-only inventory, endpoint, and SRI detector.
 *
 * @package Nubivio_HSH
 */
if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Csp {

    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    public function run() {
        $o        = $this->core->get_options();
        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);
        $sri      = $this->audit_sri();

        if (!empty($sri['candidates'])) {
            $n          = count($sri['candidates']);
            $findings[] = array(
                'severity' => 'low',
                'message'  => sprintf(
                    _n(
                        '%d external script is a candidate for Subresource Integrity. Consider pinning it with `integrity` attributes.',
                        '%d external scripts are candidates for Subresource Integrity. Consider pinning them with `integrity` attributes.',
                        $n,
                        'nubivio-healthcare-security-hardening'
                    ),
                    $n
                ),
            );
            $counts['low']++;
        }

        $policy_string = $this->build_policy_string($o);
        $grade         = $this->grade_policy($policy_string);
        if ($grade['score'] < 70) {
            $findings[] = array(
                'severity' => 'low',
                'message'  => sprintf(
                    /* translators: 1: grade letter, 2: numeric score. */
                    __('Current CSP effectiveness is %1$s (%2$d/100); review the listed issues to strengthen the policy.', 'nubivio-healthcare-security-hardening'),
                    $grade['grade'],
                    (int) $grade['score']
                ),
            );
            $counts['low']++;
        }

        return array(
            'findings' => $findings,
            'counts'   => $counts,
            'summary'  => array(
                'enabled'        => !empty($o['csp_enabled']),
                'inventory_at'   => isset($o['csp_inventory_at']) ? (int) $o['csp_inventory_at'] : 0,
                'inline_scripts' => isset($o['csp_inline_scripts']) ? (int) $o['csp_inline_scripts'] : 0,
                'seen_hosts'     => isset($o['csp_seen_hosts']) ? (array) $o['csp_seen_hosts'] : array(),
                'violations'     => isset($o['csp_violations']) ? (array) $o['csp_violations'] : array(),
                'sri'            => $sri,
                'grade'          => $grade,
                'policy_string'  => $policy_string,
            ),
        );
    }

    public function refresh_inventory() {
        delete_transient('nubivio_hsh_csp_html_' . md5((string) home_url('/')));
        return $this->run_inventory_scan();
    }

    public function run_inventory_scan() {
        $key  = 'nubivio_hsh_csp_html_' . md5((string) home_url('/'));
        $html = get_transient($key);
        if (!is_string($html)) {
            $res = wp_remote_get(home_url('/'), array(
                'timeout'    => 10,
                'user-agent' => 'Nubivio-HSH/2.4 inventory',
            ));
            if (is_wp_error($res)) {
                return false;
            }
            $html = (string) wp_remote_retrieve_body($res);
            set_transient($key, $html, DAY_IN_SECONDS);
        }

        $hosts = array(
            'script-src'  => array(),
            'style-src'   => array(),
            'font-src'    => array(),
            'img-src'     => array(),
            'frame-src'   => array(),
            'connect-src' => array(),
        );
        $site           = $this->registered_site_host();
        $inline_scripts = 0;

        if (class_exists('DOMDocument')) {
            $previous = libxml_use_internal_errors(true);
            $dom      = new DOMDocument();
            $dom->loadHTML($html);
            libxml_clear_errors();
            libxml_use_internal_errors($previous);

            foreach ($dom->getElementsByTagName('script') as $node) {
                if ($node->getAttribute('src') === '') {
                    $inline_scripts++;
                } else {
                    $this->add_host($hosts['script-src'], $node->getAttribute('src'));
                }
            }
            foreach ($dom->getElementsByTagName('link') as $node) {
                $rel  = strtolower($node->getAttribute('rel'));
                $href = $node->getAttribute('href');
                if (strpos($rel, 'stylesheet') !== false) {
                    $this->add_host($hosts['style-src'], $href);
                }
                if (strpos($rel, 'preload') !== false && strtolower($node->getAttribute('as')) === 'font') {
                    $this->add_host($hosts['font-src'], $href);
                }
            }
            foreach ($dom->getElementsByTagName('img') as $node) {
                $this->add_host($hosts['img-src'], $node->getAttribute('src'));
            }
            foreach ($dom->getElementsByTagName('iframe') as $node) {
                $this->add_host($hosts['frame-src'], $node->getAttribute('src'));
            }
        }

        if (preg_match_all('/@font-face[^}]*url\(([^)]+)\)/i', $html, $m)) {
            foreach ($m[1] as $url) {
                $this->add_host($hosts['font-src'], trim($url, " \t\"'"));
            }
        }

        foreach ($hosts as $directive => $list) {
            $filtered = array_values(array_filter(
                array_unique($list),
                function ($h) use ($site) {
                    return $h !== '' && $h !== $site;
                }
            ));
            $hosts[$directive] = array_slice($filtered, 0, 50);
        }

        $o = $this->core->get_options();
        $o['csp_seen_hosts']     = $hosts;
        $o['csp_inline_scripts'] = $inline_scripts;
        $o['csp_inventory_at']   = time();
        update_option(Nubivio_HSH::OPTION, $o);
        return true;
    }

    public function emit_report_only_header() {
        if (is_admin()) {
            return;
        }
        $o = $this->core->get_options();
        if (empty($o['csp_enabled']) || empty($o['csp_inventory_at'])) {
            return;
        }
        $policy = $this->build_policy_string($o);
        header('Content-Security-Policy-Report-Only: ' . preg_replace('/\s+/', ' ', trim($policy)), true);
    }

    /**
     * Build the CSP policy string from options and inventoried hosts.
     *
     * The output is a single-line policy suitable for either the
     * `Content-Security-Policy-Report-Only` or the enforcing
     * `Content-Security-Policy` header, depending on the caller.
     *
     * @param array $o Plugin options array.
     * @return string CSP policy string.
     */
    public function build_policy_string($o) {
        $seen = isset($o['csp_seen_hosts']) ? (array) $o['csp_seen_hosts'] : array();

        $part = function ($directive) use ($seen) {
            $hosts = isset($seen[$directive]) ? (array) $seen[$directive] : array();
            $out   = array();
            foreach ($hosts as $host) {
                $host = $this->header_host($host);
                if ($host !== '') {
                    $out[] = 'https://' . $host;
                }
            }
            return implode(' ', array_unique($out));
        };

        $policy = "default-src 'self'; "
            . "script-src 'self' " . $part('script-src') . '; '
            . "style-src 'self' 'unsafe-inline' " . $part('style-src') . '; '
            . "img-src 'self' data: https: " . $part('img-src') . '; '
            . "font-src 'self' data: " . $part('font-src') . '; '
            . "connect-src 'self' " . $part('connect-src') . '; '
            . 'frame-src ' . $part('frame-src') . '; '
            . "frame-ancestors 'none'; "
            . "base-uri 'self'; "
            . "object-src 'none'; "
            . 'report-uri /wp-json/nubivio-hsh/v1/csp-report';

        return preg_replace('/\s+/', ' ', trim($policy));
    }

    /**
     * Grade a CSP policy string on effectiveness.
     *
     * Deducts points from a baseline of 100 for known weakening patterns
     * (`unsafe-inline`, wildcards, JSONP-bypass hosts, missing hardening
     * directives, ...). Returns a grade letter, the raw score and the list
     * of issues that were detected. This is a heuristic, not a formal audit.
     *
     * @param string $policy_string CSP policy string.
     * @return array{grade:string,score:int,issues:array<int,string>}
     */
    public function grade_policy($policy_string) {
        $score  = 100;
        $issues = array();
        $policy = (string) $policy_string;

        $directives = array();
        foreach (preg_split('/;\s*/', $policy) as $chunk) {
            $chunk = trim($chunk);
            if ($chunk === '') {
                continue;
            }
            $parts = preg_split('/\s+/', $chunk);
            $name  = strtolower((string) array_shift($parts));
            if ($name === '') {
                continue;
            }
            $directives[$name] = $parts;
        }

        $script_src = isset($directives['script-src']) ? $directives['script-src'] : array();
        $style_src  = isset($directives['style-src']) ? $directives['style-src'] : array();

        if (in_array("'unsafe-inline'", $script_src, true)) {
            $score   -= 25;
            $issues[] = __("script-src allows 'unsafe-inline'", 'nubivio-healthcare-security-hardening');
        }
        if (in_array("'unsafe-eval'", $script_src, true)) {
            $score   -= 25;
            $issues[] = __("script-src allows 'unsafe-eval'", 'nubivio-healthcare-security-hardening');
        }
        if (in_array('*', $script_src, true) || in_array('*', $style_src, true)) {
            $score   -= 20;
            $issues[] = __('script-src or style-src uses wildcard (*) source', 'nubivio-healthcare-security-hardening');
        }
        if (in_array('data:', $script_src, true)) {
            $score   -= 15;
            $issues[] = __('script-src allows data: URIs', 'nubivio-healthcare-security-hardening');
        }
        if (in_array('blob:', $script_src, true)) {
            $score   -= 10;
            $issues[] = __('script-src allows blob: URIs', 'nubivio-healthcare-security-hardening');
        }

        foreach ($script_src as $src) {
            if (stripos($src, 'http://') === 0) {
                $score   -= 10;
                $issues[] = sprintf(
                    /* translators: %s: plaintext HTTP source in CSP. */
                    __('script-src includes non-HTTPS source %s', 'nubivio-healthcare-security-hardening'),
                    $src
                );
                break;
            }
        }
        foreach ($style_src as $src) {
            if (stripos($src, 'http://') === 0) {
                $score   -= 10;
                $issues[] = sprintf(
                    /* translators: %s: plaintext HTTP source in CSP. */
                    __('style-src includes non-HTTPS source %s', 'nubivio-healthcare-security-hardening'),
                    $src
                );
                break;
            }
        }

        $bypass_hosts = array('googleapis.com', 'ajax.googleapis.com', 'cdnjs.cloudflare.com');
        foreach ($bypass_hosts as $host) {
            foreach ($script_src as $src) {
                if ($this->script_src_matches_host($src, $host)) {
                    $score   -= 10;
                    $issues[] = sprintf(
                        /* translators: %s: JSONP-bypass host name. */
                        __('script-src allows JSONP-bypass host %s without a path restriction', 'nubivio-healthcare-security-hardening'),
                        $host
                    );
                    break;
                }
            }
        }

        if (!isset($directives['form-action'])) {
            $score   -= 5;
            $issues[] = __('form-action directive is missing', 'nubivio-healthcare-security-hardening');
        }
        $object_src = isset($directives['object-src']) ? $directives['object-src'] : array();
        if (!in_array("'none'", $object_src, true)) {
            $score   -= 5;
            $issues[] = __("object-src 'none' directive is missing", 'nubivio-healthcare-security-hardening');
        }

        if ($score < 0) {
            $score = 0;
        }
        if ($score > 100) {
            $score = 100;
        }
        if ($score >= 85) {
            $grade = 'A';
        } elseif ($score >= 70) {
            $grade = 'B';
        } elseif ($score >= 55) {
            $grade = 'C';
        } elseif ($score >= 40) {
            $grade = 'D';
        } else {
            $grade = 'F';
        }

        return array('grade' => $grade, 'score' => (int) $score, 'issues' => $issues);
    }

    /**
     * Determine whether a script-src entry matches a JSONP-bypass host
     * without a path restriction (path restrictions materially reduce risk).
     *
     * @param string $src  Single script-src entry.
     * @param string $host Bypass host name to match against.
     * @return bool True when the host is present without a path.
     */
    private function script_src_matches_host($src, $host) {
        $entry = trim((string) $src);
        if ($entry === '' || $entry[0] === "'") {
            return false;
        }
        $entry_host = $entry;
        if (strpos($entry_host, '://') !== false) {
            $entry_host = (string) wp_parse_url($entry, PHP_URL_HOST);
            $path       = (string) wp_parse_url($entry, PHP_URL_PATH);
            if ($path !== '' && $path !== '/') {
                return false;
            }
        } elseif (strpos($entry_host, '/') !== false) {
            return false;
        }
        return strtolower($entry_host) === strtolower($host);
    }

    public function register_route() {
        register_rest_route('nubivio-hsh/v1', '/csp-report', array(
            'methods'             => 'POST',
            'callback'            => array($this, 'handle_report'),
            'permission_callback' => '__return_true',
        ));
    }

    public function handle_report($request) {
        $ip   = !empty($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'unknown';
        $key  = 'nubivio_hsh_csp_rl_' . md5($ip);
        $rate = get_transient($key);
        $rate = is_array($rate) ? $rate : array('count' => 0);
        $rate['count']++;
        set_transient($key, $rate, MINUTE_IN_SECONDS);
        if ($rate['count'] > 100) {
            return new WP_REST_Response(null, 429);
        }

        $body = method_exists($request, 'get_body') ? $request->get_body() : '';
        $data = json_decode($body, true);
        if (isset($data['csp-report'])) {
            $data = $data['csp-report'];
        }
        if (isset($data[0]) && is_array($data[0])) {
            $data = isset($data[0]['body']) ? $data[0]['body'] : $data[0];
        }
        if (!is_array($data)) {
            return new WP_REST_Response(null, 204);
        }

        $doc       = isset($data['document-uri']) ? (string) $data['document-uri'] : '';
        $blocked   = isset($data['blocked-uri']) ? (string) $data['blocked-uri'] : '';
        $directive = isset($data['effective-directive'])
            ? (string) $data['effective-directive']
            : (isset($data['violated-directive']) ? (string) $data['violated-directive'] : '');

        $is_extension    = (bool) preg_match('#^(chrome-extension|moz-extension|safari-web-extension)://#i', $blocked);
        $is_bare_scheme  = in_array($blocked, array('data:', 'blob:'), true) && $doc === '';
        $doc_host_ok     = strtolower((string) wp_parse_url($doc, PHP_URL_HOST)) === $this->site_host();
        if ($is_extension || $is_bare_scheme || !$doc_host_ok) {
            return new WP_REST_Response(null, 204);
        }

        $o     = $this->core->get_options();
        $items = isset($o['csp_violations']) && is_array($o['csp_violations']) ? $o['csp_violations'] : array();
        $now   = time();
        $found = false;
        foreach ($items as &$item) {
            if (
                isset($item['directive'], $item['blocked_uri'])
                && $item['directive'] === $directive
                && $item['blocked_uri'] === $blocked
            ) {
                $item['last_seen'] = $now;
                $item['count']     = isset($item['count']) ? (int) $item['count'] + 1 : 1;
                $found             = true;
                break;
            }
        }
        unset($item);

        if (!$found) {
            $items[] = array(
                'directive'           => $directive,
                'blocked_uri'         => $blocked,
                'first_seen'          => $now,
                'last_seen'           => $now,
                'count'               => 1,
                'sample_document_uri' => $doc,
                'sample_ua'           => substr(
                    isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '',
                    0,
                    200
                ),
            );
        }

        usort($items, function ($a, $b) {
            return (int) $b['count'] <=> (int) $a['count'];
        });
        $o['csp_violations'] = array_slice($items, 0, 200);
        update_option(Nubivio_HSH::OPTION, $o);
        return new WP_REST_Response(null, 204);
    }

    public function add_to_allowlist($directive, $blocked) {
        $host    = $this->host_from_url($blocked);
        $allowed = array('script-src', 'style-src', 'font-src', 'img-src', 'frame-src', 'connect-src');
        if ($host === '' || !in_array($directive, $allowed, true)) {
            return false;
        }
        $o = $this->core->get_options();
        if (!isset($o['csp_seen_hosts']) || !is_array($o['csp_seen_hosts'])) {
            $o['csp_seen_hosts'] = array();
        }
        if (!isset($o['csp_seen_hosts'][$directive]) || !is_array($o['csp_seen_hosts'][$directive])) {
            $o['csp_seen_hosts'][$directive] = array();
        }
        if (!in_array($host, $o['csp_seen_hosts'][$directive], true)) {
            $o['csp_seen_hosts'][$directive][] = $host;
        }
        $o['csp_seen_hosts'][$directive] = array_slice($o['csp_seen_hosts'][$directive], 0, 50);
        update_option(Nubivio_HSH::OPTION, $o);
        return true;
    }

    public function audit_sri() {
        $key  = 'nubivio_hsh_csp_html_' . md5((string) home_url('/'));
        $html = get_transient($key);
        $out  = array('dynamic' => array(), 'candidates' => array());
        if (!is_string($html) || $html === '') {
            return $out;
        }
        $patterns = apply_filters('nubivio_hsh_sri_dynamic_hosts', array(
            'googletagmanager.com',
            'google-analytics.com',
            'googleadservices.com',
            'facebook.net',
            'connect.facebook.net',
            'hotjar.com',
            'intercom.io',
            'intercomcdn.com',
            'hs-scripts.com',
            'hs-analytics.net',
            'hsforms.net',
            'linkedin.com/analytics',
            'bing.com',
            'clarity.ms',
            'mixpanel.com',
            'segment.com',
            'segment.io',
            'fullstory.com',
            'cloudflareinsights.com',
            'usercentrics.com',
            'cookiebot.com',
            'iubenda.com',
        ));

        $urls = array();
        if (preg_match_all('/<(?:script|link)\b[^>]+(?:src|href)=["\']([^"\']+)["\'][^>]*>/i', $html, $m)) {
            $urls = $m[1];
        }
        foreach (array_unique($urls) as $url) {
            $host = $this->host_from_url($url);
            if ($host === '' || $host === $this->registered_site_host()) {
                continue;
            }
            $dynamic = false;
            foreach ((array) $patterns as $p) {
                if (strpos($host, (string) $p) !== false) {
                    $dynamic = true;
                    break;
                }
            }
            if ($dynamic) {
                $out['dynamic'][] = $url;
            } else {
                $out['candidates'][] = $url;
            }
        }
        return $out;
    }

    private function add_host(&$list, $url) {
        $host = $this->host_from_url($url);
        if ($host !== '' && !in_array($host, $list, true) && count($list) < 50) {
            $list[] = $host;
        }
    }

    private function host_from_url($url) {
        $url = trim((string) $url);
        if ($url === '' || preg_match('#^(data:|blob:|about:)#i', $url)) {
            return '';
        }
        if (strpos($url, '//') === 0) {
            $url = 'https:' . $url;
        }
        if (strpos($url, '://') === false) {
            return '';
        }
        $host = strtolower((string) wp_parse_url($url, PHP_URL_HOST));
        if ($host === '') {
            return '';
        }
        $parts = explode('.', $host);
        return count($parts) > 2 ? implode('.', array_slice($parts, -2)) : $host;
    }

    private function header_host($host) {
        return preg_replace('/[^a-z0-9.-]/i', '', strtolower((string) $host));
    }

    private function site_host() {
        return strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
    }

    private function registered_site_host() {
        return $this->registered_host($this->site_host());
    }

    private function registered_host($host) {
        $parts = explode('.', strtolower((string) $host));
        return count($parts) > 2 ? implode('.', array_slice($parts, -2)) : (string) $host;
    }
}
