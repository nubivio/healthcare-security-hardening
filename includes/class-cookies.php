<?php
/**
 * Pre-consent cookie and tracker analysis.
 *
 * Reads the response the site sends to an unauthenticated visitor and parses
 * every Set-Cookie header for the usual attribute mistakes. Also scans the
 * HTML for well-known tracker hosts and reports a high finding when trackers
 * fire without an active consent-management plugin. This analysis only sees
 * what the server emits; cookies that JavaScript sets after page load are
 * outside its reach and that limitation is surfaced as an information line.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Cookies {

    /** @var Nubivio_HSH */
    private $core;

    /**
     * Tracker host substrings. Keep in sync with the default list behind the
     * nubivio_hsh_sri_dynamic_hosts filter in class-csp.php.
     */
    const TRACKER_HOSTS = array(
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
    );

    /**
     * Consent-management plugins recognised by slug.
     */
    const CONSENT_PLUGINS = array(
        'cookie-notice/cookie-notice.php',
        'complianz-gdpr/complianz-gpdr.php',
        'cookie-law-info/cookie-law-info.php',
        'borlabs-cookie/borlabs-cookie.php',
        'real-cookie-banner/real-cookie-banner.php',
        'iubenda-cookie-law-solution/iubenda_cookie_solution.php',
        'usercentrics-cmp/usercentrics-cmp.php',
    );

    public function __construct($core) {
        $this->core = $core;
    }

    /**
     * Run the cookie and tracker analysis.
     *
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function run() {
        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);
        $summary  = array(
            'cookies'        => array(),
            'trackers'       => array(),
            'consent_plugin' => '',
            'html_fetched'   => false,
        );

        $fetch = $this->fetch_home();
        $summary['html_fetched'] = !empty($fetch['ok']);
        $html    = isset($fetch['html']) ? (string) $fetch['html'] : '';
        $cookies = $this->parse_cookies(isset($fetch['set_cookie']) ? $fetch['set_cookie'] : array());
        $summary['cookies']  = $cookies;
        $summary['trackers'] = $this->detect_trackers($html);
        $summary['consent_plugin'] = $this->detect_consent_plugin();

        $is_https = wp_parse_url(home_url(), PHP_URL_SCHEME) === 'https';
        foreach ($cookies as $c) {
            $this->grade_cookie($c, $is_https, $findings, $counts);
        }

        if (!empty($summary['trackers']) && $summary['consent_plugin'] === '') {
            $this->add(
                $findings,
                $counts,
                'high',
                __(
                    'Trackers were loaded but no consent-plugin is active. This is almost certainly a GDPR violation.',
                    'nubivio-healthcare-security-hardening'
                )
            );
        }
        foreach ($summary['trackers'] as $host) {
            $this->add(
                $findings,
                $counts,
                'low',
                sprintf(
                    /* translators: %s: tracker host. */
                    __(
                        'Tracker detected before a consent mechanism: %s. Verify this script only loads after explicit opt-in (GDPR art. 6, ePrivacy).',
                        'nubivio-healthcare-security-hardening'
                    ),
                    $host
                )
            );
        }

        // Always-present information line about the limits of this passive check.
        $findings[] = array(
            'severity' => 'info',
            'message'  => __(
                'This analysis reads what the server sends. Cookies set later by JavaScript are not visible here.',
                'nubivio-healthcare-security-hardening'
            ),
        );

        return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
    }

    /**
     * Health-check row for the site-health tab.
     *
     * @param array $summary Summary from run().
     * @return array{label:string,status:string,detail:string}
     */
    public static function health_row($summary) {
        $trackers = isset($summary['trackers']) ? (array) $summary['trackers'] : array();
        $consent  = isset($summary['consent_plugin']) ? (string) $summary['consent_plugin'] : '';
        $cookies  = isset($summary['cookies']) ? (array) $summary['cookies'] : array();

        $bad = false;
        foreach ($cookies as $c) {
            if (empty($c['secure']) || empty($c['samesite'])) {
                $bad = true;
                break;
            }
        }
        if (!empty($trackers) && $consent === '') {
            $bad = true;
        }
        return array(
            'label'  => __('Cookies and trackers', 'nubivio-healthcare-security-hardening'),
            'status' => $bad ? 'warn' : 'pass',
            'detail' => $bad
                ? __('Attribute or consent issues detected on the home response.', 'nubivio-healthcare-security-hardening')
                : __('No pre-consent cookie or tracker issues detected.', 'nubivio-healthcare-security-hardening'),
        );
    }

    /**
     * Fetch the site home over the loopback, reuse the CSP transient when it holds body.
     *
     * @return array{ok:bool,html:string,set_cookie:array}
     */
    private function fetch_home() {
        $out = array('ok' => false, 'html' => '', 'set_cookie' => array());

        $key = 'nubivio_hsh_cookies_html_' . md5((string) home_url('/'));
        $cached = get_transient($key);
        if (is_array($cached) && isset($cached['html'], $cached['set_cookie'])) {
            return array(
                'ok'         => true,
                'html'       => (string) $cached['html'],
                'set_cookie' => (array) $cached['set_cookie'],
            );
        }

        $res = wp_remote_get(
            home_url('/'),
            array(
                'timeout'    => 8,
                'user-agent' => 'Nubivio-HSH/2.5 cookies',
            )
        );
        if (is_wp_error($res)) {
            return $out;
        }
        $body = (string) wp_remote_retrieve_body($res);
        $raw  = wp_remote_retrieve_header($res, 'set-cookie');
        $set  = array();
        if (is_array($raw)) {
            $set = $raw;
        } elseif (is_string($raw) && $raw !== '') {
            $set = array($raw);
        }
        set_transient($key, array('html' => $body, 'set_cookie' => $set), 6 * HOUR_IN_SECONDS);
        return array('ok' => true, 'html' => $body, 'set_cookie' => $set);
    }

    /**
     * Parse an array of Set-Cookie header strings into attribute records.
     *
     * @param array $headers
     * @return array<int,array<string,mixed>>
     */
    private function parse_cookies($headers) {
        $out = array();
        foreach ((array) $headers as $header) {
            $header = (string) $header;
            if ($header === '') {
                continue;
            }
            $parts = array_map('trim', explode(';', $header));
            if (empty($parts)) {
                continue;
            }
            $first = array_shift($parts);
            $eq    = strpos($first, '=');
            $name  = $eq === false ? $first : substr($first, 0, $eq);
            $entry = array(
                'name'     => trim($name),
                'secure'   => false,
                'httponly' => false,
                'samesite' => '',
                'domain'   => '',
                'max_age'  => null,
                'expires'  => null,
            );
            foreach ($parts as $p) {
                $peq = strpos($p, '=');
                $key = strtolower($peq === false ? $p : substr($p, 0, $peq));
                $val = $peq === false ? '' : trim(substr($p, $peq + 1));
                if ($key === 'secure') {
                    $entry['secure'] = true;
                } elseif ($key === 'httponly') {
                    $entry['httponly'] = true;
                } elseif ($key === 'samesite') {
                    $entry['samesite'] = $val;
                } elseif ($key === 'domain') {
                    $entry['domain'] = ltrim($val, '.');
                } elseif ($key === 'max-age') {
                    $entry['max_age'] = (int) $val;
                } elseif ($key === 'expires') {
                    $ts = strtotime($val);
                    $entry['expires'] = $ts === false ? null : $ts;
                }
            }
            if ($entry['name'] !== '') {
                $out[] = $entry;
            }
        }
        return $out;
    }

    /**
     * Emit findings for one parsed cookie record.
     */
    private function grade_cookie($c, $is_https, &$findings, &$counts) {
        $name = (string) $c['name'];
        if ($is_https && empty($c['secure'])) {
            $this->add(
                $findings,
                $counts,
                'high',
                sprintf(
                    /* translators: %s: cookie name. */
                    __(
                        'Cookie %s is missing the Secure attribute on an HTTPS site; it can be intercepted on an unencrypted connection.',
                        'nubivio-healthcare-security-hardening'
                    ),
                    $name
                )
            );
        }
        if ($this->looks_like_auth($name) && empty($c['httponly'])) {
            $this->add(
                $findings,
                $counts,
                'medium',
                sprintf(
                    /* translators: %s: cookie name. */
                    __('Authentication cookie %s is missing the HttpOnly attribute.', 'nubivio-healthcare-security-hardening'),
                    $name
                )
            );
        }
        if ($c['samesite'] === '') {
            $this->add(
                $findings,
                $counts,
                'medium',
                sprintf(
                    /* translators: %s: cookie name. */
                    __(
                        'Cookie %s has no SameSite attribute; behaviour is browser-dependent.',
                        'nubivio-healthcare-security-hardening'
                    ),
                    $name
                )
            );
        } elseif (strcasecmp($c['samesite'], 'none') === 0 && empty($c['secure'])) {
            $this->add(
                $findings,
                $counts,
                'high',
                sprintf(
                    /* translators: %s: cookie name. */
                    __(
                        'Cookie %s uses SameSite=None without Secure; modern browsers reject it.',
                        'nubivio-healthcare-security-hardening'
                    ),
                    $name
                )
            );
        }
        $lifetime = $this->cookie_lifetime($c);
        if ($lifetime !== null && $lifetime > YEAR_IN_SECONDS) {
            $this->add(
                $findings,
                $counts,
                'low',
                sprintf(
                    /* translators: %s: cookie name. */
                    __('Cookie %s has a lifetime longer than one year.', 'nubivio-healthcare-security-hardening'),
                    $name
                )
            );
        }
        if ($c['domain'] !== '' && !$this->same_registrable_domain($c['domain'])) {
            $this->add(
                $findings,
                $counts,
                'medium',
                sprintf(
                    /* translators: 1: cookie name, 2: cookie domain. */
                    __(
                        'Cookie %1$s is scoped to the third-party domain %2$s.',
                        'nubivio-healthcare-security-hardening'
                    ),
                    $name,
                    $c['domain']
                )
            );
        }
    }

    private function looks_like_auth($name) {
        $needles = array('wordpress_logged_in', 'wordpress_sec', 'wp-settings');
        foreach ($needles as $n) {
            if (stripos($name, $n) !== false) {
                return true;
            }
        }
        return (bool) preg_match('/session|auth|token/i', $name);
    }

    private function cookie_lifetime($c) {
        if ($c['max_age'] !== null) {
            return (int) $c['max_age'];
        }
        if ($c['expires'] !== null) {
            return (int) $c['expires'] - time();
        }
        return null;
    }

    private function same_registrable_domain($domain) {
        $home = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        $d    = strtolower((string) $domain);
        if ($home === '' || $d === '') {
            return true;
        }
        if ($home === $d) {
            return true;
        }
        return (substr($home, -strlen($d) - 1) === '.' . $d) || (substr($d, -strlen($home) - 1) === '.' . $home);
    }

    /**
     * Return the tracker hosts detected in the fetched HTML.
     *
     * @param string $html
     * @return array<int,string>
     */
    private function detect_trackers($html) {
        $found = array();
        if ($html === '') {
            return $found;
        }
        foreach (self::TRACKER_HOSTS as $host) {
            if (stripos($html, $host) !== false && !in_array($host, $found, true)) {
                $found[] = $host;
            }
        }
        return $found;
    }

    private function detect_consent_plugin() {
        if (!function_exists('is_plugin_active')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        foreach (self::CONSENT_PLUGINS as $slug) {
            if (is_plugin_active($slug)) {
                return $slug;
            }
        }
        return '';
    }

    private function add(&$findings, &$counts, $severity, $message) {
        $findings[] = array('severity' => $severity, 'message' => $message);
        if (isset($counts[$severity])) {
            $counts[$severity]++;
        }
    }
}
