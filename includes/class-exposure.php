<?php
/**
 * Fingerprint and exposure scan of the site itself (v2.6.0).
 *
 * Checks what an outsider can learn from the public site: version
 * disclosure, WordPress core files, directory listing, leftover backup and
 * config files, user enumeration, XML-RPC and server banners.
 *
 * Safety rules:
 * - Only the site's own URLs (home_url, site_url, content_url) are
 *   requested. No third-party hosts.
 * - GET requests only, timeout 5 s, no redirects followed and at most 4 KB
 *   of body read per request.
 * - Response bodies are only matched against a fixed signature and are
 *   never stored. The cached summary holds paths, status codes and
 *   booleans only.
 * - If the homepage cannot be fetched (loopback blocked), every other HTTP
 *   probe is skipped instead of piling up timeouts.
 *
 * Results are cached for 6 hours in a transient, like the DNS module.
 *
 * @package Nubivio_HSH
 */
if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Exposure {

    const CACHE_TTL  = 21600;
    const BODY_LIMIT = 4096;

    /** @var Nubivio_HSH */
    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    public static function cache_key($host) {
        return 'nubivio_hsh_exposure_' . md5((string) $host);
    }

    public static function clear_cache($host) {
        delete_transient(self::cache_key($host));
    }

    /**
     * Run the exposure scan.
     *
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function run() {
        $host   = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        $key    = self::cache_key($host);
        $cached = get_transient($key);
        if (is_array($cached) && isset($cached['summary'])) {
            $summary = $cached['summary'];
        } else {
            $summary = $this->probe();
            // A blocked loopback is retried sooner than a completed scan.
            set_transient($key, array('summary' => $summary), !empty($summary['loopback']) ? self::CACHE_TTL : HOUR_IN_SECONDS);
        }
        return $this->evaluate($summary);
    }

    /**
     * Collect raw signals. Only paths, status codes and booleans are kept.
     *
     * @return array<string,mixed>
     */
    private function probe() {
        $summary = array(
            'loopback'         => false,
            'generator'        => false,
            'generator_inline' => false,
            'asset_version'    => false,
            'core_files'       => array(),
            'listing'          => array(),
            'remnants'         => array(),
            'rest_users'       => false,
            'author_enum'      => false,
            'xmlrpc'           => $this->xmlrpc_enabled(),
            'server'           => '',
            'powered_by'       => '',
            'requests'         => 0,
        );

        // In-process: is the generator meta tag still hooked into wp_head and not filtered away?
        if (function_exists('has_action') && has_action('wp_head', 'wp_generator') !== false) {
            $tag = function_exists('get_the_generator') ? get_the_generator('xhtml') : 'WordPress';
            $tag = apply_filters('the_generator', $tag, 'xhtml');
            $summary['generator_inline'] = trim((string) $tag) !== '';
        }

        $home = $this->fetch(home_url('/'), $summary);
        if ($home === null) {
            return $summary;
        }
        $summary['loopback'] = true;
        $wp_version          = $this->wp_version();
        $body                = $home['body'];
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*[\d.]+/i', $body)) {
            $summary['generator'] = true;
        }
        if ($wp_version !== '' && preg_match('/[?&]ver=' . preg_quote($wp_version, '/') . '(?![\d.])/', $body)) {
            $summary['asset_version'] = true;
        }
        $summary['server']     = $this->banner_with_version($home['headers'], 'server');
        $summary['powered_by'] = $this->banner_with_version($home['headers'], 'x-powered-by');

        $failures = 0;
        foreach ($this->probes() as $probe) {
            if ($failures >= 2) {
                break;
            }
            $res = $this->fetch($probe['url'], $summary);
            if ($res === null) {
                $failures++;
                continue;
            }
            $failures = 0;
            if ((int) $res['code'] !== 200 || !preg_match($probe['signature'], $res['body'])) {
                continue;
            }
            // Leftover files are never served as HTML; an HTML 200 is a catch-all page.
            $type = isset($res['headers']['content-type']) ? strtolower($res['headers']['content-type']) : '';
            if ($probe['group'] === 'remnant' && strpos($type, 'text/html') !== false) {
                continue;
            }
            $entry = array('path' => $probe['path'], 'type' => $probe['type']);
            if ($probe['group'] === 'core') {
                $summary['core_files'][] = $entry;
            } elseif ($probe['group'] === 'listing') {
                $summary['listing'][] = $entry;
            } else {
                $summary['remnants'][] = $entry;
            }
        }

        if ($failures < 2) {
            $users = $this->fetch(rest_url('wp/v2/users'), $summary);
            if ($users !== null && (int) $users['code'] === 200 && preg_match('/"slug"\s*:/', $users['body'])) {
                $summary['rest_users'] = true;
            }
            $author = $this->fetch(add_query_arg('author', '1', home_url('/')), $summary);
            if ($author !== null && in_array((int) $author['code'], array(301, 302, 307, 308), true)) {
                $summary['author_enum'] = (bool) preg_match('#/author/[^/?]+#i', (string) $author['location']);
            }
        }

        return $summary;
    }

    /**
     * Probe list. Every entry is a path on the site's own origin plus a
     * signature that the body must match, so catch-all 200 pages do not
     * produce false positives.
     *
     * @return array<int,array<string,string>>
     */
    private function probes() {
        $site    = untrailingslashit(site_url());
        $home    = untrailingslashit(home_url());
        $content = untrailingslashit(content_url());
        $config  = '/(DB_NAME|DB_PASSWORD|table_prefix)/';
        $title   = '/<title>\s*WordPress\s*(&rsaquo;|&#8250;|\x{203A})/iu';

        $list = array(
            array('group' => 'core', 'type' => 'readme', 'base' => $site, 'path' => '/readme.html', 'signature' => $title),
            array('group' => 'core', 'type' => 'license', 'base' => $site, 'path' => '/license.txt', 'signature' => '/WordPress - Web publishing software/i'),
            array('group' => 'core', 'type' => 'install', 'base' => $site, 'path' => '/wp-admin/install.php', 'signature' => $title),
            array('group' => 'listing', 'type' => 'listing', 'base' => $content, 'path' => '/uploads/', 'signature' => '/<title>\s*Index of \//i'),
            array('group' => 'listing', 'type' => 'listing', 'base' => $content, 'path' => '/plugins/', 'signature' => '/<title>\s*Index of \//i'),
            array('group' => 'remnant', 'type' => 'config', 'base' => $site, 'path' => '/wp-config.php.bak', 'signature' => $config),
            array('group' => 'remnant', 'type' => 'config', 'base' => $site, 'path' => '/wp-config.php~', 'signature' => $config),
            array('group' => 'remnant', 'type' => 'config', 'base' => $site, 'path' => '/wp-config.php.old', 'signature' => $config),
            array('group' => 'remnant', 'type' => 'config', 'base' => $site, 'path' => '/wp-config.php.save', 'signature' => $config),
            array('group' => 'remnant', 'type' => 'config', 'base' => $site, 'path' => '/wp-config.txt', 'signature' => $config),
            array('group' => 'remnant', 'type' => 'env', 'base' => $home, 'path' => '/.env', 'signature' => '/^[A-Z][A-Z0-9_]*=/m'),
            array('group' => 'remnant', 'type' => 'git', 'base' => $home, 'path' => '/.git/HEAD', 'signature' => '/^ref:\s*refs\//'),
            array('group' => 'remnant', 'type' => 'debug_log', 'base' => $content, 'path' => '/debug.log', 'signature' => '/PHP (Fatal|Warning|Notice|Deprecated|Parse)/'),
        );
        foreach ($list as $i => $probe) {
            $list[$i]['url'] = $probe['base'] . $probe['path'];
        }
        return $list;
    }

    /**
     * One GET request with the module's fixed safety limits.
     *
     * @param string $url     Own-site URL.
     * @param array  $summary Summary, request counter is increased.
     * @return array{code:int,headers:array,body:string,location:string}|null
     */
    private function fetch($url, &$summary) {
        $summary['requests']++;
        $res = wp_remote_get(
            $url,
            array(
                'timeout'             => 5,
                'redirection'         => 0,
                'limit_response_size' => self::BODY_LIMIT,
            )
        );
        if (is_wp_error($res)) {
            return null;
        }
        $headers = wp_remote_retrieve_headers($res);
        $headers = is_object($headers) && method_exists($headers, 'getAll') ? $headers->getAll() : (array) $headers;
        $lower   = array();
        foreach ($headers as $name => $value) {
            $lower[strtolower((string) $name)] = is_array($value) ? implode(', ', $value) : (string) $value;
        }
        return array(
            'code'     => (int) wp_remote_retrieve_response_code($res),
            'headers'  => $lower,
            'body'     => substr((string) wp_remote_retrieve_body($res), 0, self::BODY_LIMIT),
            'location' => isset($lower['location']) ? $lower['location'] : '',
        );
    }

    /**
     * Return a banner header only when it includes a version number.
     *
     * @param array  $headers Lower-cased header map.
     * @param string $name    Header name.
     * @return string
     */
    private function banner_with_version($headers, $name) {
        if (empty($headers[$name])) {
            return '';
        }
        $value = substr(trim((string) $headers[$name]), 0, 80);
        return preg_match('/\d+\.\d+/', $value) ? $value : '';
    }

    private function xmlrpc_enabled() {
        return (bool) apply_filters('xmlrpc_enabled', true);
    }

    private function wp_version() {
        global $wp_version;
        return isset($wp_version) ? (string) $wp_version : (string) get_bloginfo('version');
    }

    /**
     * Turn the summary into findings.
     *
     * @param array $summary Summary from probe().
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function evaluate($summary) {
        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);
        $config   = array('A.8.9');
        $leak     = array('A.8.9', 'A.8.12');

        if (!empty($summary['generator']) || !empty($summary['generator_inline'])) {
            $this->add(
                $findings,
                $counts,
                'low',
                __('The WordPress version is published in a generator meta tag. Remove it so scanners cannot match your version to known vulnerabilities.', 'nubivio-healthcare-security-hardening'),
                $config
            );
        }
        if (!empty($summary['asset_version'])) {
            $this->add(
                $findings,
                $counts,
                'low',
                __('Script and style URLs carry the WordPress version as ?ver=. This reveals the exact core version.', 'nubivio-healthcare-security-hardening'),
                $config
            );
        }
        foreach ((array) $summary['core_files'] as $file) {
            $this->add(
                $findings,
                $counts,
                'low',
                sprintf(
                    /* translators: %s: path such as /readme.html. */
                    __('%s is publicly reachable and identifies the site as WordPress. Block or remove it.', 'nubivio-healthcare-security-hardening'),
                    $file['path']
                ),
                $config
            );
        }
        foreach ((array) $summary['listing'] as $dir) {
            $this->add(
                $findings,
                $counts,
                'medium',
                sprintf(
                    /* translators: %s: directory path such as /uploads/. */
                    __('Directory listing is enabled for %s. Anyone can browse the files; disable listing in the web server (Options -Indexes).', 'nubivio-healthcare-security-hardening'),
                    'wp-content' . $dir['path']
                ),
                $leak
            );
        }
        foreach ((array) $summary['remnants'] as $file) {
            if ($file['type'] === 'debug_log') {
                $message = __(
                    'wp-content/debug.log is publicly downloadable. Debug logs can contain paths, queries and personal data. Delete it and set WP_DEBUG_LOG to a path outside the web root.',
                    'nubivio-healthcare-security-hardening'
                );
            } elseif ($file['type'] === 'git') {
                $message = __('A .git directory is publicly reachable. Source code and history can be downloaded. Block /.git in the web server.', 'nubivio-healthcare-security-hardening');
            } elseif ($file['type'] === 'env') {
                $message = __('A .env file is publicly reachable and may contain credentials. Remove it from the web root and rotate the secrets.', 'nubivio-healthcare-security-hardening');
            } else {
                $message = sprintf(
                    /* translators: %s: file path such as /wp-config.php.bak. */
                    __('%s is publicly downloadable and contains database settings. Delete it now and change the database password.', 'nubivio-healthcare-security-hardening'),
                    $file['path']
                );
            }
            $this->add($findings, $counts, 'high', $message, $leak);
        }
        if (!empty($summary['rest_users'])) {
            $this->add(
                $findings,
                $counts,
                'low',
                __('The REST API lists user accounts at /wp-json/wp/v2/users without login. Usernames make password attacks easier; restrict this endpoint.', 'nubivio-healthcare-security-hardening'),
                $leak
            );
        }
        if (!empty($summary['author_enum'])) {
            $this->add(
                $findings,
                $counts,
                'low',
                __('/?author=1 redirects to an author page and reveals a username. Consider blocking author enumeration.', 'nubivio-healthcare-security-hardening'),
                $leak
            );
        }
        if (!empty($summary['xmlrpc'])) {
            $this->add(
                $findings,
                $counts,
                'low',
                __('XML-RPC is enabled. If you do not use the WordPress mobile app, Jetpack or remote publishing, disable it to reduce the attack surface.', 'nubivio-healthcare-security-hardening'),
                $config
            );
        }
        foreach (array('server' => 'Server', 'powered_by' => 'X-Powered-By') as $field => $header) {
            if (!empty($summary[$field])) {
                $this->add(
                    $findings,
                    $counts,
                    'low',
                    sprintf(
                        /* translators: 1: header name, 2: header value. */
                        __('The %1$s header reveals software and version (%2$s). Hide version numbers in the web server or PHP configuration.', 'nubivio-healthcare-security-hardening'),
                        $header,
                        $summary[$field]
                    ),
                    $config
                );
            }
        }

        return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
    }

    /**
     * Row for the plugin's own Site health card.
     *
     * @param array $result Result of run().
     * @return array{label:string,status:string,detail:string}
     */
    public static function health_row($result) {
        $label   = __('Exposure scan', 'nubivio-healthcare-security-hardening');
        $summary = isset($result['summary']) ? (array) $result['summary'] : array();
        $counts  = isset($result['counts']) ? (array) $result['counts'] : array();
        if (empty($summary['loopback'])) {
            return array(
                'label'  => $label,
                'status' => 'warn',
                'detail' => __('The site could not request its own homepage, so the HTTP exposure checks were skipped.', 'nubivio-healthcare-security-hardening'),
            );
        }
        $high   = isset($counts['high']) ? (int) $counts['high'] : 0;
        $medium = isset($counts['medium']) ? (int) $counts['medium'] : 0;
        $low    = isset($counts['low']) ? (int) $counts['low'] : 0;
        if ($high + $medium + $low === 0) {
            return array(
                'label'  => $label,
                'status' => 'pass',
                'detail' => __('No version disclosure, leftover files or user enumeration found.', 'nubivio-healthcare-security-hardening'),
            );
        }
        return array(
            'label'  => $label,
            'status' => $high > 0 ? 'fail' : 'warn',
            'detail' => sprintf(
                /* translators: 1: high findings, 2: medium findings, 3: low findings. */
                __('Exposure findings: %1$d high, %2$d medium, %3$d low.', 'nubivio-healthcare-security-hardening'),
                $high,
                $medium,
                $low
            ),
        );
    }

    private function add(&$findings, &$counts, $severity, $message, $controls = array()) {
        $findings[]        = array('severity' => $severity, 'message' => $message, 'controls' => $controls);
        $counts[$severity]++;
    }
}
