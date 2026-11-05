<?php
/**
 * Fingerprint and exposure scan of the site itself (v2.6.0).
 *
 * Checks what an outsider can learn from the public site: WordPress core
 * files, the generator tag, user enumeration, a browsable uploads folder
 * and leftover files such as .git, .env, debug.log and wp-config backups.
 *
 * Safety rules:
 * - Only GET requests to the site's own home_url(). No third-party hosts.
 * - Timeout 8 s, no redirects followed, at most 4 KB of body read, fixed
 *   user agent "Nubivio-HSH/2.6 exposure", at most 15 requests per scan.
 * - Runs only from the manual scan or the existing scan cron; the result is
 *   cached for 12 hours.
 * - Response bodies are matched once and never stored. The cached summary
 *   holds path, status code and yes/no only. Usernames are never stored.
 * - The generator tag is read from the homepage HTML that the CSP inventory
 *   already caches, so it costs no extra request.
 *
 * Overlap with class-health.php: XML-RPC and REST user enumeration also
 * appear there as site health rows. The REST users request is made here
 * once and class-health.php reuses the cached answer. /xmlrpc.php is only
 * probed when the xmlrpc_enabled filter says it is off, because health
 * already reports the "on" case.
 *
 * Advice is always a manual step. Nothing is changed and no .htaccess rules
 * are written.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Exposure {

    const CACHE_TTL    = 43200;
    const BODY_LIMIT   = 4096;
    const TIMEOUT      = 8;
    const MAX_REQUESTS = 15;
    const USER_AGENT   = 'Nubivio-HSH/2.6 exposure';

    /** @var Nubivio_HSH|null */
    private $core;

    /**
     * @param Nubivio_HSH|null $core Plugin core.
     */
    public function __construct($core = null) {
        $this->core = $core;
    }

    /**
     * Transient key for the cached summary of a home URL.
     *
     * @param string $home Home URL.
     * @return string
     */
    public static function cache_key($home) {
        return 'nubivio_hsh_exposure_' . md5((string) $home);
    }

    /**
     * Forget the cached summary for the current site.
     *
     * @return void
     */
    public static function clear_cache() {
        delete_transient(self::cache_key(home_url('/')));
    }

    /**
     * Cached answer of the REST users check, for class-health.php.
     *
     * @return bool|null True when users are listed, false when not, null when unknown.
     */
    public static function cached_rest_users() {
        $cached = get_transient(self::cache_key(home_url('/')));
        if (!is_array($cached) || empty($cached['summary']['checks'])) {
            return null;
        }
        foreach ((array) $cached['summary']['checks'] as $check) {
            if ($check['id'] === 'rest_users' && (int) $check['status'] > 0) {
                return (bool) $check['hit'];
            }
        }
        return null;
    }

    /**
     * Run the exposure scan (cached for 12 hours).
     *
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function run() {
        $key    = self::cache_key(home_url('/'));
        $cached = get_transient($key);
        if (is_array($cached) && isset($cached['summary']['checks'])) {
            return $this->evaluate($cached['summary']);
        }
        $summary = $this->probe();
        set_transient($key, array('summary' => $summary), self::CACHE_TTL);
        return $this->evaluate($summary);
    }

    /**
     * Check definitions. `match` is evaluated against status, headers and
     * the first 4 KB of the body; the body itself is not kept.
     *
     * @return array<int,array<string,mixed>>
     */
    private function definitions() {
        $title = '/<title>\s*WordPress\s*(&rsaquo;|&#8250;|\x{203A})/iu';
        $list  = array(
            array('id' => 'readme', 'path' => '/readme.html', 'severity' => 'low', 'match' => 'signature', 're' => $title),
            array(
                'id'       => 'license',
                'path'     => '/license.txt',
                'severity' => 'low',
                'match'    => 'signature',
                're'       => '/WordPress - Web publishing software|GNU GENERAL PUBLIC LICENSE/i',
            ),
            array('id' => 'rest_users', 'path' => '/wp-json/wp/v2/users', 'severity' => 'medium', 'match' => 'rest_users'),
            array('id' => 'author_enum', 'path' => '/?author=1', 'severity' => 'medium', 'match' => 'author'),
            array('id' => 'uploads_listing', 'path' => '/wp-content/uploads/', 'severity' => 'medium', 'match' => 'signature', 're' => '/Index of/'),
            array('id' => 'git', 'path' => '/.git/HEAD', 'severity' => 'high', 'match' => 'signature', 're' => '/\Aref:/'),
            array('id' => 'env', 'path' => '/.env', 'severity' => 'high', 'match' => 'signature', 're' => '/^[A-Z_]+=/m'),
            array('id' => 'debug_log', 'path' => '/wp-content/debug.log', 'severity' => 'high', 'match' => 'file'),
        );
        $backups = array('/wp-config.php.bak', '/wp-config.php~', '/wp-config.old', '/wp-config.php.save', '/.wp-config.php.swp');
        foreach ($backups as $path) {
            $list[] = array('id' => 'config_backup', 'path' => $path, 'severity' => 'high', 'match' => 'file');
        }
        // Health already reports XML-RPC when it is enabled; only check the file when it should be off.
        if (!apply_filters('xmlrpc_enabled', true)) {
            $list[] = array(
                'id'       => 'xmlrpc',
                'path'     => '/xmlrpc.php',
                'severity' => 'low',
                'match'    => 'xmlrpc',
                're'       => '/XML-RPC server accepts POST requests only/i',
            );
        }
        return $list;
    }

    /**
     * Collect raw signals. Only path, status code and yes/no are kept.
     *
     * @return array<string,mixed>
     */
    private function probe() {
        $summary = array(
            'checks'    => array(),
            'generator' => $this->generator_from_inventory(),
            'requests'  => 0,
            'reachable' => false,
            'time'      => time(),
        );
        $failures = 0;
        foreach ($this->definitions() as $def) {
            $row = array(
                'id'       => $def['id'],
                'path'     => $def['path'],
                'severity' => $def['severity'],
                'status'   => 0,
                'hit'      => false,
            );
            // Two failed requests in a row means loopback is blocked: stop instead of piling up timeouts.
            if ($failures >= 2 || $summary['requests'] >= self::MAX_REQUESTS) {
                $summary['checks'][] = $row;
                continue;
            }
            $summary['requests']++;
            $res = $this->fetch(home_url($def['path']));
            if ($res === null) {
                $failures++;
                $summary['checks'][] = $row;
                continue;
            }
            $failures             = 0;
            $summary['reachable'] = true;
            $row['status']        = $res['code'];
            $row['hit']           = $this->matches($def, $res);
            $summary['checks'][]  = $row;
        }
        return $summary;
    }

    /**
     * Decide whether a response is a real exposure.
     *
     * @param array $def Check definition.
     * @param array $res Response from fetch().
     * @return bool
     */
    private function matches($def, $res) {
        $code = (int) $res['code'];
        $body = (string) $res['body'];
        $type = isset($res['headers']['content-type']) ? strtolower($res['headers']['content-type']) : '';
        switch ($def['match']) {
            case 'author':
                return in_array($code, array(301, 302), true)
                    && (bool) preg_match('#/author/[^/?\#]+/?#i', (string) $res['location']);
            case 'rest_users':
                if ($code !== 200) {
                    return false;
                }
                $data = json_decode($body, true);
                if (!is_array($data)) {
                    // Body cut at 4 KB: fall back to the raw shape of a users array.
                    return (bool) preg_match('/\A\s*\[\s*\{.*"slug"\s*:/s', $body);
                }
                return isset($data[0]) && is_array($data[0]) && isset($data[0]['slug']);
            case 'xmlrpc':
                return in_array($code, array(200, 405), true) && (bool) preg_match($def['re'], $body);
            case 'file':
                // Leftover files are never served as HTML; an HTML 200 is a catch-all page.
                return $code === 200 && trim($body) !== '' && strpos($type, 'text/html') === false;
            default:
                return $code === 200 && (bool) preg_match($def['re'], $body);
        }
    }

    /**
     * Generator tag with a version in the homepage HTML cached by the CSP
     * inventory. Null when that cache is empty, so no extra request is made.
     *
     * @return bool|null
     */
    private function generator_from_inventory() {
        $html = get_transient('nubivio_hsh_csp_html_' . md5((string) home_url('/')));
        if (!is_string($html) || $html === '') {
            return null;
        }
        return (bool) preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*\d+\.\d/i', $html);
    }

    /**
     * One GET request with the module's fixed safety limits.
     *
     * @param string $url Own-site URL.
     * @return array{code:int,headers:array,body:string,location:string}|null
     */
    private function fetch($url) {
        $res = wp_remote_get(
            $url,
            array(
                'timeout'             => self::TIMEOUT,
                'redirection'         => 0,
                'limit_response_size' => self::BODY_LIMIT,
                'user-agent'          => self::USER_AGENT,
            )
        );
        if (is_wp_error($res)) {
            return null;
        }
        $headers = wp_remote_retrieve_headers($res);
        if (is_object($headers) && method_exists($headers, 'getAll')) {
            $headers = $headers->getAll();
        }
        $lower = array();
        foreach ((array) $headers as $name => $value) {
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
     * Advice text per check id. Manual steps only.
     *
     * @param string $id   Check id.
     * @param string $path Path that was checked.
     * @return string
     */
    private static function message($id, $path) {
        switch ($id) {
            case 'readme':
            case 'license':
                return sprintf(
                    /* translators: %s: path such as /readme.html. */
                    __('%s is publicly reachable and identifies the site as WordPress. Remove the file or block it in the web server.', 'nubivio-healthcare-security-hardening'),
                    $path
                );
            case 'rest_users':
                return __(
                    'The REST API lists user accounts at /wp-json/wp/v2/users without login. Usernames make password attacks easier; restrict this endpoint.',
                    'nubivio-healthcare-security-hardening'
                );
            case 'author_enum':
                return __(
                    '/?author=1 redirects to an author page, which reveals a username. Block author enumeration in the web server or a security plugin.',
                    'nubivio-healthcare-security-hardening'
                );
            case 'uploads_listing':
                return __(
                    'Directory listing is enabled for /wp-content/uploads/. Anyone can browse uploaded files; disable listing in the web server (Options -Indexes).',
                    'nubivio-healthcare-security-hardening'
                );
            case 'git':
                return __(
                    'A .git directory is publicly reachable. Source code and history can be downloaded. Block /.git in the web server.',
                    'nubivio-healthcare-security-hardening'
                );
            case 'env':
                return __(
                    'A .env file is publicly reachable and may contain credentials. Remove it from the web root and rotate the secrets.',
                    'nubivio-healthcare-security-hardening'
                );
            case 'debug_log':
                return __(
                    'wp-content/debug.log is publicly downloadable. Debug logs can contain paths, queries and personal data. Delete it and log to a path outside the web root.',
                    'nubivio-healthcare-security-hardening'
                );
            case 'config_backup':
                return sprintf(
                    /* translators: %s: file path such as /wp-config.php.bak. */
                    __('%s is publicly downloadable and may contain database settings. Delete it now and change the database password.', 'nubivio-healthcare-security-hardening'),
                    $path
                );
            case 'xmlrpc':
                return __(
                    'XML-RPC is switched off in WordPress, but /xmlrpc.php still answers. Block the file in the web server if you do not use it.',
                    'nubivio-healthcare-security-hardening'
                );
        }
        return '';
    }

    /**
     * Short label per check id, for the dashboard table.
     *
     * @param string $id Check id.
     * @return string
     */
    public static function label($id) {
        $labels = array(
            'readme'          => __('WordPress readme', 'nubivio-healthcare-security-hardening'),
            'license'         => __('WordPress license file', 'nubivio-healthcare-security-hardening'),
            'rest_users'      => __('REST user listing', 'nubivio-healthcare-security-hardening'),
            'author_enum'     => __('Author enumeration', 'nubivio-healthcare-security-hardening'),
            'uploads_listing' => __('Uploads directory listing', 'nubivio-healthcare-security-hardening'),
            'git'             => __('Git repository', 'nubivio-healthcare-security-hardening'),
            'env'             => __('Environment file', 'nubivio-healthcare-security-hardening'),
            'debug_log'       => __('Debug log', 'nubivio-healthcare-security-hardening'),
            'config_backup'   => __('wp-config backup', 'nubivio-healthcare-security-hardening'),
            'xmlrpc'          => __('XML-RPC endpoint', 'nubivio-healthcare-security-hardening'),
        );
        return isset($labels[$id]) ? $labels[$id] : $id;
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

        if (!empty($summary['generator'])) {
            $this->add(
                $findings,
                $counts,
                'low',
                __(
                    'The homepage publishes the WordPress version in a generator meta tag. Remove it so scanners cannot match the version to known vulnerabilities.',
                    'nubivio-healthcare-security-hardening'
                ),
                array('A.8.9')
            );
        }
        foreach ((array) $summary['checks'] as $check) {
            if (empty($check['hit'])) {
                continue;
            }
            $controls = $check['severity'] === 'low' ? array('A.8.9') : array('A.8.9', 'A.8.12');
            $this->add($findings, $counts, $check['severity'], self::message($check['id'], $check['path']), $controls);
        }

        return array(
            'findings' => $findings,
            'counts'   => $counts,
            'summary'  => $summary,
        );
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
        if (empty($summary['reachable'])) {
            return array(
                'label'  => $label,
                'status' => 'warn',
                'detail' => __('The site could not request its own URLs, so the exposure checks were skipped.', 'nubivio-healthcare-security-hardening'),
            );
        }
        $high   = isset($counts['high']) ? (int) $counts['high'] : 0;
        $medium = isset($counts['medium']) ? (int) $counts['medium'] : 0;
        $low    = isset($counts['low']) ? (int) $counts['low'] : 0;
        if ($high + $medium + $low === 0) {
            return array(
                'label'  => $label,
                'status' => 'pass',
                'detail' => __('No leftover files, listings, version disclosure or user enumeration found.', 'nubivio-healthcare-security-hardening'),
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

    /**
     * Append a finding and bump its counter.
     *
     * @param array  $findings Findings list.
     * @param array  $counts   Counters.
     * @param string $severity high, medium or low.
     * @param string $message  Message.
     * @param array  $controls Annex A controls for the compliance map.
     * @return void
     */
    private function add(&$findings, &$counts, $severity, $message, $controls) {
        $findings[] = array(
            'severity' => $severity,
            'message'  => $message,
            'controls' => $controls,
        );
        $counts[$severity]++;
    }
}
