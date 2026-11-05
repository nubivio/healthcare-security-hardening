<?php
/**
 * PHP runtime vulnerability check (v2.6.0).
 *
 * Compares the running PHP version against a small, data-driven table of
 * PHP-level advisories. The first entry is PHP2Shell (CVE-2026-6722 and
 * CVE-2026-7568, published 29 October 2026): a memory-safety issue in the
 * multipart and session upload-progress handling of the PHP runtime itself.
 * A WordPress plugin cannot fix this; the hosting provider has to update PHP.
 * This module only detects and explains.
 *
 * Verdicts per advisory:
 * - patched:  the upstream version is at or above the fixed release of its
 *             branch, or the branch is newer than every listed branch.
 * - affected: an upstream build (no PHP_EXTRA_VERSION) below the fixed
 *             release, or an end-of-life branch older than every listed one.
 * - unknown:  a distribution build (PHP_EXTRA_VERSION set, e.g. Debian,
 *             Ubuntu, Sury, Remi) below the upstream fix. Distributions often
 *             backport fixes without changing the version number, so the
 *             plugin cannot tell; the host has to confirm.
 *
 * Filters:
 * - `nubivio_hsh_php_advisories` (array): add or adjust advisories.
 * - `nubivio_hsh_php_advisory_status` (string, array $advisory, array
 *   $runtime): override a verdict, e.g. when a host has confirmed a backport.
 *
 * @package Nubivio_HSH
 */
if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Php_Runtime {

    const DISMISS_ACTION = 'nubivio_hsh_dismiss_php_notice';
    const DISMISS_META   = 'nubivio_hsh_php_notice_dismissed';
    const SITE_HEALTH_ID = 'nubivio_hsh_php_runtime';

    /** @var Nubivio_HSH|null */
    private $core;

    public function __construct($core = null) {
        $this->core = $core;
    }

    /**
     * Wire the Site Health test, the admin notice and its dismiss handler.
     *
     * @param Nubivio_HSH $core Plugin core.
     */
    public static function register_hooks($core) {
        $self = new self($core);
        add_filter('site_status_tests', array($self, 'register_site_health_test'));
        add_action('admin_notices', array($self, 'maybe_admin_notice'));
        add_action('admin_post_' . self::DISMISS_ACTION, array($self, 'handle_dismiss'));
    }

    /**
     * PHP-level advisories. Each entry lists the first fixed release per
     * supported branch. Branches older than the oldest listed branch are
     * end-of-life and never receive an upstream fix.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function advisories() {
        $advisories = array(
            array(
                'id'             => 'php2shell',
                'name'           => 'PHP2Shell',
                'cves'           => array('CVE-2026-6722', 'CVE-2026-7568'),
                'published'      => '2026-10-29',
                'fixed'          => array(
                    '8.2' => '8.2.31',
                    '8.3' => '8.3.31',
                    '8.4' => '8.4.22',
                    '8.5' => '8.5.7',
                ),
                'upgrade_branch' => '8.3',
                'url'            => 'https://www.php.net/ChangeLog-8.php',
            ),
        );
        $filtered = apply_filters('nubivio_hsh_php_advisories', $advisories);
        return is_array($filtered) ? $filtered : $advisories;
    }

    /**
     * Snapshot of the running PHP runtime. Values that cannot be read are
     * null, so callers can tell "off" apart from "not available".
     *
     * @return array<string,mixed>
     */
    public static function current_runtime() {
        return array(
            'version'                => PHP_VERSION,
            'major'                  => PHP_MAJOR_VERSION,
            'minor'                  => PHP_MINOR_VERSION,
            'release'                => PHP_RELEASE_VERSION,
            'extra'                  => PHP_EXTRA_VERSION,
            'sapi'                   => PHP_SAPI,
            'upload_progress'        => self::ini_flag('session.upload_progress.enabled'),
            'fatal_error_backtraces' => self::ini_flag('fatal_error_backtraces'),
        );
    }

    /**
     * Read a boolean ini setting. Returns null when the directive does not
     * exist on this PHP version or ini_get() is disabled.
     *
     * @param string $name Directive name.
     * @return bool|null
     */
    private static function ini_flag($name) {
        if (!function_exists('ini_get')) {
            return null;
        }
        $value = ini_get($name);
        if ($value === false) {
            return null;
        }
        $bool = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        return $bool === null ? null : (bool) $bool;
    }

    /**
     * Normalise a runtime array so tests can pass partial input.
     *
     * @param array $runtime Partial or full runtime.
     * @return array<string,mixed>
     */
    private static function normalise_runtime($runtime) {
        $runtime = is_array($runtime) ? $runtime : array();
        $base    = array(
            'version'                => '',
            'major'                  => 0,
            'minor'                  => 0,
            'release'                => 0,
            'extra'                  => '',
            'sapi'                   => '',
            'upload_progress'        => null,
            'fatal_error_backtraces' => null,
        );
        $runtime = array_merge($base, $runtime);
        if ($runtime['version'] !== '' && empty($runtime['major'])) {
            if (preg_match('/^(\d+)\.(\d+)\.(\d+)(.*)$/', (string) $runtime['version'], $m)) {
                $runtime['major']   = (int) $m[1];
                $runtime['minor']   = (int) $m[2];
                $runtime['release'] = (int) $m[3];
                if ($runtime['extra'] === '') {
                    $runtime['extra'] = (string) $m[4];
                }
            }
        }
        $runtime['major']   = (int) $runtime['major'];
        $runtime['minor']   = (int) $runtime['minor'];
        $runtime['release'] = (int) $runtime['release'];
        $runtime['extra']   = (string) $runtime['extra'];
        if ($runtime['version'] === '') {
            $runtime['version'] = $runtime['major'] . '.' . $runtime['minor'] . '.' . $runtime['release'] . $runtime['extra'];
        }
        return $runtime;
    }

    /**
     * Verdict for one advisory against one runtime.
     *
     * @param array $advisory Advisory entry.
     * @param array $runtime  Runtime snapshot.
     * @return array{status:string,fixed_in:string,branch:string}
     */
    public static function evaluate_advisory($advisory, $runtime) {
        $runtime  = self::normalise_runtime($runtime);
        $branch   = $runtime['major'] . '.' . $runtime['minor'];
        $upstream = $runtime['major'] . '.' . $runtime['minor'] . '.' . $runtime['release'];
        $extra    = trim($runtime['extra']);
        // Upstream pre-releases (8.5.0RC1, -dev) are not distribution builds.
        $distro   = $extra !== '' && !preg_match('/^-?(dev|alpha\d*|beta\d*|rc\d*)$/i', $extra);
        $fixed    = isset($advisory['fixed']) && is_array($advisory['fixed']) ? $advisory['fixed'] : array();

        $branches = array_keys($fixed);
        usort($branches, 'version_compare');
        $oldest = $branches ? $branches[0] : '';
        $newest = $branches ? $branches[count($branches) - 1] : '';

        $status   = 'unknown';
        $fixed_in = '';
        if (isset($fixed[$branch])) {
            $fixed_in = (string) $fixed[$branch];
            if (version_compare($upstream, $fixed_in, '>=')) {
                $status = 'patched';
            } else {
                $status = $distro ? 'unknown' : 'affected';
            }
        } elseif ($newest !== '' && version_compare($branch, $newest, '>')) {
            $status = 'patched';
        } elseif ($oldest !== '' && version_compare($branch, $oldest, '<')) {
            $status   = $distro ? 'unknown' : 'affected';
            $fixed_in = isset($advisory['upgrade_branch']) ? (string) $advisory['upgrade_branch'] : $oldest;
        }

        $status = (string) apply_filters('nubivio_hsh_php_advisory_status', $status, $advisory, $runtime);
        if (!in_array($status, array('patched', 'affected', 'unknown'), true)) {
            $status = 'unknown';
        }

        return array(
            'status'   => $status,
            'fixed_in' => $fixed_in,
            'branch'   => $branch,
            'eol'      => $oldest !== '' && version_compare($branch, $oldest, '<'),
        );
    }

    /**
     * Run all advisories plus the mitigation indicators.
     *
     * @param array|null $runtime Optional runtime override (tests).
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function run($runtime = null) {
        $runtime  = self::normalise_runtime($runtime === null ? self::current_runtime() : $runtime);
        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);
        $results  = array();
        $worst    = 'patched';
        $rank     = array('patched' => 0, 'unknown' => 1, 'affected' => 2);

        foreach (self::advisories() as $advisory) {
            if (!is_array($advisory) || empty($advisory['fixed'])) {
                continue;
            }
            $verdict = self::evaluate_advisory($advisory, $runtime);
            $message = self::verdict_message($advisory, $verdict, $runtime);
            $results[] = array(
                'id'       => isset($advisory['id']) ? (string) $advisory['id'] : '',
                'name'     => isset($advisory['name']) ? (string) $advisory['name'] : '',
                'cves'     => isset($advisory['cves']) ? (array) $advisory['cves'] : array(),
                'status'   => $verdict['status'],
                'fixed_in' => $verdict['fixed_in'],
                'message'  => $message,
            );
            if ($rank[$verdict['status']] > $rank[$worst]) {
                $worst = $verdict['status'];
            }
            if ($verdict['status'] === 'affected') {
                $this->add($findings, $counts, 'high', $message);
            } elseif ($verdict['status'] === 'unknown') {
                $this->add($findings, $counts, 'medium', $message);
            }
        }

        if ($runtime['upload_progress'] === true) {
            $this->add(
                $findings,
                $counts,
                'low',
                __(
                    'session.upload_progress.enabled is On. Upload-progress session data is part of the PHP2Shell attack path; ask your host to set it to Off unless you need upload progress.',
                    'nubivio-healthcare-security-hardening'
                )
            );
        }
        if ($runtime['fatal_error_backtraces'] === true) {
            $this->add(
                $findings,
                $counts,
                'low',
                __(
                    'fatal_error_backtraces is On (the PHP 8.5 default). Backtraces in fatal errors can expose data; ask your host to set it to Off in production.',
                    'nubivio-healthcare-security-hardening'
                )
            );
        }

        return array(
            'findings' => $findings,
            'counts'   => $counts,
            'summary'  => array(
                'version'                => $runtime['version'],
                'extra'                  => $runtime['extra'],
                'sapi'                   => $runtime['sapi'],
                'upload_progress'        => $runtime['upload_progress'],
                'fatal_error_backtraces' => $runtime['fatal_error_backtraces'],
                'status'                 => $worst,
                'advisories'             => $results,
            ),
        );
    }

    /**
     * Human-readable verdict message.
     *
     * @param array $advisory Advisory entry.
     * @param array $verdict  Result of evaluate_advisory().
     * @param array $runtime  Normalised runtime.
     * @return string
     */
    private static function verdict_message($advisory, $verdict, $runtime) {
        $name    = isset($advisory['name']) ? (string) $advisory['name'] : '';
        $cves    = isset($advisory['cves']) ? implode(', ', (array) $advisory['cves']) : '';
        $label   = $cves !== '' ? $name . ' (' . $cves . ')' : $name;
        $version = (string) $runtime['version'];

        if ($verdict['status'] === 'patched') {
            return sprintf(
                /* translators: 1: PHP version, 2: advisory name with CVE IDs. */
                __('PHP %1$s includes the upstream fix for %2$s.', 'nubivio-healthcare-security-hardening'),
                $version,
                $label
            );
        }
        if ($verdict['status'] === 'affected' && !empty($verdict['eol'])) {
            return sprintf(
                /* translators: 1: PHP version, 2: advisory name with CVE IDs, 3: PHP branch to upgrade to, e.g. 8.3. */
                __(
                    'PHP %1$s is end-of-life and has no upstream fix for %2$s. Ask your hosting provider to upgrade to PHP %3$s or later.',
                    'nubivio-healthcare-security-hardening'
                ),
                $version,
                $label,
                $verdict['fixed_in']
            );
        }
        if ($verdict['status'] === 'affected') {
            return sprintf(
                /* translators: 1: PHP version, 2: advisory name with CVE IDs, 3: first fixed PHP version. */
                __(
                    'PHP %1$s is vulnerable to %2$s. Ask your hosting provider to update PHP to %3$s or later.',
                    'nubivio-healthcare-security-hardening'
                ),
                $version,
                $label,
                $verdict['fixed_in']
            );
        }
        $parts = array(
            sprintf(
                /* translators: 1: PHP version string including the distribution suffix, 2: advisory name with CVE IDs. */
                __('PHP %1$s is a distribution build, so the plugin cannot tell whether %2$s is fixed.', 'nubivio-healthcare-security-hardening'),
                $version,
                $label
            ),
            __('Distributions often backport security fixes without changing the version number.', 'nubivio-healthcare-security-hardening'),
        );
        if ($verdict['fixed_in'] !== '') {
            $parts[] = sprintf(
                /* translators: %s: first fixed upstream PHP version or branch. */
                __('Ask your hosting provider to confirm the fix is installed, or to update to PHP %s or later.', 'nubivio-healthcare-security-hardening'),
                $verdict['fixed_in']
            );
        } else {
            $parts[] = __('Ask your hosting provider to confirm the fix is installed.', 'nubivio-healthcare-security-hardening');
        }
        return implode(' ', $parts);
    }

    /**
     * Row for the plugin's own Site health card.
     *
     * @param array $summary Summary from run().
     * @return array{label:string,status:string,detail:string}
     */
    public static function health_row($summary) {
        $status = isset($summary['status']) ? (string) $summary['status'] : 'unknown';
        $map    = array('patched' => 'pass', 'unknown' => 'warn', 'affected' => 'fail');
        $detail = array();
        if (!empty($summary['advisories'])) {
            foreach ((array) $summary['advisories'] as $row) {
                $detail[] = (string) $row['message'];
            }
        }
        if (!empty($summary['sapi'])) {
            $detail[] = sprintf(
                /* translators: %s: PHP server API, e.g. fpm-fcgi. */
                __('Server API: %s.', 'nubivio-healthcare-security-hardening'),
                (string) $summary['sapi']
            );
        }
        return array(
            'label'  => __('PHP runtime vulnerabilities', 'nubivio-healthcare-security-hardening'),
            'status' => isset($map[$status]) ? $map[$status] : 'warn',
            'detail' => implode(' ', $detail),
        );
    }

    /**
     * Add the direct test to Tools > Site Health.
     *
     * @param array $tests Registered tests.
     * @return array
     */
    public function register_site_health_test($tests) {
        if (!is_array($tests)) {
            $tests = array();
        }
        $tests['direct'][self::SITE_HEALTH_ID] = array(
            'label' => __('PHP runtime vulnerabilities', 'nubivio-healthcare-security-hardening'),
            'test'  => array($this, 'site_health_test'),
        );
        return $tests;
    }

    /**
     * Site Health test callback.
     *
     * @return array<string,mixed>
     */
    public function site_health_test() {
        $result  = $this->run();
        $summary = $result['summary'];
        $status  = $summary['status'];

        $labels = array(
            'patched'  => __('Your PHP version includes the fixes for known PHP runtime advisories', 'nubivio-healthcare-security-hardening'),
            'unknown'  => __('Ask your host to confirm your PHP version is patched', 'nubivio-healthcare-security-hardening'),
            'affected' => __('Your PHP version has a known critical vulnerability', 'nubivio-healthcare-security-hardening'),
        );
        $wp_status = array('patched' => 'good', 'unknown' => 'recommended', 'affected' => 'critical');
        $colors    = array('patched' => 'blue', 'unknown' => 'orange', 'affected' => 'red');

        $description = '';
        foreach ($summary['advisories'] as $row) {
            $description .= '<p>' . esc_html($row['message']) . '</p>';
        }
        $description .= '<p>' . esc_html__(
            'This is a PHP runtime issue. A WordPress plugin cannot fix it; only your hosting provider can update PHP.',
            'nubivio-healthcare-security-hardening'
        ) . '</p>';

        return array(
            'label'       => $labels[$status],
            'status'      => $wp_status[$status],
            'badge'       => array(
                'label' => __('Security', 'nubivio-healthcare-security-hardening'),
                'color' => $colors[$status],
            ),
            'description' => $description,
            'actions'     => '<p><a href="https://www.php.net/ChangeLog-8.php" target="_blank" rel="noopener">'
                . esc_html__('PHP 8 changelog', 'nubivio-healthcare-security-hardening') . '</a></p>',
            'test'        => self::SITE_HEALTH_ID,
        );
    }

    /**
     * Fingerprint of the running PHP build; a dismissal only holds for it.
     *
     * @return string
     */
    private static function runtime_fingerprint() {
        return PHP_VERSION . '|' . PHP_SAPI;
    }

    /**
     * Admin notice for administrators when the runtime is affected.
     */
    public function maybe_admin_notice() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $user_id = get_current_user_id();
        if ((string) get_user_meta($user_id, self::DISMISS_META, true) === self::runtime_fingerprint()) {
            return;
        }
        $result = $this->run();
        if ($result['summary']['status'] !== 'affected') {
            return;
        }
        $messages = array();
        foreach ($result['summary']['advisories'] as $row) {
            if ($row['status'] === 'affected') {
                $messages[] = $row['message'];
            }
        }
        $dismiss_url = wp_nonce_url(
            admin_url('admin-post.php?action=' . self::DISMISS_ACTION),
            self::DISMISS_ACTION
        );
        echo '<div class="notice notice-error"><p><strong>'
            . esc_html__('Nubivio Healthcare Security Hardening: critical PHP vulnerability', 'nubivio-healthcare-security-hardening')
            . '</strong></p><p>' . esc_html(implode(' ', $messages)) . '</p><p>'
            . esc_html__('A WordPress plugin cannot fix this; only your hosting provider can update PHP.', 'nubivio-healthcare-security-hardening')
            . ' <a href="' . esc_url($dismiss_url) . '">'
            . esc_html__('Hide for this PHP version', 'nubivio-healthcare-security-hardening')
            . '</a></p></div>';
    }

    /**
     * Dismiss the notice for the current user and PHP build.
     */
    public function handle_dismiss() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to perform this action.', 'nubivio-healthcare-security-hardening'));
        }
        $nonce = isset($_REQUEST['_wpnonce']) ? sanitize_text_field(wp_unslash($_REQUEST['_wpnonce'])) : '';
        if (!$nonce || !wp_verify_nonce($nonce, self::DISMISS_ACTION)) {
            wp_die(esc_html__('Security check failed.', 'nubivio-healthcare-security-hardening'));
        }
        update_user_meta(get_current_user_id(), self::DISMISS_META, self::runtime_fingerprint());
        $back = wp_get_referer();
        wp_safe_redirect($back ? $back : admin_url());
        exit;
    }

    private function add(&$findings, &$counts, $severity, $message) {
        $findings[]        = array('severity' => $severity, 'message' => $message);
        $counts[$severity]++;
    }
}
