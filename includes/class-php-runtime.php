<?php
/**
 * PHP runtime vulnerability check (v2.6.0).
 *
 * Compares the PHP process that actually serves the site (not a guess from
 * response headers) with a small, data-driven table of PHP-level
 * advisories. The first entry is PHP2Shell: CVE-2026-109618 (RCE via
 * out-of-memory corruption during request cleanup) and CVE-2026-109619 (RCE
 * via stale request-owned global state), CVSS 9.2.
 * Fixed upstream on 21 October 2026 in PHP 8.2.35, 8.3.36, 8.4.27 and
 * 8.5.12. PHP 8.1 and older are unsupported: there is no official PHP
 * release with the fix, only source backports and distribution packages.
 *
 * Sources:
 * - https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
 * - https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
 * - https://github.com/NCSC-NL/php2shell
 *
 * A WordPress plugin cannot fix a PHP runtime issue. This module only reads
 * constants and ini values, makes no network calls and changes nothing; the
 * advice is always for the hosting provider.
 *
 * Filters:
 * - `nubivio_hsh_php_advisories` (array): add or adjust advisories.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Php_Runtime {

    const DISMISS_ACTION = 'nubivio_hsh_dismiss_php_notice';
    const DISMISS_META   = 'nubivio_hsh_php_notice_';
    const SITE_HEALTH_ID = 'nubivio_hsh_php2shell';

    /** @var Nubivio_HSH|null */
    private $core;

    /**
     * @param Nubivio_HSH|null $core Plugin core (unused by the checks themselves).
     */
    public function __construct($core = null) {
        $this->core = $core;
    }

    /**
     * Wire the Site Health test, the admin notice and its dismiss handler.
     *
     * @param Nubivio_HSH $core Plugin core.
     * @return void
     */
    public static function register_hooks($core) {
        $self = new self($core);
        add_filter('site_status_tests', array($self, 'register_site_health_test'));
        add_action('admin_notices', array($self, 'maybe_admin_notice'));
        add_action('admin_post_' . self::DISMISS_ACTION, array($self, 'handle_dismiss'));
    }

    /**
     * PHP-level advisories. `fixed` maps a branch to the first fixed release
     * number on that branch. Branches older than `min_supported_branch` have
     * no official PHP release with the fix. A next PHP advisory is one more entry here.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function get_advisories() {
        $advisories = array(
            array(
                'id'                   => 'php2shell',
                'name'                 => 'PHP2Shell',
                'cves'                 => array('CVE-2026-109618', 'CVE-2026-109619'),
                'published'            => '2026-10-21',
                'fixed'                => array(
                    '8.2' => 35,
                    '8.3' => 36,
                    '8.4' => 27,
                    '8.5' => 12,
                ),
                'min_supported_branch' => '8.2',
                'upgrade_branch'       => '8.3',
                'url'                  => 'https://github.com/NCSC-NL/php2shell',
            ),
        );
        $filtered = apply_filters('nubivio_hsh_php_advisories', $advisories);
        return is_array($filtered) ? $filtered : $advisories;
    }

    /**
     * Snapshot of the running PHP process. Ini values that cannot be read
     * are null, so "off" and "not available" stay distinguishable.
     *
     * @return array<string,mixed>
     */
    public static function current_runtime() {
        $is_85 = PHP_MAJOR_VERSION > 8 || (PHP_MAJOR_VERSION === 8 && PHP_MINOR_VERSION >= 5);
        return array(
            'version'                => PHP_VERSION,
            'major'                  => PHP_MAJOR_VERSION,
            'minor'                  => PHP_MINOR_VERSION,
            'release'                => PHP_RELEASE_VERSION,
            'extra'                  => PHP_EXTRA_VERSION,
            'sapi'                   => php_sapi_name(),
            'upload_progress'        => self::ini_flag('session.upload_progress.enabled'),
            'fatal_error_backtraces' => $is_85 ? self::ini_flag('fatal_error_backtraces') : null,
        );
    }

    /**
     * Read a boolean ini directive.
     *
     * @param string $name Directive name.
     * @return bool|null Null when the directive is unknown or ini_get() is disabled.
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
     * Fill in defaults so tests can pass a partial runtime.
     *
     * @param array $runtime Partial or full runtime.
     * @return array<string,mixed>
     */
    private static function normalise_runtime($runtime) {
        $defaults = array(
            'version'                => '',
            'major'                  => 0,
            'minor'                  => 0,
            'release'                => 0,
            'extra'                  => '',
            'sapi'                   => '',
            'upload_progress'        => null,
            'fatal_error_backtraces' => null,
        );
        $runtime            = array_merge($defaults, is_array($runtime) ? $runtime : array());
        $runtime['major']   = (int) $runtime['major'];
        $runtime['minor']   = (int) $runtime['minor'];
        $runtime['release'] = (int) $runtime['release'];
        $runtime['extra']   = (string) $runtime['extra'];
        $runtime['sapi']    = (string) $runtime['sapi'];
        if ($runtime['version'] === '') {
            $runtime['version'] = $runtime['major'] . '.' . $runtime['minor'] . '.' . $runtime['release'];
            $runtime['version'] .= $runtime['extra'];
        }
        return $runtime;
    }

    /**
     * Compare two "major.minor" branches as integers.
     *
     * @param string $a Branch, e.g. 8.3.
     * @param string $b Branch, e.g. 8.2.
     * @return int Negative, zero or positive.
     */
    private static function compare_branch($a, $b) {
        $pa = array_map('intval', explode('.', (string) $a)) + array(0, 0);
        $pb = array_map('intval', explode('.', (string) $b)) + array(0, 0);
        if ($pa[0] !== $pb[0]) {
            return $pa[0] - $pb[0];
        }
        return $pa[1] - $pb[1];
    }

    /**
     * Verdict for one advisory. Only major/minor/release integers are
     * compared; a distribution suffix is never fed to version_compare().
     *
     * @param array $advisory Advisory entry.
     * @param array $runtime  Runtime snapshot.
     * @return array{status:string,fixed_in:string,eol:bool}
     */
    public static function evaluate_advisory($advisory, $runtime) {
        $runtime = self::normalise_runtime($runtime);
        $branch  = $runtime['major'] . '.' . $runtime['minor'];
        $fixed   = isset($advisory['fixed']) && is_array($advisory['fixed']) ? $advisory['fixed'] : array();
        $distro  = trim($runtime['extra']) !== '';

        $branches = array_keys($fixed);
        usort($branches, array(__CLASS__, 'compare_branch'));
        $newest     = $branches ? (string) $branches[count($branches) - 1] : '';
        $min_branch = isset($advisory['min_supported_branch'])
            ? (string) $advisory['min_supported_branch']
            : ($branches ? (string) $branches[0] : '');

        if (isset($fixed[$branch])) {
            $fixed_in = $branch . '.' . (int) $fixed[$branch];
            if ($runtime['release'] >= (int) $fixed[$branch]) {
                return array('status' => 'patched', 'fixed_in' => $fixed_in, 'eol' => false);
            }
            return array('status' => $distro ? 'unknown' : 'affected', 'fixed_in' => $fixed_in, 'eol' => false);
        }
        if ($newest !== '' && self::compare_branch($branch, $newest) > 0) {
            return array('status' => 'patched', 'fixed_in' => '', 'eol' => false);
        }
        if ($min_branch !== '' && self::compare_branch($branch, $min_branch) < 0) {
            $upgrade = isset($advisory['upgrade_branch']) ? (string) $advisory['upgrade_branch'] : $min_branch;
            return array('status' => $distro ? 'unknown' : 'affected', 'fixed_in' => $upgrade, 'eol' => true);
        }
        // A supported branch missing from the table: do not guess.
        return array('status' => 'unknown', 'fixed_in' => '', 'eol' => false);
    }

    /**
     * Run all advisories plus the ini signals.
     *
     * @param array|null $runtime Optional runtime override (tests).
     * @return array{findings:array,counts:array<string,int>,summary:array}
     */
    public function run($runtime = null) {
        $runtime    = self::normalise_runtime($runtime === null ? self::current_runtime() : $runtime);
        $findings   = array();
        $counts     = array('high' => 0, 'medium' => 0, 'low' => 0);
        $advisories = array();
        $worst      = 'patched';
        $rank       = array('patched' => 0, 'unknown' => 1, 'affected' => 2);

        foreach (self::get_advisories() as $advisory) {
            if (!is_array($advisory) || empty($advisory['id']) || empty($advisory['fixed'])) {
                continue;
            }
            $id      = sanitize_key((string) $advisory['id']);
            $verdict = self::evaluate_advisory($advisory, $runtime);
            $message = self::verdict_message($advisory, $verdict, $runtime);

            $advisories[$id] = array(
                'name'     => isset($advisory['name']) ? (string) $advisory['name'] : $id,
                'cves'     => isset($advisory['cves']) ? array_values((array) $advisory['cves']) : array(),
                'url'      => isset($advisory['url']) ? (string) $advisory['url'] : '',
                'status'   => $verdict['status'],
                'fixed_in' => $verdict['fixed_in'],
                'message'  => $message,
            );
            if ($rank[$verdict['status']] > $rank[$worst]) {
                $worst = $verdict['status'];
            }
            if ($verdict['status'] === 'affected') {
                $this->add($findings, $counts, 'high', $message, $id);
            } elseif ($verdict['status'] === 'unknown') {
                $this->add($findings, $counts, 'medium', $message, $id);
            }
        }

        if ($runtime['upload_progress'] === true) {
            $this->add(
                $findings,
                $counts,
                'medium',
                __(
                    'Set session.upload_progress.enabled=0 via php.ini or your host, as PHP advises (this also covers CVE-2026-115560).',
                    'nubivio-healthcare-security-hardening'
                ) . ' ' . __('This is a temporary measure and does not replace the update.', 'nubivio-healthcare-security-hardening')
            );
        }
        if ($runtime['fatal_error_backtraces'] === true) {
            $this->add(
                $findings,
                $counts,
                'low',
                __(
                    'fatal_error_backtraces is on (PHP 8.5). PHP advises setting fatal_error_backtraces=0 via php.ini or your host.',
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
                'advisories'             => $advisories,
            ),
        );
    }

    /**
     * Human-readable verdict. Never claims "vulnerable" for distribution builds.
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
            $parts = array(
                sprintf(
                    /* translators: 1: PHP version, 2: advisory name with CVE IDs. */
                    __('PHP %1$s includes the fix for %2$s.', 'nubivio-healthcare-security-hardening'),
                    $version,
                    $label
                ),
                __(
                    'After a PHP update, old PHP workers must have been restarted. With multiple servers, every server counts separately.',
                    'nubivio-healthcare-security-hardening'
                ),
            );
            return implode(' ', $parts);
        }

        if ($verdict['status'] === 'unknown') {
            if ($verdict['fixed_in'] === '') {
                return sprintf(
                    /* translators: 1: PHP version, 2: advisory name with CVE IDs. */
                    __('PHP %1$s could not be matched to the fixed releases for %2$s. Ask your host to confirm the fix is installed.', 'nubivio-healthcare-security-hardening'),
                    $version,
                    $label
                );
            }
            $parts = array(
                sprintf(
                    /* translators: 1: PHP version string with distribution suffix, 2: advisory name with CVE IDs. */
                    __('PHP %1$s is a distribution build, which may include a backported fix for %2$s.', 'nubivio-healthcare-security-hardening'),
                    $version,
                    $label
                ),
                __(
                    'Ask your host to compare the package version with the security advisory of the distribution.',
                    'nubivio-healthcare-security-hardening'
                ),
            );
            return implode(' ', $parts);
        }

        if (!empty($verdict['eol'])) {
            $parts = array(
                sprintf(
                    /* translators: 1: PHP version, 2: advisory name with CVE IDs. */
                    __('PHP %1$s is unsupported and no official PHP release fixes %2$s. Treat it as vulnerable unless your host applied a backport.', 'nubivio-healthcare-security-hardening'),
                    $version,
                    $label
                ),
                sprintf(
                    /* translators: %s: PHP branch, e.g. 8.3. */
                    __('An upgrade to PHP %s or later is required; ask your hosting provider.', 'nubivio-healthcare-security-hardening'),
                    $verdict['fixed_in']
                ),
            );
        } else {
            $parts = array(
                sprintf(
                    /* translators: 1: PHP version, 2: advisory name with CVE IDs, 3: first fixed PHP version on this branch. */
                    __('PHP %1$s is vulnerable to %2$s. Ask your hosting provider to update PHP to %3$s or later.', 'nubivio-healthcare-security-hardening'),
                    $version,
                    $label,
                    $verdict['fixed_in']
                ),
            );
        }
        if ($runtime['sapi'] === 'apache2handler') {
            $parts[] = __('This site runs on Apache mod_php, which carries the highest risk.', 'nubivio-healthcare-security-hardening');
        }
        return implode(' ', $parts);
    }

    /**
     * Row for the plugin's own Site health card: fail when affected, warn
     * when unknown or when session.upload_progress is on, pass otherwise.
     *
     * @param array $summary Summary from run().
     * @return array{label:string,status:string,detail:string}
     */
    public static function health_row($summary) {
        $status = isset($summary['status']) ? (string) $summary['status'] : 'unknown';
        $upload = isset($summary['upload_progress']) && $summary['upload_progress'] === true;
        if ($status === 'affected') {
            $row_status = 'fail';
        } elseif ($status === 'unknown' || $upload) {
            $row_status = 'warn';
        } else {
            $row_status = 'pass';
        }
        $detail = array();
        foreach ((array) (isset($summary['advisories']) ? $summary['advisories'] : array()) as $row) {
            $detail[] = (string) $row['message'];
        }
        if ($upload) {
            $detail[] = __('session.upload_progress.enabled is on.', 'nubivio-healthcare-security-hardening');
        }
        return array(
            'label'  => __('PHP runtime (PHP2Shell)', 'nubivio-healthcare-security-hardening'),
            'status' => $row_status,
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
            'label' => __('PHP runtime vulnerabilities (PHP2Shell)', 'nubivio-healthcare-security-hardening'),
            'test'  => array($this, 'site_health_test'),
        );
        return $tests;
    }

    /**
     * Site Health test callback: critical, recommended or good.
     *
     * @return array<string,mixed>
     */
    public function site_health_test() {
        $result  = $this->run();
        $summary = $result['summary'];
        $status  = $summary['status'];
        if ($status === 'patched' && $summary['upload_progress'] === true) {
            $status = 'unknown';
        }

        $labels    = array(
            'patched'  => __('Your PHP version includes the PHP2Shell fix', 'nubivio-healthcare-security-hardening'),
            'unknown'  => __('Check your PHP version for PHP2Shell with your host', 'nubivio-healthcare-security-hardening'),
            'affected' => __('Your PHP version is vulnerable to PHP2Shell', 'nubivio-healthcare-security-hardening'),
        );
        $wp_status = array('patched' => 'good', 'unknown' => 'recommended', 'affected' => 'critical');
        $colors    = array('patched' => 'blue', 'unknown' => 'orange', 'affected' => 'red');

        $description = '';
        foreach ($summary['advisories'] as $row) {
            $description .= '<p>' . esc_html($row['message']) . '</p>';
        }
        foreach ($result['findings'] as $finding) {
            if (empty($finding['advisory'])) {
                $description .= '<p>' . esc_html($finding['message']) . '</p>';
            }
        }
        $description .= '<p>' . esc_html(self::process_note()) . '</p>';

        return array(
            'label'       => $labels[$status],
            'status'      => $wp_status[$status],
            'badge'       => array(
                'label' => __('Security', 'nubivio-healthcare-security-hardening'),
                'color' => $colors[$status],
            ),
            'description' => $description,
            'actions'     => '<p><a href="https://github.com/NCSC-NL/php2shell" target="_blank" rel="noopener">'
                . esc_html__('NCSC-NL information about PHP2Shell', 'nubivio-healthcare-security-hardening') . '</a></p>',
            'test'        => self::SITE_HEALTH_ID,
        );
    }

    /**
     * Shared UI note about where the version comes from.
     *
     * @return string
     */
    public static function process_note() {
        return __(
            'This is the version of the PHP process that actually serves your site, not a guess from response headers. A plugin cannot fix PHP; only your hosting provider can update it.',
            'nubivio-healthcare-security-hardening'
        );
    }

    /**
     * Admin notice on the dashboard and the plugin pages, for administrators,
     * per affected advisory. Dismissed per user, advisory id and PHP_VERSION.
     *
     * @return void
     */
    public function maybe_admin_notice() {
        if (!current_user_can('manage_options') || !self::on_notice_screen()) {
            return;
        }
        $result  = $this->run();
        $user_id = get_current_user_id();
        foreach ($result['summary']['advisories'] as $id => $row) {
            if ($row['status'] !== 'affected') {
                continue;
            }
            if ((string) get_user_meta($user_id, self::DISMISS_META . $id, true) === PHP_VERSION) {
                continue;
            }
            $dismiss_url = wp_nonce_url(
                admin_url('admin-post.php?action=' . self::DISMISS_ACTION . '&advisory=' . rawurlencode($id)),
                self::DISMISS_ACTION . '_' . $id
            );
            echo '<div class="notice notice-error"><p><strong>'
                . esc_html(sprintf(
                    /* translators: %s: advisory name, e.g. PHP2Shell. */
                    __('Nubivio Healthcare Security Hardening: your PHP version is vulnerable to %s', 'nubivio-healthcare-security-hardening'),
                    $row['name']
                ))
                . '</strong></p><p>' . esc_html($row['message']) . '</p>'
                . '<p>' . esc_html(self::process_note()) . '</p><p>'
                . '<a href="' . esc_url($dismiss_url) . '">'
                . esc_html__('Hide for this PHP version', 'nubivio-healthcare-security-hardening')
                . '</a></p></div>';
        }
    }

    /**
     * Whether the current admin screen is the dashboard or a plugin page.
     *
     * @return bool
     */
    private static function on_notice_screen() {
        if (!function_exists('get_current_screen')) {
            return false;
        }
        $screen = get_current_screen();
        if (!$screen || !isset($screen->id)) {
            return false;
        }
        $allowed = array('dashboard', 'plugins', 'settings_page_' . Nubivio_HSH::SLUG);
        return in_array((string) $screen->id, $allowed, true);
    }

    /**
     * Dismiss the notice for the current user, advisory and PHP_VERSION.
     *
     * @return void
     */
    public function handle_dismiss() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to perform this action.', 'nubivio-healthcare-security-hardening'));
        }
        $id    = isset($_GET['advisory']) ? sanitize_key(wp_unslash($_GET['advisory'])) : '';
        $nonce = isset($_REQUEST['_wpnonce']) ? sanitize_text_field(wp_unslash($_REQUEST['_wpnonce'])) : '';
        if ($id === '' || !$nonce || !wp_verify_nonce($nonce, self::DISMISS_ACTION . '_' . $id)) {
            wp_die(esc_html__('Security check failed.', 'nubivio-healthcare-security-hardening'));
        }
        update_user_meta(get_current_user_id(), self::DISMISS_META . $id, PHP_VERSION);
        $back = wp_get_referer();
        wp_safe_redirect($back ? $back : admin_url());
        exit;
    }

    /**
     * Append a finding and bump its counter.
     *
     * @param array  $findings Findings list.
     * @param array  $counts   Counters.
     * @param string $severity high, medium or low.
     * @param string $message  Message.
     * @param string $advisory Advisory id, empty for ini signals.
     * @return void
     */
    private function add(&$findings, &$counts, $severity, $message, $advisory = '') {
        $finding = array(
            'severity' => $severity,
            'message'  => $message,
            'controls' => array('A.8.8'),
        );
        if ($advisory !== '') {
            $finding['advisory'] = $advisory;
        }
        $findings[] = $finding;
        $counts[$severity]++;
    }
}
