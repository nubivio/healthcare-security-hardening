<?php
/**
 * Plugin Name:       Nubivio Healthcare Security Hardening
 * Plugin URI:        https://github.com/nubivio/healthcare-security-hardening
 * Description:       Security headers, a self-renewing security.txt (RFC 9116) and advanced form protection for healthcare related WordPress sites. Built for general practitioners, psychologists and other healthcare professionals. Recommended for NIS2, GDPR & NEN7510 compliance.
 * Version:           2.2.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Nubivio
 * Author URI:        https://nubivio.com/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       nubivio-healthcare-security-hardening
 *
 * Note: the plugin folder/slug is "nubivio-healthcare-security-hardening", so this
 * Text Domain matches the slug. Plugin Check may warn when run from a differently
 * named folder; that is expected until the directory uses the final slug.
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Nubivio_HSH {

    const VERSION     = '2.2.0';
    const OPTION      = 'nubivio_hsh_options';
    const SCAN_OPTION = 'nubivio_hsh_scan';
    const CRON_HOOK   = 'nubivio_hsh_daily';
    const SLUG        = 'nubivio-healthcare-security-hardening';
    const SCAN_ACTION = 'nubivio_hsh_run_scan';

    /** @var Nubivio_HSH|null */
    private static $instance = null;

    /** @var Nubivio_HSH_Scanner|null */
    private $scanner = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->load_includes();

        add_action('init', array($this, 'load_textdomain'));
        add_action('send_headers', array($this, 'send_security_headers'));
        add_action('init', array($this, 'maybe_serve_well_known'), 1);

        add_filter('gform_field_validation', array($this, 'validate_blocked_domains'), 10, 4);

        add_action('admin_menu', array($this, 'register_settings_page'));
        add_action('admin_init', array($this, 'handle_form_submit'));
        add_action('admin_init', array($this, 'maybe_refresh_security_txt_file'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'settings_link'));

        // Compliance scan + document generation (admin only).
        add_action('admin_post_' . self::SCAN_ACTION, array($this, 'handle_run_scan'));
        add_action('admin_post_nubivio_hsh_doc', array($this, 'handle_download_doc'));

        add_action(self::CRON_HOOK, array($this, 'write_security_txt_file'));
        add_action(self::CRON_HOOK, array($this, 'run_scheduled_scan'));
    }

    /**
     * Load the compliance module classes. Guarded so a missing file never
     * fatals the whole plugin; the hardening core keeps working regardless.
     */
    private function load_includes() {
        $dir = plugin_dir_path(__FILE__) . 'includes/';
        foreach (array(
            'class-cra.php',
            'class-gdpr.php',
            'class-nis2.php',
            'class-health.php',
            'class-score.php',
            'class-scanner.php',
            'class-docs.php',
        ) as $file) {
            if (file_exists($dir . $file)) {
                require_once $dir . $file;
            }
        }
    }

    public function load_textdomain() {
        load_plugin_textdomain(
            'nubivio-healthcare-security-hardening',
            false,
            dirname(plugin_basename(__FILE__)) . '/languages'
        );
    }

    /**
     * Lazily build and return the scanner orchestrator.
     *
     * @return Nubivio_HSH_Scanner|null
     */
    public function scanner() {
        if ($this->scanner === null && class_exists('Nubivio_HSH_Scanner')) {
            $this->scanner = new Nubivio_HSH_Scanner($this);
        }
        return $this->scanner;
    }

    /* Activation / deactivation / uninstall */

    public static function activate() {
        $self = self::instance();
        if (get_option(self::OPTION) === false) {
            update_option(self::OPTION, $self->get_defaults());
        }
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 3600, 'daily', self::CRON_HOOK);
        }
        $self->write_security_txt_file();
    }

    public static function deactivate() {
        wp_clear_scheduled_hook(self::CRON_HOOK);
        self::instance()->delete_security_txt_file();
        self::instance()->delete_pgp_key_file();
    }

    public static function uninstall() {
        delete_option(self::OPTION);
        delete_option(self::SCAN_OPTION);
        delete_transient('nubivio_hsh_sectxt_checked');
        delete_transient('nubivio_hsh_headers_probe');
        delete_transient('nubivio_hsh_frontend_scripts');
        delete_transient('nubivio_hsh_scan_running');
        delete_transient('nubivio_hsh_scan_cooldown');
        // Clear any per-plugin WP.org metadata caches created by the CRA scan.
        if (function_exists('wp_cache_flush')) {
            // Transients with a dynamic slug suffix are removed on natural expiry (12h).
            wp_cache_flush();
        }
        wp_clear_scheduled_hook(self::CRON_HOOK);
        self::instance()->delete_security_txt_file();
        self::instance()->delete_pgp_key_file();
    }

    /* Options */

    public function get_defaults() {
        return array(
            // Headers
            'hsts_enabled'        => 1,
            'hsts_max_age'        => 31536000,
            'hsts_subdomains'     => 1,
            'hsts_preload'        => 0,

            'csp_enabled'         => 0,
            'csp_report_only'     => 1,
            'csp_policy'          => $this->default_csp(),

            'referrer_enabled'    => 1,
            'referrer_value'      => 'strict-origin-when-cross-origin',

            'nosniff_enabled'     => 1,

            'xfo_enabled'         => 1,
            'xfo_value'           => 'SAMEORIGIN',

            'permissions_enabled' => 1,
            'permissions_value'   => $this->default_permissions_policy(),

            'strip_legacy'        => 1,

            // security.txt
            'sectxt_enabled'      => 1,
            'sectxt_contacts'     => get_option('admin_email'),
            'sectxt_expires_days' => 180,
            'sectxt_languages'    => 'nl, en',
            'sectxt_note'         => 'Responsible disclosure is welcome here. We read every report.',
            'sectxt_encryption'   => '',
            'sectxt_pgp'          => '',
            'sectxt_policy'       => '',
            'sectxt_ack'          => '',
            'sectxt_hiring'       => '',
            'sectxt_csaf'         => '',
            'sectxt_love'         => 1,

            // Gravity Forms
            'gf_block_enabled'    => 0,
            'gf_block_domains'    => '',
            'gf_block_message'    => 'Email addresses from this domain are not allowed.',

            // Compliance (v2.2.0). Additive: no existing behaviour changes when untouched.
            'scan_frameworks'     => array('cra', 'gdpr', 'nis2', 'health'),
            'scan_on_cron'        => 0,
            'vdp_synced'          => 0,
            'patchstack_key'      => '', // reserved for a future opt-in phase; unused today
        );
    }

    public function get_options() {
        $saved = get_option(self::OPTION);
        if (!is_array($saved)) {
            $saved = array();
        }
        return wp_parse_args($saved, $this->get_defaults());
    }

    private function default_csp() {
        return "default-src 'self'; base-uri 'self'; object-src 'none'; "
             . "frame-ancestors 'self'; frame-src 'self'; form-action 'self'; "
             . "img-src 'self' data:; script-src 'self'; style-src 'self'; "
             . "font-src 'self'; connect-src 'self'; upgrade-insecure-requests";
    }

    private function default_permissions_policy() {
        return 'geolocation=(), camera=(), microphone=(), payment=(), usb=(), '
             . 'accelerometer=(), gyroscope=(), magnetometer=()';
    }

    /* Headers */

    public function send_security_headers() {
        if (is_admin()) {
            return;
        }
        $o = $this->get_options();

        if (!empty($o['strip_legacy']) && function_exists('header_remove')) {
            header_remove('X-XSS-Protection');
            header_remove('Expect-CT');
        }

        if (!empty($o['hsts_enabled']) && is_ssl()) {
            $hsts = 'max-age=' . (int) $o['hsts_max_age'];
            if (!empty($o['hsts_subdomains'])) {
                $hsts .= '; includeSubDomains';
            }
            if (!empty($o['hsts_preload'])) {
                $hsts .= '; preload';
            }
            header('Strict-Transport-Security: ' . $hsts);
        }

        if (!empty($o['csp_enabled']) && trim($o['csp_policy']) !== '') {
            $name = !empty($o['csp_report_only'])
                ? 'Content-Security-Policy-Report-Only'
                : 'Content-Security-Policy';
            header($name . ': ' . $this->clean_header_value($o['csp_policy']));
        }

        if (!empty($o['referrer_enabled'])) {
            header('Referrer-Policy: ' . $this->clean_header_value($o['referrer_value']));
        }

        if (!empty($o['nosniff_enabled'])) {
            header('X-Content-Type-Options: nosniff');
        }

        if (!empty($o['xfo_enabled'])) {
            header('X-Frame-Options: ' . $this->clean_header_value($o['xfo_value']));
        }

        if (!empty($o['permissions_enabled']) && trim($o['permissions_value']) !== '') {
            header('Permissions-Policy: ' . $this->clean_header_value($o['permissions_value']));
        }
    }

    private function clean_header_value($value) {
        return trim(str_replace(array("\r", "\n"), ' ', (string) $value));
    }

    public function preview_headers() {
        $o = $this->get_options();
        $out = array();

        if (!empty($o['hsts_enabled'])) {
            $hsts = 'max-age=' . (int) $o['hsts_max_age'];
            if (!empty($o['hsts_subdomains'])) $hsts .= '; includeSubDomains';
            if (!empty($o['hsts_preload']))    $hsts .= '; preload';
            $out['Strict-Transport-Security'] = $hsts . '   (HTTPS only)';
        }
        if (!empty($o['csp_enabled']) && trim($o['csp_policy']) !== '') {
            $name = !empty($o['csp_report_only']) ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
            $out[$name] = $this->clean_header_value($o['csp_policy']);
        }
        if (!empty($o['referrer_enabled']))    $out['Referrer-Policy'] = $o['referrer_value'];
        if (!empty($o['nosniff_enabled']))     $out['X-Content-Type-Options'] = 'nosniff';
        if (!empty($o['xfo_enabled']))         $out['X-Frame-Options'] = $o['xfo_value'];
        if (!empty($o['permissions_enabled'])) $out['Permissions-Policy'] = $o['permissions_value'];

        return $out;
    }

    /* security.txt (RFC 9116) */

    /**
     * Absolute filesystem path to the public site root.
     *
     * Uses get_home_path() so the file lands at the public home directory,
     * which can differ from ABSPATH on subdirectory / giving-WordPress-its-own-directory installs.
     */
    private function home_path() {
        if (!function_exists('get_home_path')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        return rtrim(get_home_path(), '/\\');
    }

    /**
     * Initialise and return the WP_Filesystem instance.
     *
     * All file reads, writes and deletes go through this so the plugin uses the
     * WP_Filesystem API instead of direct PHP filesystem calls.
     *
     * @return WP_Filesystem_Base|null
     */
    private function fs() {
        global $wp_filesystem;
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        if (!WP_Filesystem()) {
            return null;
        }
        return $wp_filesystem;
    }

    private function security_txt_path() {
        return $this->home_path() . '/.well-known/security.txt';
    }

    private function security_txt_dir() {
        return $this->home_path() . '/.well-known';
    }

    public function canonical_url() {
        return set_url_scheme(home_url('/.well-known/security.txt'), 'https');
    }

    public function build_security_txt() {
        $o = $this->get_options();
        $days = max(1, (int) $o['sectxt_expires_days']);
        $expires = gmdate('Y-m-d\TH:i:s\Z', time() + ($days * DAY_IN_SECONDS));

        $lines = array();
        $lines[] = '# This file is generated automatically and refreshed periodically.';

        foreach (preg_split('/[\r\n]+/', (string) $o['sectxt_note']) as $note) {
            $note = trim($note);
            if ($note !== '') {
                $lines[] = '# ' . ltrim($note, '# ');
            }
        }

        foreach (preg_split('/[\r\n]+/', (string) $o['sectxt_contacts']) as $c) {
            $c = trim($c);
            if ($c === '') {
                continue;
            }
            if (!preg_match('#^(https?:|mailto:|tel:)#i', $c)) {
                $c = (strpos($c, '@') !== false) ? 'mailto:' . $c : 'https://' . $c;
            }
            $lines[] = 'Contact: ' . $c;
        }

        $lines[] = 'Expires: ' . $expires;

        $encryption = trim($o['sectxt_encryption']);
        if ($encryption === '' && $this->build_pgp_key() !== '') {
            $encryption = $this->pgp_key_url();
        }
        if ($encryption !== '')                   $lines[] = 'Encryption: ' . $encryption;
        if (trim($o['sectxt_ack']) !== '')        $lines[] = 'Acknowledgments: ' . trim($o['sectxt_ack']);
        if (trim($o['sectxt_policy']) !== '')     $lines[] = 'Policy: ' . trim($o['sectxt_policy']);
        if (trim($o['sectxt_hiring']) !== '')     $lines[] = 'Hiring: ' . trim($o['sectxt_hiring']);
        if (trim($o['sectxt_csaf']) !== '')       $lines[] = 'CSAF: ' . trim($o['sectxt_csaf']);
        if (trim($o['sectxt_languages']) !== '')  $lines[] = 'Preferred-Languages: ' . trim($o['sectxt_languages']);

        $lines[] = 'Canonical: ' . $this->canonical_url();

        if (!empty($o['sectxt_love'])) {
            $lines[] = '# Hardened by Nubivio · boring, predictable security · https://nubivio.com';
        }

        // CRLF with a trailing terminator, per RFC 9116.
        return implode("\r\n", $lines) . "\r\n";
    }

    public function write_security_txt_file() {
        $o = $this->get_options();
        if (empty($o['sectxt_enabled']) || trim($o['sectxt_contacts']) === '') {
            $this->delete_security_txt_file();
            $this->delete_pgp_key_file();
            return false;
        }
        $fs = $this->fs();
        if (!$fs) {
            return false;
        }
        $dir = $this->security_txt_dir();
        if (!$fs->is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        if (!$fs->is_dir($dir) || !$fs->is_writable($dir)) {
            return false;
        }
        $this->write_pgp_key_file();
        return $fs->put_contents($this->security_txt_path(), $this->build_security_txt(), FS_CHMOD_FILE);
    }

    /* PGP public key (hosted, linked from security.txt as Encryption) */

    private function pgp_key_path() {
        return $this->home_path() . '/.well-known/openpgp-key.txt';
    }

    public function pgp_key_url() {
        return set_url_scheme(home_url('/.well-known/openpgp-key.txt'), 'https');
    }

    public function build_pgp_key() {
        $key = trim((string) $this->get_options()['sectxt_pgp']);
        if ($key === '' || strpos($key, 'BEGIN PGP PUBLIC KEY BLOCK') === false) {
            return '';
        }
        return $key . "\n";
    }

    public function write_pgp_key_file() {
        $key = $this->build_pgp_key();
        if ($key === '') {
            $this->delete_pgp_key_file();
            return false;
        }
        $fs = $this->fs();
        if (!$fs) {
            return false;
        }
        $dir = $this->security_txt_dir();
        if (!$fs->is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        if (!$fs->is_dir($dir) || !$fs->is_writable($dir)) {
            return false;
        }
        return $fs->put_contents($this->pgp_key_path(), $key, FS_CHMOD_FILE);
    }

    public function delete_pgp_key_file() {
        $fs = $this->fs();
        $path = $this->pgp_key_path();
        if ($fs && $fs->exists($path)) {
            wp_delete_file($path);
        }
    }

    public function delete_security_txt_file() {
        $fs = $this->fs();
        $path = $this->security_txt_path();
        if ($fs && $fs->exists($path)) {
            wp_delete_file($path);
        }
    }

    public function maybe_refresh_security_txt_file() {
        $o = $this->get_options();
        if (empty($o['sectxt_enabled']) || get_transient('nubivio_hsh_sectxt_checked')) {
            return;
        }
        set_transient('nubivio_hsh_sectxt_checked', 1, 12 * HOUR_IN_SECONDS);

        $path = $this->security_txt_path();
        $refresh = true;
        $fs = $this->fs();
        if ($fs && $fs->exists($path)) {
            $content = (string) $fs->get_contents($path);
            if (preg_match('/^Expires:\s*(.+)$/mi', $content, $m)) {
                $ts = strtotime(trim($m[1]));
                if ($ts && $ts - time() > 30 * DAY_IN_SECONDS) {
                    $refresh = false;
                }
            }
        }
        if ($refresh) {
            $this->write_security_txt_file();
        }
    }

    public function maybe_serve_well_known() {
        if (empty($_SERVER['REQUEST_URI'])) {
            return;
        }
        $path = wp_parse_url(esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])), PHP_URL_PATH);
        $o = $this->get_options();

        if ($path === '/.well-known/security.txt') {
            if (empty($o['sectxt_enabled']) || trim($o['sectxt_contacts']) === '') {
                return;
            }
            if (!headers_sent()) {
                header('Content-Type: text/plain; charset=utf-8');
                header('X-Robots-Tag: noindex');
            }
            echo $this->build_security_txt(); // phpcs:ignore WordPress.Security.EscapeOutput
            exit;
        }

        if ($path === '/.well-known/openpgp-key.txt') {
            $key = $this->build_pgp_key();
            if ($key === '') {
                return;
            }
            if (!headers_sent()) {
                header('Content-Type: application/pgp-keys; charset=utf-8');
                header('X-Robots-Tag: noindex');
            }
            echo $key; // phpcs:ignore WordPress.Security.EscapeOutput
            exit;
        }
    }

    public function security_txt_status() {
        $path = $this->security_txt_path();
        $fs = $this->fs();
        if (!$fs || !$fs->exists($path)) {
            return array('mode' => 'dynamic', 'expires' => null, 'days' => null);
        }
        $content = (string) $fs->get_contents($path);
        $expires = null;
        $days = null;
        if (preg_match('/^Expires:\s*(.+)$/mi', $content, $m)) {
            $ts = strtotime(trim($m[1]));
            if ($ts) {
                $expires = gmdate('Y-m-d H:i', $ts) . ' UTC';
                $days = (int) floor(($ts - time()) / DAY_IN_SECONDS);
            }
        }
        return array('mode' => 'file', 'expires' => $expires, 'days' => $days);
    }

    /* Gravity Forms */

    public function validate_blocked_domains($result, $value, $form, $field) {
        $o = $this->get_options();
        if (empty($o['gf_block_enabled']) || !isset($field->type) || $field->type !== 'email') {
            return $result;
        }
        $domains = preg_split('/[\r\n,]+/', (string) $o['gf_block_domains']);
        $email = is_array($value) ? reset($value) : $value;
        $email = strtolower(trim((string) $email));
        if ($email === '') {
            return $result;
        }
        foreach ($domains as $d) {
            $d = strtolower(trim($d));
            if ($d === '') {
                continue;
            }
            if (preg_match('/@' . preg_quote($d, '/') . '$/i', $email)) {
                $result['is_valid'] = false;
                $result['message']  = $o['gf_block_message'] !== '' ? $o['gf_block_message'] : __('This email domain is not allowed.', 'nubivio-healthcare-security-hardening');
                break;
            }
        }
        return $result;
    }

    private function gravity_forms_active() {
        return class_exists('GFForms') || class_exists('GFCommon');
    }

    /* Admin */

    public function settings_link($links) {
        $url = admin_url('options-general.php?page=' . self::SLUG);
        array_unshift($links, '<a href="' . esc_url($url) . '">' . esc_html__('Settings', 'nubivio-healthcare-security-hardening') . '</a>');
        return $links;
    }

    public function register_settings_page() {
        $this->page_hook = add_options_page(
            __('Nubivio Healthcare Security Hardening', 'nubivio-healthcare-security-hardening'),
            __('Nubivio Security', 'nubivio-healthcare-security-hardening'),
            'manage_options',
            self::SLUG,
            array($this, 'render_settings_page')
        );
    }

    /** @var string|null */
    private $page_hook = null;

    public function enqueue_admin_assets($hook) {
        if ($this->page_hook === null || $hook !== $this->page_hook) {
            return;
        }
        wp_enqueue_style(
            'nubivio-hsh-admin',
            plugins_url('assets/admin.css', __FILE__),
            array(),
            self::VERSION
        );
        wp_enqueue_script(
            'nubivio-hsh-admin',
            plugins_url('assets/admin.js', __FILE__),
            array(),
            self::VERSION,
            true
        );
    }

    public function handle_form_submit() {
        if (!isset($_POST['nubivio_hsh_nonce']) || !current_user_can('manage_options')) {
            return;
        }
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nubivio_hsh_nonce'])), 'nubivio_hsh_save')) {
            return;
        }

        $in = wp_unslash($_POST);
        $d  = $this->get_defaults();
        $clean = array();

        foreach (array(
            'hsts_enabled','hsts_subdomains','hsts_preload',
            'csp_enabled','csp_report_only','referrer_enabled','nosniff_enabled',
            'xfo_enabled','permissions_enabled','strip_legacy',
            'sectxt_enabled','sectxt_love','gf_block_enabled',
        ) as $key) {
            $clean[$key] = empty($in[$key]) ? 0 : 1;
        }

        $clean['hsts_max_age']        = isset($in['hsts_max_age']) ? max(0, (int) $in['hsts_max_age']) : $d['hsts_max_age'];
        $clean['sectxt_expires_days'] = isset($in['sectxt_expires_days']) ? max(1, (int) $in['sectxt_expires_days']) : $d['sectxt_expires_days'];

        $clean['referrer_value']    = isset($in['referrer_value']) ? sanitize_text_field($in['referrer_value']) : $d['referrer_value'];
        $clean['xfo_value']         = isset($in['xfo_value']) ? sanitize_text_field($in['xfo_value']) : $d['xfo_value'];
        $clean['sectxt_languages']  = isset($in['sectxt_languages']) ? sanitize_text_field($in['sectxt_languages']) : $d['sectxt_languages'];
        $clean['sectxt_encryption'] = esc_url_raw($in['sectxt_encryption'] ?? '');
        $clean['sectxt_policy']     = esc_url_raw($in['sectxt_policy'] ?? '');
        $clean['sectxt_ack']        = esc_url_raw($in['sectxt_ack'] ?? '');
        $clean['sectxt_hiring']     = esc_url_raw($in['sectxt_hiring'] ?? '');
        $clean['sectxt_csaf']       = esc_url_raw($in['sectxt_csaf'] ?? '');
        $clean['gf_block_message']  = isset($in['gf_block_message']) ? sanitize_text_field($in['gf_block_message']) : $d['gf_block_message'];

        $clean['csp_policy']        = $this->sanitize_multiline($in['csp_policy'] ?? $d['csp_policy'], true);
        $clean['permissions_value'] = $this->sanitize_multiline($in['permissions_value'] ?? $d['permissions_value'], true);
        $clean['sectxt_contacts']   = $this->sanitize_multiline($in['sectxt_contacts'] ?? $d['sectxt_contacts'], false);
        $clean['sectxt_note']       = $this->sanitize_multiline($in['sectxt_note'] ?? $d['sectxt_note'], false);
        $clean['sectxt_pgp']        = $this->sanitize_multiline($in['sectxt_pgp'] ?? '', false);
        $clean['gf_block_domains']  = $this->sanitize_multiline($in['gf_block_domains'] ?? $d['gf_block_domains'], false);

        update_option(self::OPTION, wp_parse_args($clean, $d));

        delete_transient('nubivio_hsh_sectxt_checked');
        $this->write_security_txt_file();

        wp_safe_redirect(add_query_arg(array('page' => self::SLUG, 'updated' => '1'), admin_url('options-general.php')));
        exit;
    }

    private function sanitize_multiline($value, $single_line) {
        $value = wp_strip_all_tags((string) $value);
        if ($single_line) {
            $value = trim(preg_replace('/\s+/', ' ', str_replace(array("\r", "\n"), ' ', $value)));
        } else {
            $value = trim(str_replace("\r\n", "\n", $value));
        }
        return $value;
    }

    /* Compliance: scan + documents */

    /**
     * Latest stored scan result set, or null if the site has never scanned.
     *
     * @return array|null
     */
    public function get_scan() {
        $scan = get_option(self::SCAN_OPTION);
        return is_array($scan) ? $scan : null;
    }

    /**
     * Handle the admin-triggered "Run scan" POST. Nonce + capability gated,
     * with a short cooldown and a concurrency lock, then POST-redirect-GET.
     */
    public function handle_run_scan() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to run a compliance scan.', 'nubivio-healthcare-security-hardening'));
        }
        check_admin_referer(self::SCAN_ACTION);

        $redirect = add_query_arg(
            array('page' => self::SLUG, 'tab' => 'compliance'),
            admin_url('options-general.php')
        );

        $scanner = $this->scanner();
        if (!$scanner) {
            wp_safe_redirect(add_query_arg('scan', 'unavailable', $redirect));
            exit;
        }

        if (get_transient('nubivio_hsh_scan_cooldown')) {
            wp_safe_redirect(add_query_arg('scan', 'cooldown', $redirect));
            exit;
        }
        if (get_transient('nubivio_hsh_scan_running')) {
            wp_safe_redirect(add_query_arg('scan', 'running', $redirect));
            exit;
        }

        set_transient('nubivio_hsh_scan_running', 1, 2 * MINUTE_IN_SECONDS);
        $result = $scanner->run();
        update_option(self::SCAN_OPTION, $result);
        delete_transient('nubivio_hsh_scan_running');
        set_transient('nubivio_hsh_scan_cooldown', 1, 5 * MINUTE_IN_SECONDS);

        wp_safe_redirect(add_query_arg('scan', 'done', $redirect));
        exit;
    }

    /**
     * Scheduled scan hook body: only runs when the user opted in, and never
     * more often than the cooldown allows.
     */
    public function run_scheduled_scan() {
        $o = $this->get_options();
        if (empty($o['scan_on_cron']) || get_transient('nubivio_hsh_scan_cooldown')) {
            return;
        }
        $scanner = $this->scanner();
        if (!$scanner) {
            return;
        }
        set_transient('nubivio_hsh_scan_running', 1, 2 * MINUTE_IN_SECONDS);
        update_option(self::SCAN_OPTION, $scanner->run());
        delete_transient('nubivio_hsh_scan_running');
        set_transient('nubivio_hsh_scan_cooldown', 1, HOUR_IN_SECONDS);
    }

    /**
     * Stream a generated compliance document (VDP, SBOM, conformity, report).
     */
    public function handle_download_doc() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to download compliance documents.', 'nubivio-healthcare-security-hardening'));
        }
        check_admin_referer('nubivio_hsh_doc');

        $type = isset($_GET['doc']) ? sanitize_key(wp_unslash($_GET['doc'])) : '';
        if (!class_exists('Nubivio_HSH_Docs')) {
            wp_die(esc_html__('The document generator is unavailable.', 'nubivio-healthcare-security-hardening'));
        }
        $docs = new Nubivio_HSH_Docs($this);
        $docs->stream($type); // sends headers + body, then exits
        exit;
    }

    private function cb($key, $label, $opts, $desc = '') {
        $checked = !empty($opts[$key]) ? 'checked' : '';
        echo '<label class="ns-toggle"><input type="checkbox" name="' . esc_attr($key) . '" value="1" ' . esc_attr($checked) . '><span class="ns-track"></span><span class="ns-label">' . esc_html($label) . '</span></label>';
        if ($desc) {
            echo '<p class="ns-desc">' . wp_kses_post($desc) . '</p>';
        }
    }

    private function txt($key, $opts, $placeholder = '', $type = 'text') {
        echo '<input type="' . esc_attr($type) . '" name="' . esc_attr($key) . '" value="' . esc_attr($opts[$key]) . '" placeholder="' . esc_attr($placeholder) . '" class="ns-input">';
    }

    private function area($key, $opts, $rows = 3) {
        echo '<textarea name="' . esc_attr($key) . '" rows="' . (int) $rows . '" class="ns-input ns-area">' . esc_textarea($opts[$key]) . '</textarea>';
    }

    private function logo_svg() {
        // Nubivio wordmark, recolored white via CSS for the dark header.
        return '<svg class="ns-logo-svg" viewBox="600 740 1610 240" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Nubivio">'
            . '<path d="M807.14,965.13c-40.44,0-73.7-31.93-74.13-71.18-.22-19.51,7.27-37.87,21.08-51.68,12.68-12.68,29.25-20.05,47.01-20.99.43.53.89,1.05,1.39,1.55,6.93,6.93,17.72,7.61,25.43,2.08.87-.62,1.7-1.3,2.48-2.08,7.71-7.71,7.71-20.2,0-27.91-7.71-7.71-20.2-7.71-27.91,0-.78.78-1.46,1.62-2.08,2.48-.78,1.08-1.43,2.22-1.96,3.4-22.25,1.54-42.98,10.94-58.92,26.89-17.77,17.77-27.41,41.38-27.14,66.49.56,50.5,43.06,91.58,94.75,91.58h36.08c-6.42-6.3-12.21-13.19-17.37-20.62h-18.71Z"></path>'
            . '<path d="M844.33,791.01c13.65-22.13,38-36.28,65.22-36.28,18.33,0,36.46,6.28,50.37,18.34,27.73,24.06,35.98,67.22,30.84,102.12-.08.54-.18,1.09-.26,1.63-4.93,1.43-9.32,4.76-11.94,9.63-5.14,9.61-1.52,21.58,8.09,26.72,9.6,5.14,21.56,1.52,26.71-8.09,4.07-7.59,2.64-16.66-2.9-22.67.17-.98.42-2.43.69-4.18,1.43-9.42,5.49-36.12-2.02-63.25-2.46-8.9-11.22-38.85-40.33-60.35-6.74-4.98-28.17-20.35-59.26-20.5-7.91-.04-23.39.98-40.41,8.71-16.61,7.55-30.81,19.66-40.88,34.99,4.21,1.69,8.16,4.24,11.57,7.66,1.72,1.72,3.21,3.57,4.49,5.52Z"></path>'
            . '<path d="M1037.06,800.57l-16.39-.45c2.53,7.24,4.25,14.23,5.38,20.76l10.73.29c40.92,0,74.4,32.12,74.61,71.58.1,19.37-7.39,37.57-21.1,51.28s-31.67,21.1-50.88,21.1h-105.19c-8.41,0-16.82,0-25.23-.02-7.16,0-14.23.18-21.28-1.36-12.58-2.76-24.14-9.61-32.43-19.5-2.02-2.4-3.83-4.97-5.41-7.67-.29-.51-.59-1.03-.9-1.55,0-.8.02-1.75.02-2.56,2.85-4.6,3.83-10.38,2.07-16.16-2.61-8.62-11.04-14.47-20.04-13.89-11.97.77-20.27,11.68-18.25,23.13,1.49,8.51,8.23,14.74,16.29,16.04.66,1.25,1.35,2.48,2.03,3.7,3.84,6.76,7.8,13.46,12.96,19.11,7.9,8.6,16.49,13.57,26.96,17.01,11.15,3.67,22.65,3.77,34.25,4.12,20.76.61,41.53.22,62.29.22h71.85c24.72,0,47.97-9.64,65.46-27.14,17.62-17.64,27.27-41.06,27.12-65.97-.27-50.77-42.98-92.09-94.94-92.07Z"></path>'
            . '<path d="M838.12,835.1c.7,18.47,7.4,92.08,69.56,115.26,71.29-26.58,69.64-119.5,69.64-119.5-39.18-2.03-69.58-22.7-69.64-25.38-.06,2.55-27.77,21.49-64.36,24.97-1.74.17-3.5.31-5.28.4,0,0-.03,1.53.08,4.24ZM894.91,863.28c0-6.83,5.72-12.36,12.77-12.36s12.77,5.54,12.77,12.36c0,4.49-2.5,8.38-6.19,10.55l6.19,22.74h-25.54l6.19-22.74c-3.7-2.17-6.19-6.06-6.19-10.55Z"></path>'
            . '<path d="M1314.89,826.43c34.35,0,46.19,10.67,46.19,39.2v63.07c0,2.91-1.36,4.27-4.27,4.27h-19.02c-2.72,0-4.27-1.36-4.27-4.27v-56.28c0-17.27-3.88-21.35-19.99-21.35h-51.62c-16.69,0-21.15,4.85-21.15,21.35v56.28c0,2.91-1.36,4.27-4.27,4.27h-19.02c-2.91,0-4.27-1.36-4.27-4.27v-63.07c0-28.53,11.84-39.2,46-39.2h55.7Z"></path>'
            . '<path d="M1408.04,826.43c2.91,0,4.27,1.55,4.27,4.27v56.48c0,17.08,3.88,21.15,19.99,21.15h49.88c16.69,0,21.35-4.66,21.35-21.15v-56.48c0-2.72,1.55-4.27,4.27-4.27h19.02c2.91,0,4.27,1.55,4.27,4.27v63.07c0,28.72-11.84,39.2-46.19,39.2h-54.15c-34.16,0-46-10.48-46-39.2v-63.07c0-2.72,1.36-4.27,4.27-4.27h19.02Z"></path>'
            . '<path d="M1578.05,787.42c2.91,0,4.27,1.36,4.27,4.27v34.74h72.78c33.96,0,46.19,10.29,46.19,39.2v28.14c0,28.92-12.23,39.2-46.19,39.2h-54.34c-33.96,0-46-10.29-46-39.2v-102.08c0-2.91,1.36-4.27,4.27-4.27h19.02ZM1582.32,888.33c0,16.5,4.46,20.57,21.15,20.57h48.91c16.88,0,21.35-4.07,21.35-20.57v-17.27c0-16.3-4.46-20.57-21.35-20.57h-70.06v37.84Z"></path>'
            . '<path d="M1747.67,787.03c2.91,0,4.27,1.36,4.27,4.27v18.44c0,2.91-1.36,4.46-4.27,4.46h-19.02c-2.91,0-4.27-1.55-4.27-4.46v-18.44c0-2.91,1.36-4.27,4.27-4.27h19.02ZM1747.67,826.43c2.72,0,4.27,1.55,4.27,4.27v98.01c0,2.91-1.55,4.27-4.27,4.27h-19.02c-2.91,0-4.27-1.36-4.27-4.27v-98.01c0-2.72,1.36-4.27,4.27-4.27h19.02Z"></path>'
            . '<path d="M1792.69,826.43c2.33,0,3.69.78,4.66,2.72l46,80.15c.78,1.17.97,1.17,1.94,1.17h.97c.97,0,1.36,0,1.94-1.17l45.8-80.15c.97-1.94,2.13-2.72,4.46-2.72h21.35c2.72,0,3.88,2.33,2.72,4.85l-53.18,92.96c-3.49,6.4-7.76,8.73-16.3,8.73h-15.72c-8.73,0-12.61-2.33-16.11-8.73l-53.56-92.96c-1.55-2.52-.19-4.85,2.52-4.85h22.51Z"></path>'
            . '<path d="M1961.14,787.03c2.91,0,4.27,1.36,4.27,4.27v18.44c0,2.91-1.36,4.46-4.27,4.46h-19.02c-2.91,0-4.27-1.55-4.27-4.46v-18.44c0-2.91,1.36-4.27,4.27-4.27h19.02ZM1961.14,826.43c2.72,0,4.27,1.55,4.27,4.27v98.01c0,2.91-1.55,4.27-4.27,4.27h-19.02c-2.91,0-4.27-1.36-4.27-4.27v-98.01c0-2.72,1.36-4.27,4.27-4.27h19.02Z"></path>'
            . '<path d="M2089.42,826.43c33.96,0,46.19,10.29,46.19,39.2v28.14c0,28.92-12.23,39.2-46.19,39.2h-54.92c-33.96,0-46-10.29-46-39.2v-28.14c0-28.92,12.03-39.2,46-39.2h54.92ZM2016.06,888.92c0,16.3,4.27,20.38,21.15,20.38h49.49c17.08,0,21.35-4.07,21.35-20.38v-18.44c0-16.11-4.27-20.18-21.35-20.18h-49.49c-16.88,0-21.15,4.07-21.15,20.18v18.44Z"></path>'
            . '</svg>';
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $o = $this->get_options();
        $status = $this->security_txt_status();
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        $internetnl = 'https://internet.nl/site/' . rawurlencode($host) . '/';
        $saved = isset($_GET['updated']); // phpcs:ignore WordPress.Security.NonceVerification
        $tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'hardening'; // phpcs:ignore WordPress.Security.NonceVerification
        if (!in_array($tab, array('hardening', 'compliance'), true)) {
            $tab = 'hardening';
        }
        $scan = $this->get_scan();
        $base_url = admin_url('options-general.php?page=' . self::SLUG);
        $hardening_url  = add_query_arg('tab', 'hardening', $base_url);
        $compliance_url = add_query_arg('tab', 'compliance', $base_url);
        ?>
        <div class="wrap" id="nubivio-hsh">
            <?php if ($saved): ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Settings saved.', 'nubivio-healthcare-security-hardening'); ?></p></div>
            <?php endif; ?>

            <div class="ns-header">
                <div class="ns-header-main">
                    <div class="ns-brand">
                        <?php echo $this->logo_svg(); // phpcs:ignore WordPress.Security.EscapeOutput ?>
                        <span class="ns-brand-suffix"><?php esc_html_e('Healthcare Security', 'nubivio-healthcare-security-hardening'); ?></span>
                    </div>
                    <p><?php esc_html_e('Security hardening for WordPress. Headers, security.txt and form protection, aligned with the internet.nl test.', 'nubivio-healthcare-security-hardening'); ?></p>
                </div>
                <div class="ns-head-meta">v<?php echo esc_html(self::VERSION); ?></div>
            </div>

            <h2 class="nav-tab-wrapper ns-tabs">
                <a href="<?php echo esc_url($hardening_url); ?>" class="nav-tab <?php echo $tab === 'hardening' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Hardening', 'nubivio-healthcare-security-hardening'); ?></a>
                <a href="<?php echo esc_url($compliance_url); ?>" class="nav-tab <?php echo $tab === 'compliance' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e('Compliance', 'nubivio-healthcare-security-hardening'); ?></a>
            </h2>

            <?php if ($tab === 'compliance'): ?>
                <?php
                // phpcs:ignore WordPress.Security.NonceVerification
                $scan_msg = isset($_GET['scan']) ? sanitize_key(wp_unslash($_GET['scan'])) : '';
                if ($scan_msg === 'done'): ?>
                    <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Compliance scan complete.', 'nubivio-healthcare-security-hardening'); ?></p></div>
                <?php elseif ($scan_msg === 'cooldown'): ?>
                    <div class="notice notice-warning is-dismissible"><p><?php esc_html_e('A scan ran recently. Please wait a few minutes before scanning again.', 'nubivio-healthcare-security-hardening'); ?></p></div>
                <?php elseif ($scan_msg === 'running'): ?>
                    <div class="notice notice-warning is-dismissible"><p><?php esc_html_e('A scan is already running. Please wait for it to finish.', 'nubivio-healthcare-security-hardening'); ?></p></div>
                <?php elseif ($scan_msg === 'unavailable'): ?>
                    <div class="notice notice-error is-dismissible"><p><?php esc_html_e('The scanner module is unavailable.', 'nubivio-healthcare-security-hardening'); ?></p></div>
                <?php endif; ?>
                <?php
                $dashboard = plugin_dir_path(__FILE__) . 'admin/dashboard.php';
                if (file_exists($dashboard)) {
                    $core = $this; // exposed to the view
                    require $dashboard;
                } else {
                    echo '<div class="ns-card"><p>' . esc_html__('The compliance dashboard is unavailable.', 'nubivio-healthcare-security-hardening') . '</p></div>';
                }
                ?>
            <?php else: ?>

            <div class="ns-card ns-status">
                <h2><?php esc_html_e('Status', 'nubivio-healthcare-security-hardening'); ?></h2>
                <div class="ns-status-grid">
                    <div>
                        <span class="ns-stat-label"><?php esc_html_e('security.txt', 'nubivio-healthcare-security-hardening'); ?></span>
                        <?php if ($status['days'] === null && $status['mode'] === 'dynamic'): ?>
                            <span class="ns-pill ns-pill-info"><?php esc_html_e('Served dynamically', 'nubivio-healthcare-security-hardening'); ?></span>
                        <?php elseif ($status['days'] !== null && $status['days'] > 30): ?>
                            <span class="ns-pill ns-pill-ok"><?php echo esc_html(sprintf(
                                /* translators: %d: number of days until expiry. */
                                _n('Valid - %d day left', 'Valid - %d days left', (int) $status['days'], 'nubivio-healthcare-security-hardening'),
                                (int) $status['days']
                            )); ?></span>
                        <?php elseif ($status['days'] !== null): ?>
                            <span class="ns-pill ns-pill-warn"><?php echo esc_html(sprintf(
                                /* translators: %d: number of days until expiry. */
                                __('Expiring (%dd) - auto refreshed', 'nubivio-healthcare-security-hardening'),
                                (int) $status['days']
                            )); ?></span>
                        <?php else: ?>
                            <span class="ns-pill ns-pill-warn"><?php esc_html_e('Not created', 'nubivio-healthcare-security-hardening'); ?></span>
                        <?php endif; ?>
                        <?php if ($status['expires']): ?>
                            <span class="ns-stat-sub"><?php echo esc_html(sprintf(
                                /* translators: %s: expiry timestamp. */
                                __('Expires: %s', 'nubivio-healthcare-security-hardening'),
                                $status['expires']
                            )); ?></span>
                        <?php endif; ?>
                    </div>
                    <div>
                        <span class="ns-stat-label"><?php esc_html_e('Canonical', 'nubivio-healthcare-security-hardening'); ?></span>
                        <a href="<?php echo esc_url($this->canonical_url()); ?>" target="_blank" rel="noopener"><?php echo esc_html($this->canonical_url()); ?></a>
                    </div>
                    <div>
                        <span class="ns-stat-label"><?php esc_html_e('Test your domain', 'nubivio-healthcare-security-hardening'); ?></span>
                        <a href="<?php echo esc_url($internetnl); ?>" target="_blank" rel="noopener">internet.nl/site/<?php echo esc_html($host); ?></a>
                    </div>
                    <?php if ($scan && isset($scan['score'], $scan['band'])): ?>
                    <div>
                        <span class="ns-stat-label"><?php esc_html_e('Compliance score', 'nubivio-healthcare-security-hardening'); ?></span>
                        <a class="ns-score-badge ns-band-<?php echo esc_attr($scan['band']); ?>" href="<?php echo esc_url($compliance_url); ?>">
                            <?php echo esc_html(sprintf(
                                /* translators: %d: compliance score out of 100. */
                                __('%d / 100', 'nubivio-healthcare-security-hardening'),
                                (int) $scan['score']
                            )); ?>
                        </a>
                    </div>
                    <?php endif; ?>
                </div>
                <details class="ns-preview">
                    <summary><?php esc_html_e('View active response headers', 'nubivio-healthcare-security-hardening'); ?></summary>
                    <pre><?php
                        foreach ($this->preview_headers() as $name => $val) {
                            echo esc_html($name . ': ' . $val) . "\n";
                        }
                    ?></pre>
                </details>
                <details class="ns-preview">
                    <summary><?php esc_html_e('security.txt preview', 'nubivio-healthcare-security-hardening'); ?></summary>
                    <pre><?php echo esc_html($this->build_security_txt()); ?></pre>
                </details>
            </div>

            <form method="post" action="">
                <?php wp_nonce_field('nubivio_hsh_save', 'nubivio_hsh_nonce'); ?>

                <div class="ns-card">
                    <h2><?php esc_html_e('Security headers', 'nubivio-healthcare-security-hardening'); ?></h2>

                    <div class="ns-field">
                        <?php $this->cb('hsts_enabled', __('HSTS (Strict-Transport-Security)', 'nubivio-healthcare-security-hardening'), $o, __('Enforces HTTPS. Sent on HTTPS connections only.', 'nubivio-healthcare-security-hardening')); ?>
                        <div class="ns-sub">
                            <label class="ns-inline-label"><?php esc_html_e('max-age (seconds)', 'nubivio-healthcare-security-hardening'); ?> <?php $this->txt('hsts_max_age', $o, '31536000', 'number'); ?></label>
                            <?php $this->cb('hsts_subdomains', __('includeSubDomains', 'nubivio-healthcare-security-hardening'), $o); ?>
                            <?php $this->cb('hsts_preload', __('preload', 'nubivio-healthcare-security-hardening'), $o, __('<strong>Caution:</strong> only enable if you submit the domain to hstspreload.org. Combines with includeSubDomains and is hard to reverse.', 'nubivio-healthcare-security-hardening')); ?>
                        </div>
                    </div>

                    <div class="ns-field">
                        <?php $this->cb('csp_enabled', __('Content-Security-Policy', 'nubivio-healthcare-security-hardening'), $o, __('Off by default because a strict policy can break inline scripts and third-party tags. The baseline below is internet.nl compliant. Test in Report-Only, add the domains your site needs, then enforce.', 'nubivio-healthcare-security-hardening')); ?>
                        <div class="ns-sub">
                            <?php $this->area('csp_policy', $o, 4); ?>
                            <?php $this->cb('csp_report_only', __('Report-Only mode (test without blocking anything)', 'nubivio-healthcare-security-hardening'), $o, __('internet.nl only credits an enforced policy. Turn this off once your site works under the policy.', 'nubivio-healthcare-security-hardening')); ?>
                        </div>
                    </div>

                    <div class="ns-field">
                        <?php $this->cb('referrer_enabled', __('Referrer-Policy', 'nubivio-healthcare-security-hardening'), $o); ?>
                        <div class="ns-sub">
                            <select name="referrer_value" class="ns-input">
                                <?php
                                $ref = array(
                                    'no-referrer'                     => __('no-referrer  (internet.nl: Good)', 'nubivio-healthcare-security-hardening'),
                                    'same-origin'                     => __('same-origin  (internet.nl: Good)', 'nubivio-healthcare-security-hardening'),
                                    'strict-origin'                   => __('strict-origin  (internet.nl: Warning)', 'nubivio-healthcare-security-hardening'),
                                    'strict-origin-when-cross-origin' => __('strict-origin-when-cross-origin  (internet.nl: Warning)', 'nubivio-healthcare-security-hardening'),
                                    'origin'                          => __('origin  (internet.nl: Bad)', 'nubivio-healthcare-security-hardening'),
                                    'origin-when-cross-origin'        => __('origin-when-cross-origin  (internet.nl: Bad)', 'nubivio-healthcare-security-hardening'),
                                    'no-referrer-when-downgrade'      => __('no-referrer-when-downgrade  (internet.nl: Bad)', 'nubivio-healthcare-security-hardening'),
                                    'unsafe-url'                      => __('unsafe-url  (internet.nl: Bad)', 'nubivio-healthcare-security-hardening'),
                                );
                                foreach ($ref as $val => $label) {
                                    echo '<option value="' . esc_attr($val) . '" ' . selected($o['referrer_value'], $val, false) . '>' . esc_html($label) . '</option>';
                                }
                                ?>
                            </select>
                            <p class="ns-desc"><?php echo wp_kses_post(__('For a fully green internet.nl result, pick <code>no-referrer</code> or <code>same-origin</code>.', 'nubivio-healthcare-security-hardening')); ?></p>
                        </div>
                    </div>

                    <div class="ns-field">
                        <?php $this->cb('nosniff_enabled', __('X-Content-Type-Options: nosniff', 'nubivio-healthcare-security-hardening'), $o); ?>
                    </div>

                    <div class="ns-field">
                        <?php $this->cb('xfo_enabled', __('X-Frame-Options', 'nubivio-healthcare-security-hardening'), $o, __('Clickjacking protection. CSP frame-ancestors is the modern equivalent, but internet.nl still checks this header.', 'nubivio-healthcare-security-hardening')); ?>
                        <div class="ns-sub">
                            <select name="xfo_value" class="ns-input">
                                <?php foreach (array('SAMEORIGIN','DENY') as $xv) {
                                    echo '<option value="' . esc_attr($xv) . '" ' . selected($o['xfo_value'], $xv, false) . '>' . esc_html($xv) . '</option>';
                                } ?>
                            </select>
                        </div>
                    </div>

                    <div class="ns-field">
                        <?php $this->cb('permissions_enabled', __('Permissions-Policy', 'nubivio-healthcare-security-hardening'), $o, __('Disables browser features the site does not use (camera, microphone, geolocation).', 'nubivio-healthcare-security-hardening')); ?>
                        <div class="ns-sub">
                            <?php $this->area('permissions_value', $o, 2); ?>
                        </div>
                    </div>

                    <div class="ns-field ns-field-flat">
                        <?php $this->cb('strip_legacy', __('Actively remove deprecated headers (X-XSS-Protection, Expect-CT)', 'nubivio-healthcare-security-hardening'), $o, __('Both are deprecated. X-XSS-Protection can open new holes in old browsers; Expect-CT no longer does anything.', 'nubivio-healthcare-security-hardening')); ?>
                    </div>
                </div>

                <div class="ns-card">
                    <h2><?php esc_html_e('security.txt', 'nubivio-healthcare-security-hardening'); ?> <span class="ns-tag">RFC 9116</span></h2>
                    <p class="ns-card-intro"><?php echo wp_kses_post(__('Written to <code>/.well-known/security.txt</code> and refreshed automatically so <code>Expires</code> never lapses. If the file cannot be written (read-only docroot), it is served dynamically instead.', 'nubivio-healthcare-security-hardening')); ?></p>

                    <div class="ns-field ns-field-flat">
                        <?php $this->cb('sectxt_enabled', __('Enable security.txt', 'nubivio-healthcare-security-hardening'), $o); ?>
                    </div>

                    <div class="ns-field">
                        <label class="ns-strong"><?php esc_html_e('Contact', 'nubivio-healthcare-security-hardening'); ?> <span class="ns-req"><?php esc_html_e('required', 'nubivio-healthcare-security-hardening'); ?></span></label>
                        <p class="ns-desc"><?php echo wp_kses_post(__('Email address or URL, one per line. An email gets a <code>mailto:</code> prefix automatically.', 'nubivio-healthcare-security-hardening')); ?></p>
                        <?php $this->area('sectxt_contacts', $o, 2); ?>
                    </div>

                    <div class="ns-field">
                        <label class="ns-strong"><?php esc_html_e('Message to researchers', 'nubivio-healthcare-security-hardening'); ?> <span class="ns-opt"><?php esc_html_e('optional', 'nubivio-healthcare-security-hardening'); ?></span></label>
                        <p class="ns-desc"><?php esc_html_e('Shown as comment lines at the top of the file. One per line.', 'nubivio-healthcare-security-hardening'); ?></p>
                        <?php $this->area('sectxt_note', $o, 2); ?>
                    </div>

                    <div class="ns-grid-2">
                        <div class="ns-field">
                            <label class="ns-strong"><?php esc_html_e('Refresh Expires after (days)', 'nubivio-healthcare-security-hardening'); ?></label>
                            <?php $this->txt('sectxt_expires_days', $o, '180', 'number'); ?>
                            <p class="ns-desc"><?php esc_html_e('Keep under 365. internet.nl wants an expiry under one year.', 'nubivio-healthcare-security-hardening'); ?></p>
                        </div>
                        <div class="ns-field">
                            <label class="ns-strong"><?php esc_html_e('Preferred-Languages', 'nubivio-healthcare-security-hardening'); ?></label>
                            <?php $this->txt('sectxt_languages', $o, 'nl, en'); ?>
                        </div>
                    </div>

                    <div class="ns-grid-2">
                        <div class="ns-field">
                            <label class="ns-strong"><?php esc_html_e('Policy URL', 'nubivio-healthcare-security-hardening'); ?> <span class="ns-opt"><?php esc_html_e('optional', 'nubivio-healthcare-security-hardening'); ?></span></label>
                            <?php $this->txt('sectxt_policy', $o, 'https://example.com/security-policy', 'url'); ?>
                            <p class="ns-desc"><?php esc_html_e('Your Coordinated Vulnerability Disclosure policy.', 'nubivio-healthcare-security-hardening'); ?></p>
                        </div>
                        <div class="ns-field">
                            <label class="ns-strong"><?php esc_html_e('Encryption URL', 'nubivio-healthcare-security-hardening'); ?> <span class="ns-opt"><?php esc_html_e('recommended', 'nubivio-healthcare-security-hardening'); ?></span></label>
                            <?php $this->txt('sectxt_encryption', $o, 'https://example.com/pgp-key.txt', 'url'); ?>
                            <p class="ns-desc"><?php esc_html_e('internet.nl recommends this when Contact is an email.', 'nubivio-healthcare-security-hardening'); ?></p>
                        </div>
                        <div class="ns-field">
                            <label class="ns-strong"><?php esc_html_e('Hiring URL', 'nubivio-healthcare-security-hardening'); ?> <span class="ns-opt"><?php esc_html_e('careers / vacatures', 'nubivio-healthcare-security-hardening'); ?></span></label>
                            <?php $this->txt('sectxt_hiring', $o, 'https://example.com/careers', 'url'); ?>
                            <p class="ns-desc"><?php esc_html_e('Point security people at your open roles.', 'nubivio-healthcare-security-hardening'); ?></p>
                        </div>
                        <div class="ns-field">
                            <label class="ns-strong"><?php esc_html_e('CSAF URL', 'nubivio-healthcare-security-hardening'); ?> <span class="ns-opt"><?php esc_html_e('advisories', 'nubivio-healthcare-security-hardening'); ?></span></label>
                            <?php $this->txt('sectxt_csaf', $o, 'https://example.com/.well-known/csaf/provider-metadata.json', 'url'); ?>
                            <p class="ns-desc"><?php esc_html_e('Link to your CSAF provider metadata, if you publish advisories.', 'nubivio-healthcare-security-hardening'); ?></p>
                        </div>
                        <div class="ns-field">
                            <label class="ns-strong"><?php esc_html_e('Acknowledgments URL', 'nubivio-healthcare-security-hardening'); ?> <span class="ns-opt"><?php esc_html_e('optional', 'nubivio-healthcare-security-hardening'); ?></span></label>
                            <?php $this->txt('sectxt_ack', $o, 'https://example.com/hall-of-fame', 'url'); ?>
                            <p class="ns-desc"><?php esc_html_e('Your hall of fame for reporters.', 'nubivio-healthcare-security-hardening'); ?></p>
                        </div>
                    </div>

                    <div class="ns-field">
                        <label class="ns-strong"><?php esc_html_e('PGP public key', 'nubivio-healthcare-security-hardening'); ?> <span class="ns-opt"><?php esc_html_e('optional', 'nubivio-healthcare-security-hardening'); ?></span></label>
                        <p class="ns-desc"><?php echo wp_kses_post(__('Paste your ASCII-armored public key. The plugin hosts it at <code>/.well-known/openpgp-key.txt</code> and links it from security.txt as <code>Encryption</code> automatically. A manual Encryption URL above takes precedence.', 'nubivio-healthcare-security-hardening')); ?></p>
                        <?php $this->area('sectxt_pgp', $o, 5); ?>
                    </div>

                    <div class="ns-field ns-field-flat">
                        <?php $this->cb('sectxt_love', __('Show Nubivio some love', 'nubivio-healthcare-security-hardening'), $o, __('Adds a small Nubivio signature comment to security.txt. Turn it off to keep the file plain.', 'nubivio-healthcare-security-hardening')); ?>
                        <p class="ns-love-msg" id="nhsh-love-msg" aria-live="polite"></p>
                    </div>
                </div>

                <?php if ($this->gravity_forms_active()): ?>
                <div class="ns-card">
                    <h2><?php esc_html_e('Gravity Forms', 'nubivio-healthcare-security-hardening'); ?></h2>
                    <div class="ns-field ns-field-flat">
                        <?php $this->cb('gf_block_enabled', __('Block email domains in forms', 'nubivio-healthcare-security-hardening'), $o, __('Rejects email fields ending in a blocked domain.', 'nubivio-healthcare-security-hardening')); ?>
                        <div class="ns-sub">
                            <label class="ns-strong"><?php esc_html_e('Blocked domains', 'nubivio-healthcare-security-hardening'); ?></label>
                            <p class="ns-desc"><?php echo wp_kses_post(__('One per line or comma separated, without @. For example <code>example.com</code>.', 'nubivio-healthcare-security-hardening')); ?></p>
                            <?php $this->area('gf_block_domains', $o, 2); ?>
                            <label class="ns-strong"><?php esc_html_e('Error message', 'nubivio-healthcare-security-hardening'); ?></label>
                            <?php $this->txt('gf_block_message', $o, ''); ?>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <div class="ns-actions">
                    <button type="submit" class="ns-btn"><?php esc_html_e('Save settings', 'nubivio-healthcare-security-hardening'); ?></button>
                    <span class="ns-by">nubivio.com</span>
                </div>
            </form>
            <?php endif; ?>
        </div>
        <?php
    }
}

register_activation_hook(__FILE__, array('Nubivio_HSH', 'activate'));
register_deactivation_hook(__FILE__, array('Nubivio_HSH', 'deactivate'));
register_uninstall_hook(__FILE__, array('Nubivio_HSH', 'uninstall'));

add_action('plugins_loaded', array('Nubivio_HSH', 'instance'));
