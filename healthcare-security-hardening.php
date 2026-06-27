<?php
/**
 * Plugin Name:       Nubivio Salus - Security Hardening for Healthcare
 * Plugin URI:        https://github.com/nubivio/healthcare-security-hardening
 * Description:       Security headers, a self-renewing security.txt (RFC 9116) and advanced form protection for healthcare related WordPress sites. Built for general practitioners, psychologists and other healthcare professionals. Recommended for NIS2, GDPR & NEN7510 compliance.
 * Version:           2.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Nubivio
 * Author URI:        https://nubivio.com/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       healthcare-security-hardening
 */

if (!defined('ABSPATH')) {
    exit;
}

final class Nubivio_Salus {

    const VERSION   = '2.0.0';
    const OPTION    = 'nubivio_salus_options';
    const CRON_HOOK = 'nubivio_salus_daily';
    const SLUG      = 'nubivio-salus';

    /** @var Nubivio_Salus|null */
    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_action('send_headers', array($this, 'send_security_headers'));
        add_action('init', array($this, 'maybe_serve_well_known'), 1);

        add_filter('gform_field_validation', array($this, 'validate_blocked_domains'), 10, 4);

        add_action('admin_menu', array($this, 'register_settings_page'));
        add_action('admin_init', array($this, 'handle_form_submit'));
        add_action('admin_init', array($this, 'maybe_refresh_security_txt_file'));
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'settings_link'));

        add_action(self::CRON_HOOK, array($this, 'write_security_txt_file'));
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

    private function security_txt_path() {
        return rtrim(ABSPATH, '/\\') . '/.well-known/security.txt';
    }

    private function security_txt_dir() {
        return rtrim(ABSPATH, '/\\') . '/.well-known';
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
            $lines[] = '# Hardened by Nubivio Salus · boring, predictable security · https://nubivio.com';
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
        $dir = $this->security_txt_dir();
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        if (!is_dir($dir) || !is_writable($dir)) {
            return false;
        }
        $this->write_pgp_key_file();
        return @file_put_contents($this->security_txt_path(), $this->build_security_txt(), LOCK_EX) !== false;
    }

    /* PGP public key (hosted, linked from security.txt as Encryption) */

    private function pgp_key_path() {
        return rtrim(ABSPATH, '/\\') . '/.well-known/openpgp-key.txt';
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
        $dir = $this->security_txt_dir();
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        if (!is_dir($dir) || !is_writable($dir)) {
            return false;
        }
        return @file_put_contents($this->pgp_key_path(), $key, LOCK_EX) !== false;
    }

    public function delete_pgp_key_file() {
        if (file_exists($this->pgp_key_path())) {
            @unlink($this->pgp_key_path());
        }
    }

    public function delete_security_txt_file() {
        $path = $this->security_txt_path();
        if (file_exists($path)) {
            @unlink($path);
        }
    }

    public function maybe_refresh_security_txt_file() {
        $o = $this->get_options();
        if (empty($o['sectxt_enabled']) || get_transient('nubivio_salus_sectxt_checked')) {
            return;
        }
        set_transient('nubivio_salus_sectxt_checked', 1, 12 * HOUR_IN_SECONDS);

        $path = $this->security_txt_path();
        $refresh = true;
        if (file_exists($path)) {
            $content = (string) @file_get_contents($path);
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
        $path = wp_parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
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
        if (!file_exists($path)) {
            return array('mode' => 'dynamic', 'expires' => null, 'days' => null);
        }
        $content = (string) @file_get_contents($path);
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
                $result['message']  = $o['gf_block_message'] !== '' ? $o['gf_block_message'] : 'This email domain is not allowed.';
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
        array_unshift($links, '<a href="' . esc_url($url) . '">Settings</a>');
        return $links;
    }

    public function register_settings_page() {
        add_options_page('Nubivio Salus', 'Nubivio Salus', 'manage_options', self::SLUG, array($this, 'render_settings_page'));
    }

    public function handle_form_submit() {
        if (!isset($_POST['nubivio_salus_nonce']) || !current_user_can('manage_options')) {
            return;
        }
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nubivio_salus_nonce'])), 'nubivio_salus_save')) {
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

        delete_transient('nubivio_salus_sectxt_checked');
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
        ?>
        <div class="wrap" id="nubivio-salus">
            <?php if ($saved): ?>
                <div class="notice notice-success is-dismissible"><p>Settings saved.</p></div>
            <?php endif; ?>

            <div class="ns-header">
                <div class="ns-header-main">
                    <div class="ns-brand">
                        <?php echo $this->logo_svg(); // phpcs:ignore WordPress.Security.EscapeOutput ?>
                        <span class="ns-brand-suffix">Salus</span>
                    </div>
                    <p>Security hardening for WordPress. Headers, security.txt and form protection, aligned with the internet.nl test.</p>
                </div>
                <div class="ns-head-meta">v<?php echo esc_html(self::VERSION); ?></div>
            </div>

            <div class="ns-card ns-status">
                <h2>Status</h2>
                <div class="ns-status-grid">
                    <div>
                        <span class="ns-stat-label">security.txt</span>
                        <?php if ($status['days'] === null && $status['mode'] === 'dynamic'): ?>
                            <span class="ns-pill ns-pill-info">Served dynamically</span>
                        <?php elseif ($status['days'] !== null && $status['days'] > 30): ?>
                            <span class="ns-pill ns-pill-ok">Valid - <?php echo (int) $status['days']; ?> days left</span>
                        <?php elseif ($status['days'] !== null): ?>
                            <span class="ns-pill ns-pill-warn">Expiring (<?php echo (int) $status['days']; ?>d) - auto refreshed</span>
                        <?php else: ?>
                            <span class="ns-pill ns-pill-warn">Not created</span>
                        <?php endif; ?>
                        <?php if ($status['expires']): ?>
                            <span class="ns-stat-sub">Expires: <?php echo esc_html($status['expires']); ?></span>
                        <?php endif; ?>
                    </div>
                    <div>
                        <span class="ns-stat-label">Canonical</span>
                        <a href="<?php echo esc_url($this->canonical_url()); ?>" target="_blank" rel="noopener"><?php echo esc_html($this->canonical_url()); ?></a>
                    </div>
                    <div>
                        <span class="ns-stat-label">Test your domain</span>
                        <a href="<?php echo esc_url($internetnl); ?>" target="_blank" rel="noopener">internet.nl/site/<?php echo esc_html($host); ?></a>
                    </div>
                </div>
                <details class="ns-preview">
                    <summary>View active response headers</summary>
                    <pre><?php
                        foreach ($this->preview_headers() as $name => $val) {
                            echo esc_html($name . ': ' . $val) . "\n";
                        }
                    ?></pre>
                </details>
                <details class="ns-preview">
                    <summary>security.txt preview</summary>
                    <pre><?php echo esc_html($this->build_security_txt()); ?></pre>
                </details>
            </div>

            <form method="post" action="">
                <?php wp_nonce_field('nubivio_salus_save', 'nubivio_salus_nonce'); ?>

                <div class="ns-card">
                    <h2>Security headers</h2>

                    <div class="ns-field">
                        <?php $this->cb('hsts_enabled', 'HSTS (Strict-Transport-Security)', $o, 'Enforces HTTPS. Sent on HTTPS connections only.'); ?>
                        <div class="ns-sub">
                            <label class="ns-inline-label">max-age (seconds) <?php $this->txt('hsts_max_age', $o, '31536000', 'number'); ?></label>
                            <?php $this->cb('hsts_subdomains', 'includeSubDomains', $o); ?>
                            <?php $this->cb('hsts_preload', 'preload', $o, '<strong>Caution:</strong> only enable if you submit the domain to hstspreload.org. Combines with includeSubDomains and is hard to reverse.'); ?>
                        </div>
                    </div>

                    <div class="ns-field">
                        <?php $this->cb('csp_enabled', 'Content-Security-Policy', $o, 'Off by default because a strict policy can break inline scripts and third-party tags. The baseline below is internet.nl compliant. Test in Report-Only, add the domains your site needs, then enforce.'); ?>
                        <div class="ns-sub">
                            <?php $this->area('csp_policy', $o, 4); ?>
                            <?php $this->cb('csp_report_only', 'Report-Only mode (test without blocking anything)', $o, 'internet.nl only credits an enforced policy. Turn this off once your site works under the policy.'); ?>
                        </div>
                    </div>

                    <div class="ns-field">
                        <?php $this->cb('referrer_enabled', 'Referrer-Policy', $o); ?>
                        <div class="ns-sub">
                            <select name="referrer_value" class="ns-input">
                                <?php
                                $ref = array(
                                    'no-referrer'                     => 'no-referrer  (internet.nl: Good)',
                                    'same-origin'                     => 'same-origin  (internet.nl: Good)',
                                    'strict-origin'                   => 'strict-origin  (internet.nl: Warning)',
                                    'strict-origin-when-cross-origin' => 'strict-origin-when-cross-origin  (internet.nl: Warning)',
                                    'origin'                          => 'origin  (internet.nl: Bad)',
                                    'origin-when-cross-origin'        => 'origin-when-cross-origin  (internet.nl: Bad)',
                                    'no-referrer-when-downgrade'      => 'no-referrer-when-downgrade  (internet.nl: Bad)',
                                    'unsafe-url'                      => 'unsafe-url  (internet.nl: Bad)',
                                );
                                foreach ($ref as $val => $label) {
                                    echo '<option value="' . esc_attr($val) . '" ' . selected($o['referrer_value'], $val, false) . '>' . esc_html($label) . '</option>';
                                }
                                ?>
                            </select>
                            <p class="ns-desc">For a fully green internet.nl result, pick <code>no-referrer</code> or <code>same-origin</code>.</p>
                        </div>
                    </div>

                    <div class="ns-field">
                        <?php $this->cb('nosniff_enabled', 'X-Content-Type-Options: nosniff', $o); ?>
                    </div>

                    <div class="ns-field">
                        <?php $this->cb('xfo_enabled', 'X-Frame-Options', $o, 'Clickjacking protection. CSP frame-ancestors is the modern equivalent, but internet.nl still checks this header.'); ?>
                        <div class="ns-sub">
                            <select name="xfo_value" class="ns-input">
                                <?php foreach (array('SAMEORIGIN','DENY') as $xv) {
                                    echo '<option value="' . esc_attr($xv) . '" ' . selected($o['xfo_value'], $xv, false) . '>' . esc_html($xv) . '</option>';
                                } ?>
                            </select>
                        </div>
                    </div>

                    <div class="ns-field">
                        <?php $this->cb('permissions_enabled', 'Permissions-Policy', $o, 'Disables browser features the site does not use (camera, microphone, geolocation).'); ?>
                        <div class="ns-sub">
                            <?php $this->area('permissions_value', $o, 2); ?>
                        </div>
                    </div>

                    <div class="ns-field ns-field-flat">
                        <?php $this->cb('strip_legacy', 'Actively remove deprecated headers (X-XSS-Protection, Expect-CT)', $o, 'Both are deprecated. X-XSS-Protection can open new holes in old browsers; Expect-CT no longer does anything.'); ?>
                    </div>
                </div>

                <div class="ns-card">
                    <h2>security.txt <span class="ns-tag">RFC 9116</span></h2>
                    <p class="ns-card-intro">Written to <code>/.well-known/security.txt</code> and refreshed automatically so <code>Expires</code> never lapses. If the file cannot be written (read-only docroot), it is served dynamically instead.</p>

                    <div class="ns-field ns-field-flat">
                        <?php $this->cb('sectxt_enabled', 'Enable security.txt', $o); ?>
                    </div>

                    <div class="ns-field">
                        <label class="ns-strong">Contact <span class="ns-req">required</span></label>
                        <p class="ns-desc">Email address or URL, one per line. An email gets a <code>mailto:</code> prefix automatically.</p>
                        <?php $this->area('sectxt_contacts', $o, 2); ?>
                    </div>

                    <div class="ns-field">
                        <label class="ns-strong">Message to researchers <span class="ns-opt">optional</span></label>
                        <p class="ns-desc">Shown as comment lines at the top of the file. One per line.</p>
                        <?php $this->area('sectxt_note', $o, 2); ?>
                    </div>

                    <div class="ns-grid-2">
                        <div class="ns-field">
                            <label class="ns-strong">Refresh Expires after (days)</label>
                            <?php $this->txt('sectxt_expires_days', $o, '180', 'number'); ?>
                            <p class="ns-desc">Keep under 365. internet.nl wants an expiry under one year.</p>
                        </div>
                        <div class="ns-field">
                            <label class="ns-strong">Preferred-Languages</label>
                            <?php $this->txt('sectxt_languages', $o, 'nl, en'); ?>
                        </div>
                    </div>

                    <div class="ns-grid-2">
                        <div class="ns-field">
                            <label class="ns-strong">Policy URL <span class="ns-opt">optional</span></label>
                            <?php $this->txt('sectxt_policy', $o, 'https://example.com/security-policy', 'url'); ?>
                            <p class="ns-desc">Your Coordinated Vulnerability Disclosure policy.</p>
                        </div>
                        <div class="ns-field">
                            <label class="ns-strong">Encryption URL <span class="ns-opt">recommended</span></label>
                            <?php $this->txt('sectxt_encryption', $o, 'https://example.com/pgp-key.txt', 'url'); ?>
                            <p class="ns-desc">internet.nl recommends this when Contact is an email.</p>
                        </div>
                        <div class="ns-field">
                            <label class="ns-strong">Hiring URL <span class="ns-opt">careers / vacatures</span></label>
                            <?php $this->txt('sectxt_hiring', $o, 'https://example.com/careers', 'url'); ?>
                            <p class="ns-desc">Point security people at your open roles.</p>
                        </div>
                        <div class="ns-field">
                            <label class="ns-strong">CSAF URL <span class="ns-opt">advisories</span></label>
                            <?php $this->txt('sectxt_csaf', $o, 'https://example.com/.well-known/csaf/provider-metadata.json', 'url'); ?>
                            <p class="ns-desc">Link to your CSAF provider metadata, if you publish advisories.</p>
                        </div>
                        <div class="ns-field">
                            <label class="ns-strong">Acknowledgments URL <span class="ns-opt">optional</span></label>
                            <?php $this->txt('sectxt_ack', $o, 'https://example.com/hall-of-fame', 'url'); ?>
                            <p class="ns-desc">Your hall of fame for reporters.</p>
                        </div>
                    </div>

                    <div class="ns-field">
                        <label class="ns-strong">PGP public key <span class="ns-opt">optional</span></label>
                        <p class="ns-desc">Paste your ASCII-armored public key. The plugin hosts it at <code>/.well-known/openpgp-key.txt</code> and links it from security.txt as <code>Encryption</code> automatically. A manual Encryption URL above takes precedence.</p>
                        <?php $this->area('sectxt_pgp', $o, 5); ?>
                    </div>

                    <div class="ns-field ns-field-flat">
                        <?php $this->cb('sectxt_love', 'Show Nubivio some love', $o, 'Adds a small Nubivio signature comment to security.txt. Turn it off to keep the file plain.'); ?>
                        <p class="ns-love-msg" id="ns-love-msg" aria-live="polite"></p>
                    </div>
                </div>

                <?php if ($this->gravity_forms_active()): ?>
                <div class="ns-card">
                    <h2>Gravity Forms</h2>
                    <div class="ns-field ns-field-flat">
                        <?php $this->cb('gf_block_enabled', 'Block email domains in forms', $o, 'Rejects email fields ending in a blocked domain.'); ?>
                        <div class="ns-sub">
                            <label class="ns-strong">Blocked domains</label>
                            <p class="ns-desc">One per line or comma separated, without @. For example <code>example.com</code>.</p>
                            <?php $this->area('gf_block_domains', $o, 2); ?>
                            <label class="ns-strong">Error message</label>
                            <?php $this->txt('gf_block_message', $o, ''); ?>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <div class="ns-actions">
                    <button type="submit" class="ns-btn">Save settings</button>
                    <span class="ns-by">nubivio.com</span>
                </div>
            </form>
        </div>

        <script>
        (function(){
            var root = document.getElementById('nubivio-salus');
            if (!root) { return; }
            var cb = root.querySelector('input[name="sectxt_love"]');
            var msg = document.getElementById('ns-love-msg');
            if (!cb || !msg) { return; }
            function update(){
                if (cb.checked) {
                    msg.style.display = 'none';
                    msg.textContent = '';
                } else {
                    msg.style.display = 'block';
                    msg.textContent = '\uD83D\uDC94 Ouch. Fine, we will keep hardening your headers in total silence. \uD83D\uDE22';
                }
            }
            cb.addEventListener('change', update);
            update();
        })();
        </script>

        <style>
        #nubivio-salus{--p:#044172;--p2:#13274C;--p-deep:#01233F;--mist:#E6E7E8;--ink:#231F20;--ok:#1FB57A;--ok-bg:#E5F7EE;--warn:#E8A33A;--warn-bg:#FCF1DD;--danger:#E04A4A;--info-bg:#D9E2EB;max-width:920px;}
        #nubivio-salus *{box-sizing:border-box;}
        #nubivio-salus .ns-header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;background:linear-gradient(135deg,#13274C 0%,#044172 60%,#01233F 100%);color:#fff;padding:24px 26px;border-radius:14px;margin:16px 0 18px;box-shadow:0 6px 22px rgba(4,65,114,.18);}
        #nubivio-salus .ns-header-main{flex:1;}
        #nubivio-salus .ns-brand{display:flex;align-items:center;gap:12px;}
        #nubivio-salus .ns-logo-svg{height:30px;width:auto;display:block;}
        #nubivio-salus .ns-logo-svg path{fill:#fff;}
        #nubivio-salus .ns-brand-suffix{font-size:22px;font-weight:300;color:#B4C6D6;letter-spacing:.01em;border-left:1px solid rgba(255,255,255,.25);padding-left:12px;line-height:1;}
        #nubivio-salus .ns-header p{margin:12px 0 0;color:#B4C6D6;font-size:13px;max-width:560px;line-height:1.45;}
        #nubivio-salus .ns-head-meta{flex:0 0 auto;font-size:11px;color:#82A0B9;border:1px solid rgba(255,255,255,.18);padding:3px 9px;border-radius:999px;}
        #nubivio-salus .ns-card{background:#fff;border:1px solid var(--mist);border-radius:14px;padding:20px 24px;margin:0 0 16px;box-shadow:0 1px 2px rgba(19,39,76,.04);}
        #nubivio-salus .ns-card h2{font-size:16px;font-weight:700;color:var(--p2);margin:0 0 14px;padding-bottom:12px;border-bottom:1px solid var(--mist);display:flex;align-items:center;gap:10px;}
        #nubivio-salus .ns-tag,#nubivio-salus .ns-req,#nubivio-salus .ns-opt{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:2px 8px;border-radius:999px;}
        #nubivio-salus .ns-tag{background:var(--info-bg);color:var(--p);}
        #nubivio-salus .ns-req{background:var(--warn-bg);color:#9a6a16;}
        #nubivio-salus .ns-opt{background:var(--mist);color:#6F727A;}
        #nubivio-salus .ns-card-intro{margin:-4px 0 16px;color:#4A4D55;font-size:13px;line-height:1.5;}
        #nubivio-salus .ns-field{padding:14px 0;border-bottom:1px solid #f0f1f3;}
        #nubivio-salus .ns-field:last-child{border-bottom:none;}
        #nubivio-salus .ns-field-flat{padding:14px 0 4px;}
        #nubivio-salus .ns-sub{margin:12px 0 2px 52px;display:flex;flex-direction:column;gap:12px;align-items:flex-start;}
        #nubivio-salus .ns-inline-label{font-size:13px;color:#4A4D55;display:flex;align-items:center;gap:10px;}
        #nubivio-salus .ns-toggle{display:flex;align-items:center;gap:12px;cursor:pointer;font-weight:600;color:var(--ink);font-size:14px;}
        #nubivio-salus .ns-sub label.ns-toggle{display:flex;align-items:center;gap:12px;font-weight:600;}
        #nubivio-salus .ns-toggle input{position:absolute;opacity:0;width:0;height:0;}
        #nubivio-salus .ns-track{position:relative;flex:0 0 auto;width:40px;height:22px;background:#C9CBCF;border-radius:999px;transition:background .15s;}
        #nubivio-salus .ns-track:after{content:"";position:absolute;top:2px;left:2px;width:18px;height:18px;background:#fff;border-radius:50%;transition:transform .15s;box-shadow:0 1px 2px rgba(0,0,0,.25);}
        #nubivio-salus .ns-toggle input:checked + .ns-track{background:var(--p);}
        #nubivio-salus .ns-toggle input:checked + .ns-track:after{transform:translateX(18px);}
        #nubivio-salus .ns-toggle input:focus-visible + .ns-track{box-shadow:0 0 0 4px rgba(4,65,114,.20);}
        #nubivio-salus .ns-desc{margin:6px 0 0 52px;color:#6F727A;font-size:12.5px;line-height:1.5;}
        #nubivio-salus .ns-sub .ns-desc{margin-left:0;}
        #nubivio-salus .ns-strong{font-weight:700;color:var(--p2);font-size:13px;display:block;margin-bottom:4px;}
        #nubivio-salus .ns-input{width:100%;max-width:560px;border:1px solid #C9CBCF;border-radius:8px;padding:8px 11px;font-size:13px;color:var(--ink);background:#fff;}
        #nubivio-salus input[type=number].ns-input{max-width:180px;}
        #nubivio-salus .ns-input:focus{border-color:var(--p);outline:none;box-shadow:0 0 0 3px rgba(4,65,114,.15);}
        #nubivio-salus .ns-area{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:1.5;}
        #nubivio-salus .ns-grid-2{display:grid;grid-template-columns:1fr 1fr;gap:6px 28px;}
        #nubivio-salus .ns-status{border-left:4px solid var(--p);}
        #nubivio-salus .ns-status-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:6px;}
        #nubivio-salus .ns-stat-label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#6F727A;font-weight:700;margin-bottom:5px;}
        #nubivio-salus .ns-stat-sub{display:block;font-size:11.5px;color:#6F727A;margin-top:5px;}
        #nubivio-salus .ns-pill{display:inline-block;font-size:12px;font-weight:700;padding:4px 11px;border-radius:999px;}
        #nubivio-salus .ns-pill-ok{background:var(--ok-bg);color:#0c7a4f;}
        #nubivio-salus .ns-pill-warn{background:var(--warn-bg);color:#9a6a16;}
        #nubivio-salus .ns-pill-info{background:var(--info-bg);color:var(--p);}
        #nubivio-salus .ns-preview{margin-top:14px;border-top:1px solid var(--mist);padding-top:10px;}
        #nubivio-salus .ns-preview summary{cursor:pointer;font-size:12.5px;font-weight:600;color:var(--p);}
        #nubivio-salus .ns-preview pre{background:var(--p-deep);color:#cfe1f0;padding:14px 16px;border-radius:10px;font-size:11.5px;line-height:1.55;overflow:auto;margin-top:10px;white-space:pre-wrap;word-break:break-word;}
        #nubivio-salus .ns-actions{display:flex;align-items:center;gap:18px;margin:4px 0 8px;}
        #nubivio-salus .ns-btn{background:var(--p);color:#fff;border:none;border-radius:10px;padding:11px 26px;font-size:14px;font-weight:700;cursor:pointer;transition:background .15s,transform .05s;}
        #nubivio-salus .ns-btn:hover{background:#033054;}
        #nubivio-salus .ns-btn:active{transform:translateY(1px);background:#01233F;}
        #nubivio-salus .ns-by{font-size:12px;color:#A1A4AB;}
        #nubivio-salus .ns-love-msg{display:none;margin:8px 0 0 52px;font-size:13px;font-weight:600;color:var(--danger);}
        @media(max-width:782px){#nubivio-salus .ns-grid-2{grid-template-columns:1fr;}#nubivio-salus .ns-sub,#nubivio-salus .ns-desc{margin-left:0;}}
        </style>
        <?php
    }
}

register_activation_hook(__FILE__, array('Nubivio_Salus', 'activate'));
register_deactivation_hook(__FILE__, array('Nubivio_Salus', 'deactivate'));
register_uninstall_hook(__FILE__, array('Nubivio_Salus', 'uninstall'));

add_action('plugins_loaded', array('Nubivio_Salus', 'instance'));
