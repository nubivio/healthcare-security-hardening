<?php
/**
 * Additive optional security headers.
 *
 * @package Nubivio_HSH
 */
if (!defined('ABSPATH')) { exit; }

class Nubivio_HSH_Headers {
    private $core;
    public function __construct($core) { $this->core = $core; }

    public function run() {
        return array('findings' => array(), 'counts' => array('high' => 0, 'medium' => 0, 'low' => 0));
    }

    public function emit() {
        if (is_admin()) { return; }
        $o = $this->core->get_options();
        $headers = array(
            'coop' => 'Cross-Origin-Opener-Policy',
            'coep' => 'Cross-Origin-Embedder-Policy',
            'corp' => 'Cross-Origin-Resource-Policy',
            'permissions_policy' => 'Permissions-Policy',
        );
        foreach ($headers as $key => $name) {
            if (empty($o[$key . '_enabled']) || empty($o[$key . '_value'])) { continue; }
            // The baseline Permissions-Policy remains untouched unless the optional extended policy is enabled.
            header($name . ': ' . $this->clean($o[$key . '_value']), $key === 'permissions_policy');
        }
    }

    private function clean($value) {
        return trim(str_replace(array("\r", "\n"), ' ', (string) $value));
    }
}
