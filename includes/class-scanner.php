<?php
/**
 * Scanner orchestrator: registers the passive front-end script snapshot,
 * runs the requested framework modules plus health, and aggregates the score.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Scanner {

    /** @var Nubivio_HSH */
    private $core;

    /** @var Nubivio_HSH_Health|null */
    private $health = null;

    public function __construct($core) {
        $this->core = $core;
        // Passive snapshot of enqueued script hosts, front end only, non-admin.
        if (!is_admin()) {
            add_action('wp_footer', array($this, 'snapshot_frontend_scripts'), 999);
        }
    }

    /**
     * Once per 12h, record the external hosts of enqueued front-end scripts.
     * Passive: it only reads the already-registered script list.
     */
    public function snapshot_frontend_scripts() {
        if (is_admin() || get_transient('nubivio_hsh_frontend_scripts') !== false) {
            return;
        }
        global $wp_scripts;
        $hosts = array();
        $site_host = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        if ($wp_scripts instanceof WP_Scripts && !empty($wp_scripts->done)) {
            foreach ($wp_scripts->done as $handle) {
                if (empty($wp_scripts->registered[$handle])) {
                    continue;
                }
                $src = $wp_scripts->registered[$handle]->src;
                if (!$src || strpos($src, '//') === false) {
                    continue;
                }
                $host = strtolower((string) wp_parse_url($src, PHP_URL_HOST));
                if ($host !== '' && $host !== $site_host && !in_array($host, $hosts, true)) {
                    $hosts[] = $host;
                }
            }
        }
        set_transient('nubivio_hsh_frontend_scripts', $hosts, 12 * HOUR_IN_SECONDS);
    }

    /**
     * Run the compliance scan.
     *
     * @return array
     */
    public function run() {
        $o          = $this->core->get_options();
        $frameworks = isset($o['scan_frameworks']) && is_array($o['scan_frameworks'])
            ? $o['scan_frameworks']
            : array('cra', 'gdpr', 'nis2', 'health');

        $results = array();

        $cra  = array('findings' => array(), 'counts' => array('high' => 0, 'medium' => 0, 'low' => 0));
        $gdpr = array('findings' => array(), 'counts' => array('high' => 0, 'medium' => 0, 'low' => 0));
        $nis2 = array('findings' => array(), 'counts' => array('high' => 0, 'medium' => 0, 'low' => 0), 'score_points' => 0);

        if (in_array('cra', $frameworks, true) && class_exists('Nubivio_HSH_Cra')) {
            $cra = (new Nubivio_HSH_Cra($this->core))->run();
            $results['cra'] = $cra;
        }
        if (in_array('gdpr', $frameworks, true) && class_exists('Nubivio_HSH_Gdpr')) {
            $gdpr = (new Nubivio_HSH_Gdpr($this->core))->run();
            $results['gdpr'] = $gdpr;
        }
        if (in_array('nis2', $frameworks, true) && class_exists('Nubivio_HSH_Nis2')) {
            $nis2 = (new Nubivio_HSH_Nis2($this->core))->run();
            $results['nis2'] = $nis2;
        }

        // Health always runs.
        $health = $this->health()->run();
        $results['health'] = $health;

        $counts = array('high' => 0, 'medium' => 0, 'low' => 0);
        foreach (array($cra, $gdpr, $nis2) as $set) {
            foreach (array('high', 'medium', 'low') as $sev) {
                if (isset($set['counts'][$sev])) {
                    $counts[$sev] += (int) $set['counts'][$sev];
                }
            }
        }

        $score = class_exists('Nubivio_HSH_Score')
            ? Nubivio_HSH_Score::compute($this->core, $cra, $gdpr, $nis2, $health)
            : array('score' => 0, 'band' => 'red', 'header_bonus' => 0, 'sectxt_bonus' => 0, 'breakdown' => array());

        return array(
            'time'         => time(),
            'score'        => $score['score'],
            'band'         => $score['band'],
            'frameworks'   => $results,
            'counts'       => $counts,
            'header_bonus' => $score['header_bonus'],
            'sectxt_bonus' => $score['sectxt_bonus'],
        );
    }

    /**
     * Passthrough to the health probe, used by the Phase 3 evidence panel.
     *
     * @return array
     */
    public function probe_headers() {
        return $this->health()->probe_headers();
    }

    private function health() {
        if ($this->health === null && class_exists('Nubivio_HSH_Health')) {
            $this->health = new Nubivio_HSH_Health($this->core);
        }
        return $this->health;
    }
}
