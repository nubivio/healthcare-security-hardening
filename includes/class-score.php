<?php
/**
 * Aggregate compliance score. Subtractive for findings, additive credit for the
 * plugin's own enforced headers and a valid security.txt.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Score {

    /**
     * Compute the aggregate score.
     *
     * @param Nubivio_HSH $core
     * @param array $cra    CRA run result.
     * @param array $gdpr   GDPR run result.
     * @param array $nis2   NIS2 run result.
     * @param array $health Health run result.
     * @return array{score:int,band:string,header_bonus:int,sectxt_bonus:int,breakdown:array}
     */
    public static function compute($core, $cra, $gdpr, $nis2, $health) {
        $high = 0;
        $medium = 0;
        foreach (array($cra, $gdpr, $nis2) as $set) {
            if (isset($set['counts']['high'])) {
                $high += (int) $set['counts']['high'];
            }
            if (isset($set['counts']['medium'])) {
                $medium += (int) $set['counts']['medium'];
            }
        }
        $health_fails = isset($health['fails']) ? (int) $health['fails'] : 0;

        $o = $core->get_options();

        // Header bonus (up to +8).
        $header_bonus = 0;
        if (!empty($o['csp_enabled']) && empty($o['csp_report_only'])) {
            $header_bonus += 3;
        }
        $probe = method_exists($core, 'scanner') && $core->scanner() ? $core->scanner()->probe_headers() : array('ok' => false, 'present' => array());
        if (!empty($o['hsts_enabled'])) {
            $hsts_live = !empty($probe['ok']) && isset($probe['present']['strict-transport-security']);
            if ($hsts_live) {
                $header_bonus += 3;
            } elseif (empty($probe['ok'])) {
                $header_bonus += 2;
            }
        }
        if (!empty($o['referrer_enabled']) && !empty($o['nosniff_enabled']) && !empty($o['xfo_enabled']) && !empty($o['permissions_enabled'])) {
            $header_bonus += 2;
        }
        $header_bonus = min(8, $header_bonus);

        // security.txt bonus (up to +4).
        $sectxt_bonus = 0;
        $status = $core->security_txt_status();
        if ($status['mode'] === 'dynamic' || ($status['days'] !== null && $status['days'] > 30)) {
            $sectxt_bonus += 2;
        }
        $canonical = $core->canonical_url();
        $home_host = wp_parse_url(home_url(), PHP_URL_HOST);
        $can_host  = wp_parse_url($canonical, PHP_URL_HOST);
        if ($can_host && $home_host && strtolower($can_host) === strtolower($home_host)) {
            $sectxt_bonus += 1;
        }
        if (trim((string) $o['sectxt_contacts']) !== '') {
            $sectxt_bonus += 1;
        }
        $sectxt_bonus = min(4, $sectxt_bonus);

        $raw = 100 - ($high * 10) - ($medium * 5) - ($health_fails * 4) + $header_bonus + $sectxt_bonus;
        $score = max(0, min(100, $raw));

        if ($score >= 80) {
            $band = 'green';
        } elseif ($score >= 60) {
            $band = 'amber';
        } else {
            $band = 'red';
        }

        return array(
            'score'        => (int) $score,
            'band'         => $band,
            'header_bonus' => (int) $header_bonus,
            'sectxt_bonus' => (int) $sectxt_bonus,
            'breakdown'    => array(
                'high'         => $high,
                'medium'       => $medium,
                'health_fails' => $health_fails,
                'header_bonus' => (int) $header_bonus,
                'sectxt_bonus' => (int) $sectxt_bonus,
            ),
        );
    }
}
