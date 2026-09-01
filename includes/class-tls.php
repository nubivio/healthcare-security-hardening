<?php
/**
 * TLS certificate overview.
 *
 * @package Nubivio_HSH
 */
if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Tls {

    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    public function run() {
        $host   = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
        $key    = 'nubivio_hsh_tls_' . md5($host);
        $cached = get_transient($key);
        if (is_array($cached)) {
            return $cached;
        }

        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);
        $summary  = array(
            'host'           => $host,
            'available'      => false,
            'subject_cn'     => '',
            'sans'           => array(),
            'issuer_cn'      => '',
            'issuer_o'       => '',
            'valid_from'     => 0,
            'valid_to'       => 0,
            'days_remaining' => null,
            'signature'      => '',
            'dane'           => false,
        );

        if (!function_exists('stream_socket_client') || !function_exists('openssl_x509_parse')) {
            $findings[] = array(
                'severity' => 'warn',
                'message'  => __('TLS inspection not available on this server.', 'nubivio-healthcare-security-hardening'),
            );
            $result = array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
            set_transient($key, $result, 6 * HOUR_IN_SECONDS);
            return $result;
        }

        if (wp_parse_url(home_url(), PHP_URL_SCHEME) !== 'https') {
            $this->add($findings, $counts, 'medium', __('Site is not served over HTTPS.', 'nubivio-healthcare-security-hardening'));
            $result = array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
            set_transient($key, $result, 6 * HOUR_IN_SECONDS);
            return $result;
        }

        $context = stream_context_create(array(
            'ssl' => array(
                'capture_peer_cert'       => true,
                'capture_peer_cert_chain' => true,
                'verify_peer'             => true,
                'verify_peer_name'        => true,
                'SNI_enabled'             => true,
            ),
        ));
        $errno  = 0;
        $errstr = '';
        $client = @stream_socket_client(
            'ssl://' . $host . ':443',
            $errno,
            $errstr,
            5,
            STREAM_CLIENT_CONNECT,
            $context
        );
        if (!$client) {
            $this->add(
                $findings,
                $counts,
                'high',
                sprintf(__('Could not establish TLS connection: %s.', 'nubivio-healthcare-security-hardening'), $errstr)
            );
            $result = array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
            set_transient($key, $result, 6 * HOUR_IN_SECONDS);
            return $result;
        }

        $params = stream_context_get_params($client);
        fclose($client);
        $cert   = isset($params['options']['ssl']['peer_certificate'])
            ? $params['options']['ssl']['peer_certificate']
            : null;
        $parsed = $cert ? @openssl_x509_parse($cert) : false;

        if (!is_array($parsed)) {
            $findings[] = array(
                'severity' => 'warn',
                'message'  => __('Could not parse the TLS certificate.', 'nubivio-healthcare-security-hardening'),
            );
            return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
        }

        $summary['available']  = true;
        $summary['subject_cn'] = isset($parsed['subject']['CN']) ? (string) $parsed['subject']['CN'] : '';
        $summary['issuer_cn']  = isset($parsed['issuer']['CN']) ? (string) $parsed['issuer']['CN'] : '';
        $summary['issuer_o']   = isset($parsed['issuer']['O']) ? (string) $parsed['issuer']['O'] : '';
        $summary['valid_from'] = isset($parsed['validFrom_time_t']) ? (int) $parsed['validFrom_time_t'] : 0;
        $summary['valid_to']   = isset($parsed['validTo_time_t']) ? (int) $parsed['validTo_time_t'] : 0;
        $summary['days_remaining'] = $summary['valid_to']
            ? (int) floor(($summary['valid_to'] - time()) / DAY_IN_SECONDS)
            : null;
        $summary['signature'] = isset($parsed['signatureTypeSN']) ? (string) $parsed['signatureTypeSN'] : '';

        if (!empty($parsed['extensions']['subjectAltName'])) {
            foreach (explode(',', $parsed['extensions']['subjectAltName']) as $san) {
                $san = trim(preg_replace('/^DNS:/i', '', $san));
                if ($san !== '') {
                    $summary['sans'][] = $san;
                }
            }
        }

        if ($summary['days_remaining'] !== null && $summary['days_remaining'] < 14) {
            $this->add(
                $findings,
                $counts,
                'high',
                sprintf(
                    __('TLS certificate expires in %1$d days (%2$s).', 'nubivio-healthcare-security-hardening'),
                    $summary['days_remaining'],
                    date_i18n(get_option('date_format'), $summary['valid_to'])
                )
            );
        } elseif ($summary['days_remaining'] !== null && $summary['days_remaining'] < 30) {
            $this->add(
                $findings,
                $counts,
                'medium',
                sprintf(
                    __('TLS certificate expires in %1$d days (%2$s).', 'nubivio-healthcare-security-hardening'),
                    $summary['days_remaining'],
                    date_i18n(get_option('date_format'), $summary['valid_to'])
                )
            );
        }
        if (stripos($summary['signature'], 'sha1') !== false) {
            $this->add(
                $findings,
                $counts,
                'high',
                __('Certificate uses SHA-1 signature; browsers reject this.', 'nubivio-healthcare-security-hardening')
            );
        }

        $names = array_merge(array($summary['subject_cn']), $summary['sans']);
        $match = false;
        foreach ($names as $name) {
            if ($name === $host) {
                $match = true;
                break;
            }
            if ($name !== '' && substr($name, 0, 2) === '*.' && substr($host, -strlen(substr($name, 1))) === substr($name, 1)) {
                $match = true;
                break;
            }
        }
        if (!$match) {
            $this->add(
                $findings,
                $counts,
                'high',
                __('TLS certificate subject does not match the site host.', 'nubivio-healthcare-security-hardening')
            );
        }

        if (function_exists('dns_get_record')) {
            $type = defined('DNS_ANY') ? DNS_ANY : DNS_TXT;
            $tlsa = @dns_get_record('_443._tcp.' . $host, $type);
            foreach ((array) $tlsa as $r) {
                if ((isset($r['type']) && $r['type'] === 'TLSA') || isset($r['tlsa'])) {
                    $summary['dane'] = true;
                    $findings[]      = array(
                        'severity' => 'low',
                        'message'  => __('DANE/TLSA record present. Validate at ssl-tools.net/dane or a DNS DANE validator.', 'nubivio-healthcare-security-hardening'),
                    );
                    $counts['low']++;
                    break;
                }
            }
        }

        $result = array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
        set_transient($key, $result, 6 * HOUR_IN_SECONDS);
        return $result;
    }

    public static function health_row($summary) {
        $days   = isset($summary['days_remaining']) ? $summary['days_remaining'] : null;
        $status = ($days !== null && $days < 14)
            ? 'fail'
            : (($days !== null && $days < 30) ? 'warn' : 'pass');
        return array(
            'label'  => __('TLS overview', 'nubivio-healthcare-security-hardening'),
            'status' => $status,
            'detail' => $days === null
                ? __('TLS certificate status is unavailable.', 'nubivio-healthcare-security-hardening')
                : sprintf(
                    _n(
                        'TLS certificate has %d day remaining.',
                        'TLS certificate has %d days remaining.',
                        $days,
                        'nubivio-healthcare-security-hardening'
                    ),
                    $days
                ),
        );
    }

    private function add(&$findings, &$counts, $severity, $message) {
        $findings[]        = array('severity' => $severity, 'message' => $message);
        $counts[$severity]++;
    }
}
