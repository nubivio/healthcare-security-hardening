<?php
/**
 * WordPress core integrity check against the official WordPress.org checksums
 * API. Read-only: it hashes core files and compares, it never writes or repairs.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Integrity {

    /** Files hashed in a single run before the check gives up. */
    const MAX_FILES = 5000;

    /** Individual modified/missing files listed in the findings. */
    const MAX_LISTED = 20;

    /** @var Nubivio_HSH */
    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    /**
     * Compare the installed core files against the published checksums.
     *
     * @return array{findings:array<int,array>,counts:array<string,int>,summary:array}
     */
    public function run() {
        $version = get_bloginfo('version');
        $locale  = get_locale();

        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);
        $summary  = array(
            'version'    => $version,
            'locale'     => $locale,
            'checked'    => 0,
            'modified'   => array(),
            'missing'    => array(),
            'unreadable' => array(),
            'truncated'  => false,
            'available'  => false,
        );

        $checksums = $this->fetch_checksums($version, $locale);
        if (!is_array($checksums) || empty($checksums)) {
            $findings[] = $this->finding(
                'warn',
                __('Could not retrieve WordPress checksums; skipping core integrity check.', 'nubivio-healthcare-security-hardening')
            );
            return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
        }

        $summary['available'] = true;

        foreach ($checksums as $path => $expected) {
            if ($this->is_skipped($path)) {
                continue;
            }
            if ($summary['checked'] >= self::MAX_FILES) {
                $summary['truncated'] = true;
                break;
            }
            $summary['checked']++;

            $abs = ABSPATH . $path;
            if (!file_exists($abs)) {
                $summary['missing'][] = $path;
                continue;
            }
            if (!is_readable($abs)) {
                $summary['unreadable'][] = $path;
                continue;
            }
            if (md5_file($abs) !== $expected) {
                $summary['modified'][] = $path;
            }
        }

        if ($summary['truncated']) {
            $findings[] = $this->finding(
                'warn',
                sprintf(
                    /* translators: %d: maximum number of files hashed per run. */
                    __('Core integrity check truncated at %d files.', 'nubivio-healthcare-security-hardening'),
                    self::MAX_FILES
                )
            );
        }

        foreach (array_slice($summary['missing'], 0, self::MAX_LISTED) as $path) {
            $findings[] = $this->finding('high', sprintf(
                /* translators: %s: path of a core file, relative to the WordPress root. */
                __('Core file is missing: %s', 'nubivio-healthcare-security-hardening'),
                $path
            ));
            $counts['high']++;
        }
        $extra_missing = count($summary['missing']) - self::MAX_LISTED;
        if ($extra_missing > 0) {
            $findings[] = $this->finding('high', sprintf(
                /* translators: %d: number of additional missing core files. */
                _n('%d further core file is missing.', '%d further core files are missing.', $extra_missing, 'nubivio-healthcare-security-hardening'),
                $extra_missing
            ));
            $counts['high']++;
        }

        foreach (array_slice($summary['modified'], 0, self::MAX_LISTED) as $path) {
            $findings[] = $this->finding('high', sprintf(
                /* translators: %s: path of a core file, relative to the WordPress root. */
                __('Core file does not match the published checksum: %s', 'nubivio-healthcare-security-hardening'),
                $path
            ));
            $counts['high']++;
        }
        $extra_modified = count($summary['modified']) - self::MAX_LISTED;
        if ($extra_modified > 0) {
            $findings[] = $this->finding('high', sprintf(
                /* translators: %d: number of additional modified core files. */
                _n('%d further core file does not match its checksum.', '%d further core files do not match their checksums.', $extra_modified, 'nubivio-healthcare-security-hardening'),
                $extra_modified
            ));
            $counts['high']++;
        }

        return array('findings' => $findings, 'counts' => $counts, 'summary' => $summary);
    }

    /**
     * Health row for the site health checklist.
     *
     * @param array $summary Summary from run().
     * @return array{label:string,status:string,detail:string}
     */
    public static function health_row($summary) {
        $label = __('WordPress core integrity', 'nubivio-healthcare-security-hardening');

        if (empty($summary['available'])) {
            return array(
                'label'  => $label,
                'status' => 'warn',
                'detail' => __('Checksums were unavailable, so core files could not be verified.', 'nubivio-healthcare-security-hardening'),
            );
        }

        $modified = isset($summary['modified']) ? count($summary['modified']) : 0;
        $missing  = isset($summary['missing']) ? count($summary['missing']) : 0;
        $total    = $modified + $missing;

        if ($total === 0) {
            return array(
                'label'  => $label,
                'status' => 'pass',
                'detail' => sprintf(
                    /* translators: %d: number of core files verified. */
                    __('All %d core files match the published checksums.', 'nubivio-healthcare-security-hardening'),
                    isset($summary['checked']) ? (int) $summary['checked'] : 0
                ),
            );
        }

        $status = $total <= 3 ? 'warn' : 'fail';

        return array(
            'label'  => $label,
            'status' => $status,
            'detail' => sprintf(
                /* translators: 1: number of modified core files, 2: number of missing core files. */
                __('%1$d modified and %2$d missing core files.', 'nubivio-healthcare-security-hardening'),
                $modified,
                $missing
            ),
        );
    }

    /**
     * Fetch and cache the checksum map for this version and locale.
     *
     * @param string $version
     * @param string $locale
     * @return array<string,string>|null
     */
    private function fetch_checksums($version, $locale) {
        $key    = 'nubivio_hsh_checksums_' . md5($version . '|' . $locale);
        $cached = get_transient($key);
        if (is_array($cached)) {
            return $cached;
        }
        if ($cached === 'unavailable') {
            return null;
        }

        $url = 'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode($version)
             . '&locale=' . rawurlencode($locale);
        $res = wp_remote_get($url, array('timeout' => 8));

        if (is_wp_error($res)) {
            set_transient($key, 'unavailable', HOUR_IN_SECONDS);
            return null;
        }

        $data = json_decode(wp_remote_retrieve_body($res), true);
        if (!is_array($data) || empty($data['checksums']) || !is_array($data['checksums'])) {
            set_transient($key, 'unavailable', HOUR_IN_SECONDS);
            return null;
        }

        $map = $data['checksums'];
        // Some locales nest the map one level deeper, keyed by version.
        if (!empty($map[$version]) && is_array($map[$version])) {
            $map = $map[$version];
        }

        set_transient($key, $map, 12 * HOUR_IN_SECONDS);
        return $map;
    }

    /**
     * Paths outside core's control, or that legitimately differ per install.
     *
     * @param string $path
     * @return bool
     */
    private function is_skipped($path) {
        return strpos($path, 'wp-content/') === 0
            || $path === 'wp-config-sample.php'
            || $path === 'wp-config.php';
    }

    private function finding($severity, $message) {
        return array('severity' => $severity, 'message' => $message);
    }
}
