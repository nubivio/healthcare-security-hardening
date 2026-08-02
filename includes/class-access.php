<?php
/**
 * Access and integrity checks: administrator baseline, privilege escalation,
 * application passwords, must-use plugins, siteurl sanity and recently
 * modified core files.
 *
 * Read-only. The only state it writes is the first-run administrator baseline;
 * every later baseline change goes through the nonce protected approve action.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

class Nubivio_HSH_Access {

    /** Users inspected for elevated capabilities in a single run. */
    const MAX_USERS = 500;

    /** Files walked by the recently-modified core file scan. */
    const MAX_SCANNED_FILES = 10000;

    /** Individual items listed in the findings. */
    const MAX_LISTED = 20;

    /** Administrator capabilities that no other role should hold. */
    const ADMIN_CAPS = array('manage_options', 'edit_users', 'promote_users', 'delete_users', 'create_users');

    /** @var Nubivio_HSH */
    private $core;

    public function __construct($core) {
        $this->core = $core;
    }

    /**
     * Run every access sub-check.
     *
     * @return array{findings:array<int,array>,counts:array<string,int>,report:array}
     */
    public function run() {
        $findings = array();
        $counts   = array('high' => 0, 'medium' => 0, 'low' => 0);

        $users    = $this->scan_users();
        $baseline = $this->get_baseline();
        $app_pws  = $this->collect_app_passwords($users['admins']);

        $report = array(
            'admins'          => array(),
            'app_passwords'   => array(),
            'mu_plugins'      => array(),
            'baseline_set_at' => isset($baseline['set_at']) ? (int) $baseline['set_at'] : 0,
            'baseline_state'  => 'ok',
            'needs_approval'  => false,
            'users_truncated' => $users['truncated'],
        );

        $this->check_admin_baseline($users['admins'], $app_pws, $baseline, $findings, $counts, $report);
        $this->check_recent_admins($users['admins'], $baseline, $findings, $counts);
        $this->check_roles($findings, $counts);
        $this->check_elevated_users($users['elevated'], $findings, $counts);
        $this->check_app_passwords($app_pws, $baseline, $findings, $counts, $report);
        $this->check_mu_plugins($findings, $counts, $report);
        $this->check_site_url($findings, $counts);
        $this->check_recent_core_files($findings, $counts);

        $report['admins'] = $this->admin_rows($users['admins'], $app_pws, $baseline);

        if ($users['truncated']) {
            $findings[] = $this->finding('warn', sprintf(
                /* translators: %d: maximum number of users inspected. */
                __('User review truncated at %d users.', 'nubivio-healthcare-security-hardening'),
                self::MAX_USERS
            ));
        }

        return array('findings' => $findings, 'counts' => $counts, 'report' => $report);
    }

    /**
     * Build a fresh baseline from the current site state. Used by the
     * nonce protected "Approve current admins" action in the main file.
     *
     * @return array
     */
    public function build_baseline() {
        $users   = $this->scan_users();
        $app_pws = $this->collect_app_passwords($users['admins']);

        return array(
            'admin_fingerprint'  => $this->admin_fingerprint($users['admins']),
            'admin_snapshot'     => array_values($users['admins']),
            'app_pw_fingerprint' => $this->app_pw_fingerprint($app_pws),
            'app_pw_snapshot'    => $this->app_pw_keys($app_pws),
            'set_at'             => time(),
        );
    }

    /**
     * Health row summarising the baseline state.
     *
     * @param array $report Report from run().
     * @return array{label:string,status:string,detail:string}
     */
    public static function health_row($report) {
        $label = __('Administrator baseline', 'nubivio-healthcare-security-hardening');
        $state = isset($report['baseline_state']) ? $report['baseline_state'] : 'ok';

        if ($state === 'new') {
            return array(
                'label'  => $label,
                'status' => 'warn',
                'detail' => __('A first baseline of administrator accounts was recorded. Review and approve it.', 'nubivio-healthcare-security-hardening'),
            );
        }
        if ($state === 'changed') {
            return array(
                'label'  => $label,
                'status' => 'fail',
                'detail' => __('The administrator account list differs from the approved baseline.', 'nubivio-healthcare-security-hardening'),
            );
        }
        return array(
            'label'  => $label,
            'status' => 'pass',
            'detail' => __('Administrator accounts match the approved baseline.', 'nubivio-healthcare-security-hardening'),
        );
    }

    /* Sub-checks */

    /** 3A. Administrator baseline diff. */
    private function check_admin_baseline($admins, $app_pws, $baseline, &$findings, &$counts, &$report) {
        $fingerprint = $this->admin_fingerprint($admins);

        if (empty($baseline['admin_fingerprint'])) {
            // First run: record a silent baseline so later scans have something to diff.
            $this->save_baseline(array(
                'admin_fingerprint'  => $fingerprint,
                'admin_snapshot'     => array_values($admins),
                'app_pw_fingerprint' => $this->app_pw_fingerprint($app_pws),
                'app_pw_snapshot'    => $this->app_pw_keys($app_pws),
                'set_at'             => time(),
            ));
            $report['baseline_state']  = 'new';
            $report['needs_approval']  = true;
            $report['baseline_set_at'] = time();
            return;
        }

        if ($fingerprint === $baseline['admin_fingerprint']) {
            return;
        }

        $snapshot = isset($baseline['admin_snapshot']) && is_array($baseline['admin_snapshot'])
            ? $baseline['admin_snapshot']
            : array();
        $known = array();
        foreach ($snapshot as $row) {
            if (isset($row['id'])) {
                $known[(int) $row['id']] = $row;
            }
        }

        $added = array();
        foreach ($admins as $id => $row) {
            if (!isset($known[$id])) {
                $added[] = $row['login'];
            }
        }
        $removed = array();
        foreach ($known as $id => $row) {
            if (!isset($admins[$id])) {
                $removed[] = isset($row['login']) ? $row['login'] : (string) $id;
            }
        }

        $detail = array();
        if ($added) {
            $detail[] = sprintf(
                /* translators: %s: comma separated list of user logins. */
                __('added: %s', 'nubivio-healthcare-security-hardening'),
                implode(', ', array_slice($added, 0, self::MAX_LISTED))
            );
        }
        if ($removed) {
            $detail[] = sprintf(
                /* translators: %s: comma separated list of user logins. */
                __('removed: %s', 'nubivio-healthcare-security-hardening'),
                implode(', ', array_slice($removed, 0, self::MAX_LISTED))
            );
        }

        $message = __('Administrator account list changed since last approved baseline. Review below.', 'nubivio-healthcare-security-hardening');
        if ($detail) {
            $message .= ' (' . implode('; ', $detail) . ')';
        }

        $findings[] = $this->finding('high', $message);
        $counts['high']++;
        $report['baseline_state'] = 'changed';
        $report['needs_approval'] = true;
    }

    /** 3B. Administrators created in the last 30 days. */
    private function check_recent_admins($admins, $baseline, &$findings, &$counts) {
        $cutoff      = time() - (30 * DAY_IN_SECONDS);
        $baseline_at = isset($baseline['set_at']) ? (int) $baseline['set_at'] : 0;
        $known       = array();
        if (isset($baseline['admin_snapshot']) && is_array($baseline['admin_snapshot'])) {
            foreach ($baseline['admin_snapshot'] as $row) {
                if (isset($row['id'])) {
                    $known[(int) $row['id']] = true;
                }
            }
        }

        foreach ($admins as $id => $row) {
            $registered = strtotime((string) $row['registered']);
            if (!$registered || $registered < $cutoff) {
                continue;
            }
            // Already vouched for by the approved baseline.
            if (isset($known[$id]) && $baseline_at > 0 && $registered < $baseline_at) {
                continue;
            }
            $findings[] = $this->finding('medium', sprintf(
                /* translators: 1: user login, 2: email address, 3: registration date. */
                __('Administrator \'%1$s\' (%2$s) created on %3$s. Verify this was intentional.', 'nubivio-healthcare-security-hardening'),
                $row['login'],
                $this->mask_email($row['email']),
                date_i18n(get_option('date_format'), $registered)
            ));
            $counts['medium']++;
        }
    }

    /** 3C. Roles that carry administrator capabilities. */
    private function check_roles(&$findings, &$counts) {
        if (!function_exists('wp_roles')) {
            return;
        }
        $roles = wp_roles()->roles;
        if (!is_array($roles)) {
            return;
        }

        foreach ($roles as $slug => $role) {
            if ($slug === 'administrator' || empty($role['capabilities']) || !is_array($role['capabilities'])) {
                continue;
            }
            $hits = array();
            foreach (self::ADMIN_CAPS as $cap) {
                if (!empty($role['capabilities'][$cap])) {
                    $hits[] = $cap;
                }
            }
            if (!$hits) {
                continue;
            }
            $findings[] = $this->finding('high', sprintf(
                /* translators: 1: role slug, 2: comma separated list of capabilities. */
                __('Non-administrator role \'%1$s\' has administrator capabilities: %2$s.', 'nubivio-healthcare-security-hardening'),
                $slug,
                implode(', ', $hits)
            ));
            $counts['high']++;
        }
    }

    /** 3C. Users holding manage_options outside the administrator role. */
    private function check_elevated_users($elevated, &$findings, &$counts) {
        foreach (array_slice($elevated, 0, self::MAX_LISTED) as $login) {
            $findings[] = $this->finding('high', sprintf(
                /* translators: %s: user login. */
                __('User \'%s\' has manage_options capability but is not an administrator role. Investigate.', 'nubivio-healthcare-security-hardening'),
                $login
            ));
            $counts['high']++;
        }
    }

    /** 3D. Application passwords on administrator accounts. */
    private function check_app_passwords($app_pws, $baseline, &$findings, &$counts, &$report) {
        $known = isset($baseline['app_pw_snapshot']) && is_array($baseline['app_pw_snapshot'])
            ? $baseline['app_pw_snapshot']
            : array();
        $has_baseline = !empty($baseline['admin_fingerprint']);

        foreach ($app_pws as $pw) {
            $is_new = $has_baseline && !in_array($pw['key'], $known, true);

            $report['app_passwords'][] = array(
                'login'   => $pw['login'],
                'name'    => $pw['name'],
                'created' => $pw['created'] ? date_i18n(get_option('date_format'), $pw['created']) : '',
                'new'     => $is_new,
            );

            if (!$is_new) {
                continue;
            }
            $findings[] = $this->finding('medium', sprintf(
                /* translators: 1: application password name, 2: user login, 3: creation date. */
                __('New application password \'%1$s\' on admin \'%2$s\', created %3$s. Revoke via Users, Profile if unknown.', 'nubivio-healthcare-security-hardening'),
                $pw['name'],
                $pw['login'],
                $pw['created'] ? date_i18n(get_option('date_format'), $pw['created']) : ''
            ));
            $counts['medium']++;
        }
    }

    /** 3E. Unexpected must-use plugins. */
    private function check_mu_plugins(&$findings, &$counts, &$report) {
        $dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
        if (!is_dir($dir) || !is_readable($dir)) {
            return;
        }

        $patterns = apply_filters('nubivio_hsh_known_mu_plugins', array(
            '^wpengine-common\.php$',
            '^kinsta-mu-plugins?.*\.php$',
            '^kinsta-cache-purger\.php$',
            '^cloudways-.*\.php$',
            '^siteground-.*\.php$',
            '^sg-.*\.php$',
            '^wpmudev-.*\.php$',
            '^wpaas-.*\.php$',
            '^gd-system-plugin\.php$',
            '^presslabs-mu\.php$',
            '^rocket-cache-mu\.php$',
        ));

        $entries = scandir($dir);
        if (!is_array($entries)) {
            return;
        }

        $subdirs = array();
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . '/' . $entry;
            if (is_dir($path)) {
                $subdirs[] = $entry;
                continue;
            }
            if (substr(strtolower($entry), -4) !== '.php') {
                continue;
            }

            $known = false;
            foreach ((array) $patterns as $pattern) {
                if (preg_match('#' . $pattern . '#i', $entry)) {
                    $known = true;
                    break;
                }
            }

            $report['mu_plugins'][] = array('file' => $entry, 'known' => $known);

            if ($known) {
                continue;
            }
            $findings[] = $this->finding('medium', sprintf(
                /* translators: %s: must-use plugin filename. */
                __('Unexpected must-use plugin \'%s\'. MU-plugins run on every request and are a common persistence path. Review.', 'nubivio-healthcare-security-hardening'),
                $entry
            ));
            $counts['medium']++;
        }

        if ($subdirs) {
            $findings[] = $this->finding('medium', sprintf(
                /* translators: %s: comma separated list of directory names. */
                __('The must-use plugins directory contains subdirectories (%s). WordPress does not load these automatically, which is unusual. Review.', 'nubivio-healthcare-security-hardening'),
                implode(', ', array_slice($subdirs, 0, self::MAX_LISTED))
            ));
            $counts['medium']++;
        }
    }

    /** 3F. siteurl host sanity. */
    private function check_site_url(&$findings, &$counts) {
        if (empty($_SERVER['HTTP_HOST'])) {
            return; // CLI or cron: no request host to compare against.
        }
        $request_host = strtolower(sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])));
        $request_host = preg_replace('/:\d+$/', '', $request_host);
        $option_host  = strtolower((string) wp_parse_url(get_option('siteurl'), PHP_URL_HOST));

        if ($option_host === '' || $request_host === '' || $option_host === $request_host) {
            return;
        }

        $findings[] = $this->finding('medium', sprintf(
            /* translators: 1: host configured in the siteurl option, 2: host of the current request. */
            __('Site URL host (%1$s) does not match the current request host (%2$s). If unexpected, an attacker may have changed siteurl to redirect notifications.', 'nubivio-healthcare-security-hardening'),
            $option_host,
            $request_host
        ));
        $counts['medium']++;
    }

    /** 3G. Core PHP files modified well after the last core update. */
    private function check_recent_core_files(&$findings, &$counts) {
        $reference = 0;
        foreach (array('wp-load.php', 'wp-settings.php', 'wp-login.php') as $marker) {
            $path = ABSPATH . $marker;
            if (file_exists($path)) {
                $reference = max($reference, (int) filemtime($path));
            }
        }
        if ($reference === 0) {
            return;
        }

        $cutoff    = time() - (30 * DAY_IN_SECONDS);
        $threshold = $reference + DAY_IN_SECONDS;
        $scanned   = 0;
        $suspect   = array();
        $truncated = false;

        foreach (array('wp-admin', 'wp-includes') as $sub) {
            $root = ABSPATH . $sub;
            if (!is_dir($root) || !is_readable($root)) {
                continue;
            }
            try {
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
            } catch (Exception $e) {
                continue;
            }

            foreach ($it as $file) {
                if ($scanned >= self::MAX_SCANNED_FILES) {
                    $truncated = true;
                    break 2;
                }
                if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') {
                    continue;
                }
                $scanned++;
                $mtime = (int) $file->getMTime();
                if ($mtime > $cutoff && $mtime > $threshold) {
                    $suspect[] = array(
                        'path'  => str_replace(ABSPATH, '', $file->getPathname()),
                        'mtime' => $mtime,
                    );
                }
            }
        }

        if ($truncated) {
            $findings[] = $this->finding('warn', sprintf(
                /* translators: %d: maximum number of files scanned. */
                __('Recent-file check truncated at %d files.', 'nubivio-healthcare-security-hardening'),
                self::MAX_SCANNED_FILES
            ));
        }

        foreach (array_slice($suspect, 0, self::MAX_LISTED) as $item) {
            $findings[] = $this->finding('high', sprintf(
                /* translators: 1: file path relative to the WordPress root, 2: modification date. */
                __('Core file %1$s was modified on %2$s, well after the last core update. Investigate.', 'nubivio-healthcare-security-hardening'),
                $item['path'],
                date_i18n(get_option('date_format'), $item['mtime'])
            ));
            $counts['high']++;
        }

        $extra = count($suspect) - self::MAX_LISTED;
        if ($extra > 0) {
            $findings[] = $this->finding('high', sprintf(
                /* translators: %d: number of additional recently modified core files. */
                _n('%d further core file was modified after the last core update.', '%d further core files were modified after the last core update.', $extra, 'nubivio-healthcare-security-hardening'),
                $extra
            ));
            $counts['high']++;
        }
    }

    /* Data collection */

    /**
     * One pass over the user list: administrators (by role or capability) and
     * users holding manage_options without the administrator role.
     *
     * @return array{admins:array<int,array>,elevated:array<int,string>,truncated:bool}
     */
    private function scan_users() {
        $users = get_users(array('number' => self::MAX_USERS + 1, 'orderby' => 'ID', 'order' => 'ASC'));

        $truncated = count($users) > self::MAX_USERS;
        if ($truncated) {
            $users = array_slice($users, 0, self::MAX_USERS);
        }

        $admins   = array();
        $elevated = array();

        foreach ($users as $u) {
            $is_admin_role = in_array('administrator', (array) $u->roles, true);
            $can_manage    = user_can($u, 'manage_options');

            if ($is_admin_role || $can_manage) {
                $admins[(int) $u->ID] = array(
                    'id'         => (int) $u->ID,
                    'login'      => (string) $u->user_login,
                    'email'      => (string) $u->user_email,
                    'registered' => (string) $u->user_registered,
                );
            }
            if ($can_manage && !$is_admin_role) {
                $elevated[] = (string) $u->user_login;
            }
        }

        ksort($admins);

        return array('admins' => $admins, 'elevated' => $elevated, 'truncated' => $truncated);
    }

    /**
     * Application passwords across the administrator accounts.
     *
     * @param array<int,array> $admins
     * @return array<int,array>
     */
    private function collect_app_passwords($admins) {
        $out = array();
        if (!class_exists('WP_Application_Passwords')) {
            return $out;
        }

        foreach ($admins as $id => $row) {
            $passwords = WP_Application_Passwords::get_user_application_passwords($id);
            if (!is_array($passwords)) {
                continue;
            }
            foreach ($passwords as $pw) {
                $uuid = isset($pw['uuid']) ? (string) $pw['uuid'] : '';
                $out[] = array(
                    'key'     => $id . ':' . $uuid,
                    'user_id' => $id,
                    'login'   => $row['login'],
                    'name'    => isset($pw['name']) ? (string) $pw['name'] : '',
                    'created' => isset($pw['created']) ? (int) $pw['created'] : 0,
                );
            }
        }

        return $out;
    }

    /**
     * Rows for the administrators table on the Compliance tab.
     *
     * @return array<int,array>
     */
    private function admin_rows($admins, $app_pws, $baseline) {
        $known = array();
        if (isset($baseline['admin_snapshot']) && is_array($baseline['admin_snapshot'])) {
            foreach ($baseline['admin_snapshot'] as $row) {
                if (isset($row['id'])) {
                    $known[(int) $row['id']] = true;
                }
            }
        }

        $pw_counts = array();
        foreach ($app_pws as $pw) {
            $uid = (int) $pw['user_id'];
            $pw_counts[$uid] = isset($pw_counts[$uid]) ? $pw_counts[$uid] + 1 : 1;
        }

        $rows = array();
        foreach ($admins as $id => $row) {
            $last_login = get_user_meta($id, '_last_login', true);
            $registered = strtotime((string) $row['registered']);

            $rows[] = array(
                'id'           => $id,
                'login'        => $row['login'],
                'email'        => $this->mask_email($row['email']),
                'registered'   => $registered ? date_i18n(get_option('date_format'), $registered) : '',
                'last_login'   => $this->format_last_login($last_login),
                'app_pw_count' => isset($pw_counts[$id]) ? $pw_counts[$id] : 0,
                'state'        => empty($baseline['admin_fingerprint']) ? 'unknown' : (isset($known[$id]) ? 'unchanged' : 'new'),
            );
        }

        return $rows;
    }

    /* Baseline helpers */

    private function get_baseline() {
        $o = $this->core->get_options();
        return isset($o['baseline']) && is_array($o['baseline']) ? $o['baseline'] : array();
    }

    private function save_baseline($baseline) {
        $o = $this->core->get_options();
        $o['baseline'] = $baseline;
        update_option(Nubivio_HSH::OPTION, $o);
    }

    /**
     * @param array<int,array> $admins
     * @return string
     */
    private function admin_fingerprint($admins) {
        ksort($admins);
        $parts = array();
        foreach ($admins as $row) {
            $parts[] = $row['id'] . ':' . $row['login'] . ':' . $row['email'];
        }
        return md5(implode('|', $parts));
    }

    /**
     * @param array<int,array> $app_pws
     * @return string
     */
    private function app_pw_fingerprint($app_pws) {
        $keys = $this->app_pw_keys($app_pws);
        sort($keys);
        return md5(implode('|', $keys));
    }

    /**
     * @param array<int,array> $app_pws
     * @return array<int,string>
     */
    private function app_pw_keys($app_pws) {
        $keys = array();
        foreach ($app_pws as $pw) {
            $keys[] = $pw['key'];
        }
        return $keys;
    }

    /* Formatting */

    /**
     * Keep the first character and the domain, mask the rest.
     *
     * @param string $email
     * @return string
     */
    private function mask_email($email) {
        $email = (string) $email;
        $at    = strpos($email, '@');
        if ($at === false || $at < 1) {
            return $email === '' ? '' : '***';
        }
        return substr($email, 0, 1) . '***' . substr($email, $at);
    }

    private function format_last_login($value) {
        if (empty($value)) {
            return '';
        }
        $ts = is_numeric($value) ? (int) $value : strtotime((string) $value);
        return $ts ? date_i18n(get_option('date_format'), $ts) : '';
    }

    private function finding($severity, $message) {
        return array('severity' => $severity, 'message' => $message);
    }
}
