<?php
/**
 * Compliance tab view. Receives $core (Nubivio_HSH) and $o (options array).
 * Additive and read-only unless the user submits the nonce-protected scan form.
 *
 * @package Nubivio_HSH
 */

if (!defined('ABSPATH')) {
    exit;
}

/** @var Nubivio_HSH $core */
/** @var array $o */

$scan   = $core->get_scan();
$host   = wp_parse_url(home_url(), PHP_URL_HOST);
$intnl  = 'https://internet.nl/site/' . rawurlencode((string) $host) . '/';
$doc_url = function ($doc) {
    return wp_nonce_url(
        admin_url('admin-post.php?action=nubivio_hsh_doc&doc=' . rawurlencode($doc)),
        'nubivio_hsh_doc'
    );
};

// Header to framework clause mapping for the evidence table.
$header_clauses = array(
    'Strict-Transport-Security' => __('NIS2 Art. 21: encryption in transit', 'nubivio-healthcare-security-hardening'),
    'Content-Security-Policy'   => __('Product security hardening / GDPR script control', 'nubivio-healthcare-security-hardening'),
    'Content-Security-Policy-Report-Only' => __('Product security hardening / GDPR script control', 'nubivio-healthcare-security-hardening'),
    'X-Frame-Options'           => __('Clickjacking hardening', 'nubivio-healthcare-security-hardening'),
    'Permissions-Policy'        => __('Attack-surface minimisation', 'nubivio-healthcare-security-hardening'),
    'Referrer-Policy'           => __('Data minimisation', 'nubivio-healthcare-security-hardening'),
    'X-Content-Type-Options'    => __('Content hardening', 'nubivio-healthcare-security-hardening'),
);
?>
<div class="ns-card ns-compliance-intro">
    <h2><?php esc_html_e('Compliance', 'nubivio-healthcare-security-hardening'); ?></h2>
    <p class="ns-card-intro">
        <?php
        esc_html_e(
            'Optional CRA, GDPR and NIS2 checks plus site health, built around the headers and security.txt this plugin already enforces.',
            'nubivio-healthcare-security-hardening'
        );
        echo ' ';
        esc_html_e('Nothing here changes your hardening; it verifies and documents it.', 'nubivio-healthcare-security-hardening');
        ?>
    </p>

    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="ns-scan-form">
        <input type="hidden" name="action" value="<?php echo esc_attr(Nubivio_HSH::SCAN_ACTION); ?>">
        <?php wp_nonce_field(Nubivio_HSH::SCAN_ACTION); ?>
        <button type="submit" class="ns-btn ns-run-scan"><?php esc_html_e('Run compliance scan', 'nubivio-healthcare-security-hardening'); ?></button>
        <span class="ns-by"><?php
            esc_html_e(
                'This may take a few seconds. Scans query the WordPress.org Plugins API (see External Services in the readme).',
                'nubivio-healthcare-security-hardening'
            );
        ?></span>
    </form>
</div>

<?php
// v2.6.0 risk scenarios: combined signals from the last scan, shown first.
if (!empty($scan['frameworks']['scenarios']['summary'])):
    $scn_sum  = $scan['frameworks']['scenarios']['summary'];
    $scn_list = isset($scn_sum['scenarios']) ? (array) $scn_sum['scenarios'] : array();
    ?>
    <div class="ns-card ns-scenarios">
        <h2><?php esc_html_e('Risk scenarios', 'nubivio-healthcare-security-hardening'); ?></h2>
        <p class="ns-card-intro"><strong><?php echo esc_html(Nubivio_HSH_Scenarios::caveat()); ?></strong></p>
        <?php if (!$scn_list): ?>
            <p class="ns-desc"><?php
                esc_html_e(
                    'No combination of signals from the last scan matches a known attack scenario.',
                    'nubivio-healthcare-security-hardening'
                );
            ?></p>
        <?php endif; ?>
        <?php foreach ($scn_list as $scn): ?>
            <div class="ns-scenario ns-finding-<?php echo esc_attr($scn['severity']); ?>">
                <h3>
                    <span class="ns-chip ns-chip-<?php echo esc_attr($scn['severity']); ?>"><?php
                        echo esc_html(strtoupper($scn['severity']));
                    ?></span>
                    <?php echo esc_html($scn['title']); ?>
                </h3>
                <p class="ns-desc"><?php esc_html_e('Signals found:', 'nubivio-healthcare-security-hardening'); ?></p>
                <ul class="ns-finding-list">
                    <?php foreach ((array) $scn['signals'] as $scn_sig): ?>
                        <li><?php echo esc_html($scn_sig); ?></li>
                    <?php endforeach; ?>
                </ul>
                <p><strong><?php esc_html_e('First step:', 'nubivio-healthcare-security-hardening'); ?></strong>
                    <?php echo esc_html($scn['first_step']); ?></p>
            </div>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<?php
// v2.6.0 PHP runtime: read live from the running PHP process, no scan or network needed.
if (class_exists('Nubivio_HSH_Php_Runtime')):
    $php_rt      = (new Nubivio_HSH_Php_Runtime($core))->run();
    $php_sum     = $php_rt['summary'];
    $php_chips   = array(
        'patched'  => array('ok', __('patched', 'nubivio-healthcare-security-hardening')),
        'unknown'  => array('medium', __('check with host', 'nubivio-healthcare-security-hardening')),
        'affected' => array('high', __('vulnerable', 'nubivio-healthcare-security-hardening')),
    );
    $php_extra   = array();
    foreach ($php_rt['findings'] as $php_f) {
        if (empty($php_f['advisory'])) {
            $php_extra[] = $php_f;
        }
    }
    $php_ini     = function ($value) {
        if ($value === null) {
            return __('not available', 'nubivio-healthcare-security-hardening');
        }
        return $value ? __('on', 'nubivio-healthcare-security-hardening') : __('off', 'nubivio-healthcare-security-hardening');
    };
    ?>
    <div class="ns-card ns-php-runtime">
        <h2><?php esc_html_e('PHP runtime', 'nubivio-healthcare-security-hardening'); ?></h2>
        <p class="ns-card-intro"><?php echo esc_html(Nubivio_HSH_Php_Runtime::process_note()); ?></p>
        <table class="ns-evidence-table"><tbody>
            <tr>
                <td><?php esc_html_e('PHP version', 'nubivio-healthcare-security-hardening'); ?></td>
                <td><code><?php echo esc_html($php_sum['version']); ?></code></td>
            </tr>
            <tr>
                <td><?php esc_html_e('Server API (SAPI)', 'nubivio-healthcare-security-hardening'); ?></td>
                <td><code><?php echo esc_html($php_sum['sapi']); ?></code></td>
            </tr>
            <?php foreach ($php_sum['advisories'] as $php_adv):
                $php_chip = isset($php_chips[$php_adv['status']]) ? $php_chips[$php_adv['status']] : $php_chips['unknown'];
                ?>
                <tr>
                    <td>
                        <?php if ($php_adv['url'] !== ''): ?>
                            <a href="<?php echo esc_url($php_adv['url']); ?>" target="_blank" rel="noopener"><?php
                                echo esc_html($php_adv['name']);
                            ?></a>
                        <?php else: ?>
                            <?php echo esc_html($php_adv['name']); ?>
                        <?php endif; ?>
                        <br><small><?php echo esc_html(implode(', ', $php_adv['cves'])); ?></small>
                    </td>
                    <td>
                        <span class="ns-chip ns-chip-<?php echo esc_attr($php_chip[0]); ?>"><?php echo esc_html($php_chip[1]); ?></span>
                        <?php echo esc_html($php_adv['message']); ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            <tr>
                <td><code>session.upload_progress.enabled</code></td>
                <td><?php echo esc_html($php_ini($php_sum['upload_progress'])); ?></td>
            </tr>
            <?php if ($php_sum['fatal_error_backtraces'] !== null): ?>
                <tr>
                    <td><code>fatal_error_backtraces</code></td>
                    <td><?php echo esc_html($php_ini($php_sum['fatal_error_backtraces'])); ?></td>
                </tr>
            <?php endif; ?>
        </tbody></table>
        <?php if ($php_extra): ?>
            <ul class="ns-finding-list">
                <?php foreach ($php_extra as $php_f): ?>
                    <li class="ns-finding ns-finding-<?php echo esc_attr($php_f['severity']); ?>">
                        <span class="ns-chip ns-chip-<?php echo esc_attr($php_f['severity']); ?>"><?php
                            echo esc_html(strtoupper($php_f['severity']));
                        ?></span>
                        <?php echo esc_html($php_f['message']); ?>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    </div>
<?php endif; ?>

<?php if (!$scan): ?>
    <div class="ns-card">
        <p><?php esc_html_e('No scan has run yet. Run a compliance scan to see your score, findings and evidence.', 'nubivio-healthcare-security-hardening'); ?></p>
    </div>
<?php else:
    $band = isset($scan['band']) ? $scan['band'] : 'red';
    $score = isset($scan['score']) ? (int) $scan['score'] : 0;
    $when  = isset($scan['time']) ? human_time_diff((int) $scan['time'], time()) : '';
    ?>
    <div class="ns-card ns-score-card">
        <div class="ns-score-ring ns-band-<?php echo esc_attr($band); ?>">
            <svg viewBox="0 0 120 120" width="120" height="120" role="img" aria-label="<?php echo esc_attr(sprintf(
                /* translators: %d: compliance score. */
                __('Compliance score %d of 100', 'nubivio-healthcare-security-hardening'),
                $score
            )); ?>">
                <circle class="ns-ring-bg" cx="60" cy="60" r="52" fill="none" stroke-width="12"></circle>
                <circle class="ns-ring-fg" cx="60" cy="60" r="52" fill="none" stroke-width="12"
                    stroke-dasharray="<?php echo esc_attr(round(2 * M_PI * 52, 2)); ?>"
                    stroke-dashoffset="<?php echo esc_attr(round(2 * M_PI * 52 * (1 - $score / 100), 2)); ?>"
                    transform="rotate(-90 60 60)"></circle>
                <text class="ns-ring-num" x="60" y="68" text-anchor="middle"><?php echo (int) $score; ?></text>
            </svg>
        </div>
        <div class="ns-score-meta">
            <span class="ns-pill ns-band-pill-<?php echo esc_attr($band); ?>"><?php
                if ($band === 'green') {
                    esc_html_e('Green', 'nubivio-healthcare-security-hardening');
                } elseif ($band === 'amber') {
                    esc_html_e('Amber', 'nubivio-healthcare-security-hardening');
                } else {
                    esc_html_e('Red', 'nubivio-healthcare-security-hardening');
                }
            ?></span>
            <?php if ($when): ?>
                <span class="ns-stat-sub"><?php echo esc_html(sprintf(
                    /* translators: %s: human readable time difference, e.g. "5 mins". */
                    __('Last scanned %s ago', 'nubivio-healthcare-security-hardening'),
                    $when
                )); ?></span>
            <?php endif; ?>
            <div class="ns-chip-row">
                <span class="ns-chip ns-chip-high"><?php echo esc_html(sprintf(
                    /* translators: %d: number of high severity findings. */
                    _n('%d high', '%d high', (int) $scan['counts']['high'], 'nubivio-healthcare-security-hardening'),
                    (int) $scan['counts']['high']
                )); ?></span>
                <span class="ns-chip ns-chip-medium"><?php echo esc_html(sprintf(
                    /* translators: %d: number of medium severity findings. */
                    _n('%d medium', '%d medium', (int) $scan['counts']['medium'], 'nubivio-healthcare-security-hardening'),
                    (int) $scan['counts']['medium']
                )); ?></span>
                <span class="ns-chip ns-chip-low"><?php echo esc_html(sprintf(
                    /* translators: %d: number of low severity findings. */
                    _n('%d low', '%d low', (int) $scan['counts']['low'], 'nubivio-healthcare-security-hardening'),
                    (int) $scan['counts']['low']
                )); ?></span>
            </div>
        </div>
    </div>

    <?php
    // Per-framework findings.
    $fw_labels = array(
        'cra'  => __('CRA: plugin readiness', 'nubivio-healthcare-security-hardening'),
        'gdpr' => __('GDPR', 'nubivio-healthcare-security-hardening'),
        'nis2' => __('NIS2 Art. 21', 'nubivio-healthcare-security-hardening'),
    );
    foreach ($fw_labels as $key => $label):
        if (empty($scan['frameworks'][$key])) {
            continue;
        }
        $findings = isset($scan['frameworks'][$key]['findings']) ? $scan['frameworks'][$key]['findings'] : array();
        ?>
        <div class="ns-card">
            <h2><?php echo esc_html($label); ?></h2>
            <?php if (empty($findings)): ?>
                <p class="ns-ok-line"><?php esc_html_e('No issues detected.', 'nubivio-healthcare-security-hardening'); ?></p>
            <?php else: ?>
                <ul class="ns-finding-list">
                    <?php foreach ($findings as $f):
                        $sev = isset($f['severity']) ? $f['severity'] : 'low';
                        ?>
                        <li class="ns-finding ns-finding-<?php echo esc_attr($sev); ?>">
                            <span class="ns-chip ns-chip-<?php echo esc_attr($sev === 'ok' ? 'ok' : $sev); ?>"><?php echo esc_html(strtoupper($sev)); ?></span>
                            <?php if (!empty($f['plugin'])): ?><strong><?php echo esc_html($f['plugin']); ?>:</strong> <?php endif; ?>
                            <?php echo esc_html(isset($f['message']) ? $f['message'] : ''); ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>

    <?php
    // v2.6.0 exposure scan of the site itself.
    if (!empty($scan['frameworks']['exposure']['summary']['checks'])):
        $exp       = $scan['frameworks']['exposure'];
        $exp_sum   = $exp['summary'];
        $exp_yes   = '<span class="ns-chip ns-chip-%1$s">%2$s</span>';
        ?>
        <div class="ns-card ns-exposure">
            <h2><?php esc_html_e('Exposure scan', 'nubivio-healthcare-security-hardening'); ?></h2>
            <p class="ns-card-intro"><?php
                esc_html_e(
                    'Requests to your own site only, as an outsider would make them. Bodies are not stored; only path, status and the yes/no result.',
                    'nubivio-healthcare-security-hardening'
                );
                if (!empty($exp_sum['time'])) {
                    echo ' ';
                    echo esc_html(sprintf(
                        /* translators: %s: human readable time difference, e.g. 2 hours. */
                        __('Checked %s ago; results are kept for 12 hours.', 'nubivio-healthcare-security-hardening'),
                        human_time_diff((int) $exp_sum['time'], time())
                    ));
                }
            ?></p>
            <table class="ns-evidence-table">
                <thead><tr>
                    <th><?php esc_html_e('Check', 'nubivio-healthcare-security-hardening'); ?></th>
                    <th><?php esc_html_e('Path', 'nubivio-healthcare-security-hardening'); ?></th>
                    <th><?php esc_html_e('HTTP status', 'nubivio-healthcare-security-hardening'); ?></th>
                    <th><?php esc_html_e('Result', 'nubivio-healthcare-security-hardening'); ?></th>
                </tr></thead>
                <tbody>
                <?php if ($exp_sum['generator'] !== null): ?>
                    <tr>
                        <td><?php esc_html_e('Generator meta tag', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td><code>/</code></td>
                        <td>&nbsp;</td>
                        <td><?php
                        // phpcs:ignore WordPress.Security.EscapeOutput -- format string is static, parts are escaped.
                        echo $exp_sum['generator']
                            ? sprintf($exp_yes, 'low', esc_html__('exposed', 'nubivio-healthcare-security-hardening'))
                            : sprintf($exp_yes, 'ok', esc_html__('not exposed', 'nubivio-healthcare-security-hardening'));
                        ?></td>
                    </tr>
                <?php endif; ?>
                <?php foreach ($exp_sum['checks'] as $exp_row): ?>
                    <tr>
                        <td><?php echo esc_html(Nubivio_HSH_Exposure::label($exp_row['id'])); ?></td>
                        <td><code><?php echo esc_html($exp_row['path']); ?></code></td>
                        <td><?php echo $exp_row['status'] ? (int) $exp_row['status'] : '&nbsp;'; ?></td>
                        <td><?php
                        // phpcs:disable WordPress.Security.EscapeOutput -- format string is static, parts are escaped.
                        if (!empty($exp_row['hit'])) {
                            echo sprintf($exp_yes, esc_attr($exp_row['severity']), esc_html__('exposed', 'nubivio-healthcare-security-hardening'));
                        } elseif ((int) $exp_row['status'] === 0) {
                            echo sprintf($exp_yes, 'low', esc_html__('not checked', 'nubivio-healthcare-security-hardening'));
                        } else {
                            echo sprintf($exp_yes, 'ok', esc_html__('not exposed', 'nubivio-healthcare-security-hardening'));
                        }
                        // phpcs:enable WordPress.Security.EscapeOutput
                        ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <?php if (!empty($exp['findings'])): ?>
                <ul class="ns-finding-list">
                    <?php foreach ($exp['findings'] as $exp_f): ?>
                        <li class="ns-finding ns-finding-<?php echo esc_attr($exp_f['severity']); ?>">
                            <span class="ns-chip ns-chip-<?php echo esc_attr($exp_f['severity']); ?>"><?php
                                echo esc_html(strtoupper($exp_f['severity']));
                            ?></span>
                            <?php echo esc_html($exp_f['message']); ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php
    // v2.6.0 security headers across the redirect chain.
    if (!empty($scan['frameworks']['redirects']['summary']['chains'])):
        $rdr      = $scan['frameworks']['redirects'];
        $rdr_ends = array(
            'too_many'    => __('stopped after 5 hops', 'nubivio-healthcare-security-hardening'),
            'loop'        => __('redirect loop', 'nubivio-healthcare-security-hardening'),
            'external'    => __('leaves your domain, not followed', 'nubivio-healthcare-security-hardening'),
            'unreachable' => __('could not be requested', 'nubivio-healthcare-security-hardening'),
            'error'       => __('request failed', 'nubivio-healthcare-security-hardening'),
        );
        ?>
        <div class="ns-card ns-redirects">
            <h2><?php esc_html_e('Redirect chain security headers', 'nubivio-healthcare-security-hardening'); ?></h2>
            <p class="ns-card-intro"><?php
                esc_html_e(
                    'Every step from http to your homepage, checked one by one. Each HTTPS step should send HSTS, and the first step should go to HTTPS on the same host.',
                    'nubivio-healthcare-security-hardening'
                );
            ?></p>
            <?php foreach ($rdr['summary']['chains'] as $rdr_chain): ?>
                <h3><code><?php echo esc_html($rdr_chain['start']); ?></code></h3>
                <table class="ns-evidence-table">
                    <thead><tr>
                        <th>#</th>
                        <th><?php esc_html_e('URL', 'nubivio-healthcare-security-hardening'); ?></th>
                        <th><?php esc_html_e('HTTP status', 'nubivio-healthcare-security-hardening'); ?></th>
                        <th><?php esc_html_e('Location', 'nubivio-healthcare-security-hardening'); ?></th>
                        <th>HSTS</th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($rdr_chain['hops'] as $rdr_i => $rdr_hop):
                        $rdr_https = strpos((string) $rdr_hop['url'], 'https://') === 0;
                        ?>
                        <tr>
                            <td><?php echo (int) $rdr_i + 1; ?></td>
                            <td><code><?php echo esc_html($rdr_hop['url']); ?></code></td>
                            <td><?php echo (int) $rdr_hop['status']; ?></td>
                            <td><?php if ($rdr_hop['location'] !== ''): ?><code><?php echo esc_html($rdr_hop['location']); ?></code><?php endif; ?></td>
                            <td><?php if (!$rdr_https): ?>
                                <?php esc_html_e('n/a (http)', 'nubivio-healthcare-security-hardening'); ?>
                            <?php elseif ($rdr_hop['hsts']): ?>
                                <span class="ns-chip ns-chip-ok"><?php esc_html_e('present', 'nubivio-healthcare-security-hardening'); ?></span>
                            <?php else: ?>
                                <span class="ns-chip ns-chip-medium"><?php esc_html_e('missing', 'nubivio-healthcare-security-hardening'); ?></span>
                            <?php endif; ?></td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if (isset($rdr_ends[$rdr_chain['end']])): ?>
                        <tr><td colspan="5"><?php echo esc_html($rdr_ends[$rdr_chain['end']]); ?></td></tr>
                    <?php endif; ?>
                    </tbody>
                </table>
            <?php endforeach; ?>
            <?php if (!empty($rdr['findings'])): ?>
                <ul class="ns-finding-list">
                    <?php foreach ($rdr['findings'] as $rdr_f): ?>
                        <li class="ns-finding ns-finding-<?php echo esc_attr($rdr_f['severity']); ?>">
                            <span class="ns-chip ns-chip-<?php echo esc_attr($rdr_f['severity']); ?>"><?php
                                echo esc_html(strtoupper($rdr_f['severity']));
                            ?></span>
                            <?php echo esc_html($rdr_f['message']); ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php else: ?>
                <p class="ns-ok-line"><?php esc_html_e('No issues detected.', 'nubivio-healthcare-security-hardening'); ?></p>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php
    // v2.6.0 domain registration via RDAP (opt-in).
    if (!empty($scan['frameworks']['rdap']['summary']['enabled'])):
        $rdap_r   = $scan['frameworks']['rdap'];
        $rdap_s   = $rdap_r['summary'];
        $rdap_fmt = get_option('date_format');
        ?>
        <div class="ns-card ns-rdap">
            <h2><?php esc_html_e('Domain registration (RDAP)', 'nubivio-healthcare-security-hardening'); ?></h2>
            <?php if (empty($rdap_s['available'])): ?>
                <p class="ns-card-intro"><?php
                    $rdap_row = Nubivio_HSH_Rdap::health_row($rdap_r);
                    echo esc_html($rdap_row ? $rdap_row['detail'] : '');
                ?></p>
            <?php else: ?>
                <table class="ns-evidence-table"><tbody>
                    <tr>
                        <td><?php esc_html_e('Domain', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td><code><?php echo esc_html($rdap_s['domain']); ?></code></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('Registrar', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td><?php echo esc_html($rdap_s['registrar'] !== '' ? $rdap_s['registrar'] : '-'); ?></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('Registered', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td><?php
                        if ($rdap_s['created']) {
                            echo esc_html(sprintf(
                                /* translators: 1: date, 2: age in days. */
                                __('%1$s (%2$d days ago)', 'nubivio-healthcare-security-hardening'),
                                date_i18n($rdap_fmt, (int) $rdap_s['created']),
                                (int) $rdap_s['age_days']
                            ));
                        } else {
                            echo '-';
                        }
                        ?></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('Expires', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td><?php
                        if ($rdap_s['expires']) {
                            echo esc_html(sprintf(
                                /* translators: 1: date, 2: days remaining. */
                                __('%1$s (in %2$d days)', 'nubivio-healthcare-security-hardening'),
                                date_i18n($rdap_fmt, (int) $rdap_s['expires']),
                                (int) $rdap_s['expires_days']
                            ));
                        } else {
                            esc_html_e('not published by the registry', 'nubivio-healthcare-security-hardening');
                        }
                        ?></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('Status', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td><?php echo esc_html($rdap_s['status'] ? implode(', ', $rdap_s['status']) : '-'); ?></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('DNSSEC delegation (registry)', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td><?php
                        if ($rdap_s['signed'] === null) {
                            echo '-';
                        } elseif ($rdap_s['signed']) {
                            esc_html_e('signed', 'nubivio-healthcare-security-hardening');
                        } else {
                            esc_html_e('not signed', 'nubivio-healthcare-security-hardening');
                        }
                        ?></td>
                    </tr>
                </tbody></table>
                <?php foreach ((array) $rdap_s['notes'] as $rdap_note): ?>
                    <p class="ns-desc"><?php echo esc_html($rdap_note); ?></p>
                <?php endforeach; ?>
                <?php if (!empty($rdap_r['findings'])): ?>
                    <ul class="ns-finding-list">
                        <?php foreach ($rdap_r['findings'] as $rdap_f): ?>
                            <li class="ns-finding ns-finding-<?php echo esc_attr($rdap_f['severity']); ?>">
                                <span class="ns-chip ns-chip-<?php echo esc_attr($rdap_f['severity']); ?>"><?php
                                    echo esc_html(strtoupper($rdap_f['severity']));
                                ?></span>
                                <?php echo esc_html($rdap_f['message']); ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php
    // v2.6.0 Certificate Transparency via crt.sh (opt-in).
    if (!empty($scan['frameworks']['ct']['summary']['enabled'])):
        $ct_r   = $scan['frameworks']['ct'];
        $ct_s   = $ct_r['summary'];
        $ct_fmt = get_option('date_format');
        ?>
        <div class="ns-card ns-ct">
            <h2><?php esc_html_e('Certificate Transparency (crt.sh)', 'nubivio-healthcare-security-hardening'); ?></h2>
            <?php if (empty($ct_s['available'])): ?>
                <p class="ns-card-intro"><?php
                    esc_html_e('CT source temporarily not available; the scan continued without it.', 'nubivio-healthcare-security-hardening');
                ?></p>
            <?php else: ?>
                <p class="ns-card-intro"><?php
                    echo esc_html(sprintf(
                        /* translators: 1: domain, 2: number of certificates, 3: number of subdomain names. */
                        __('%1$s: %2$d unexpired certificates in the CT logs, %3$d subdomain names seen.', 'nubivio-healthcare-security-hardening'),
                        $ct_s['domain'],
                        (int) $ct_s['entries'],
                        count((array) $ct_s['subdomains'])
                    ));
                    if (!empty($ct_s['baseline_at'])) {
                        echo ' ';
                        echo esc_html(sprintf(
                            /* translators: %s: date. */
                            __('Known issuers recorded on %s.', 'nubivio-healthcare-security-hardening'),
                            date_i18n($ct_fmt, (int) $ct_s['baseline_at'])
                        ));
                    }
                ?></p>
                <?php if (!empty($ct_s['issuers'])): ?>
                    <table class="ns-evidence-table">
                        <thead><tr>
                            <th><?php esc_html_e('Issuer', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Certificates', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Latest issued', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Known', 'nubivio-healthcare-security-hardening'); ?></th>
                        </tr></thead>
                        <tbody>
                        <?php foreach ($ct_s['issuers'] as $ct_name => $ct_info): ?>
                            <tr>
                                <td><?php echo esc_html($ct_name); ?></td>
                                <td><?php echo (int) $ct_info['count']; ?></td>
                                <td><?php echo $ct_info['latest'] ? esc_html(date_i18n($ct_fmt, (int) $ct_info['latest'])) : '-'; ?></td>
                                <td><?php
                                if (in_array($ct_name, (array) $ct_s['known'], true)) {
                                    echo '<span class="ns-chip ns-chip-ok">' . esc_html__('known', 'nubivio-healthcare-security-hardening') . '</span>';
                                } else {
                                    echo '<span class="ns-chip ns-chip-medium">' . esc_html__('new', 'nubivio-healthcare-security-hardening') . '</span>';
                                }
                                ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="<?php echo esc_attr(Nubivio_HSH_Ct::MARK_ACTION); ?>">
                        <?php wp_nonce_field(Nubivio_HSH_Ct::MARK_ACTION); ?>
                        <button type="submit" class="ns-btn ns-btn-ghost"><?php
                            esc_html_e('Mark current issuers as known', 'nubivio-healthcare-security-hardening');
                        ?></button>
                    </form>
                <?php endif; ?>
                <?php if (!empty($ct_s['truncated'])): ?>
                    <p class="ns-desc"><?php
                        esc_html_e('The CT answer was larger than the limit; only the first entries were read.', 'nubivio-healthcare-security-hardening');
                    ?></p>
                <?php endif; ?>
                <?php if (!empty($ct_r['findings'])): ?>
                    <ul class="ns-finding-list">
                        <?php foreach ($ct_r['findings'] as $ct_f): ?>
                            <li class="ns-finding ns-finding-<?php echo esc_attr($ct_f['severity']); ?>">
                                <span class="ns-chip ns-chip-<?php echo esc_attr($ct_f['severity']); ?>"><?php
                                    echo esc_html(strtoupper($ct_f['severity']));
                                ?></span>
                                <?php echo esc_html($ct_f['message']); ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php
    // WordPress core integrity (v2.3.0).
    if (!empty($scan['frameworks']['integrity'])):
        $integrity = $scan['frameworks']['integrity'];
        $isum      = isset($integrity['summary']) ? $integrity['summary'] : array();
        $i_mod     = isset($isum['modified']) ? (array) $isum['modified'] : array();
        $i_missing = isset($isum['missing']) ? (array) $isum['missing'] : array();
        $i_unread  = isset($isum['unreadable']) ? (array) $isum['unreadable'] : array();
        $i_bad     = array_merge($i_missing, $i_mod);
        ?>
        <div class="ns-card">
            <h2><?php esc_html_e('WordPress core integrity', 'nubivio-healthcare-security-hardening'); ?></h2>
            <p class="ns-card-intro"><?php echo esc_html(sprintf(
                /* translators: 1: WordPress version, 2: site locale. */
                __('Checked WordPress %1$s, locale %2$s.', 'nubivio-healthcare-security-hardening'),
                isset($isum['version']) ? $isum['version'] : '',
                isset($isum['locale']) ? $isum['locale'] : ''
            )); ?></p>

            <?php if (empty($isum['available'])): ?>
                <span class="ns-chip ns-chip-medium"><?php esc_html_e('Checksums unavailable', 'nubivio-healthcare-security-hardening'); ?></span>
            <?php elseif (empty($i_bad)): ?>
                <span class="ns-chip ns-chip-ok"><?php echo esc_html(sprintf(
                    /* translators: %d: number of core files verified. */
                    _n('All %d core file matches', 'All %d core files match', (int) $isum['checked'], 'nubivio-healthcare-security-hardening'),
                    (int) $isum['checked']
                )); ?></span>
            <?php else: ?>
                <span class="ns-chip ns-chip-high"><?php echo esc_html(sprintf(
                    /* translators: 1: number of modified files, 2: number of missing files. */
                    __('%1$d modified, %2$d missing', 'nubivio-healthcare-security-hardening'),
                    count($i_mod),
                    count($i_missing)
                )); ?></span>
                <details class="ns-details">
                    <summary><?php esc_html_e('Show affected files', 'nubivio-healthcare-security-hardening'); ?></summary>
                    <ul class="ns-file-list">
                        <?php foreach (array_slice($i_bad, 0, 20) as $path): ?>
                            <li><code><?php echo esc_html($path); ?></code></li>
                        <?php endforeach; ?>
                    </ul>
                </details>
            <?php endif; ?>

            <?php if (!empty($isum['truncated'])): ?>
                <p class="ns-desc"><?php esc_html_e('The check stopped early because the file cap was reached.', 'nubivio-healthcare-security-hardening'); ?></p>
            <?php endif; ?>
            <?php if (!empty($i_unread)): ?>
                <p class="ns-desc"><?php echo esc_html(sprintf(
                    /* translators: %d: number of unreadable core files. */
                    _n('%d core file could not be read and was skipped.', '%d core files could not be read and were skipped.', count($i_unread), 'nubivio-healthcare-security-hardening'),
                    count($i_unread)
                )); ?></p>
            <?php endif; ?>

            <p class="ns-desc"><?php
                esc_html_e(
                    'Uses the official WordPress.org checksums API (MD5). This detects unintended or malicious file changes; it is not a cryptographic tamper-proof check.',
                    'nubivio-healthcare-security-hardening'
                );
            ?></p>
            <p class="ns-desc"><?php esc_html_e('Recently updated? Checksums may lag by a few minutes after a core update.', 'nubivio-healthcare-security-hardening'); ?></p>
        </div>
    <?php endif; ?>

    <?php
    // Access and integrity (v2.3.0).
    if (!empty($scan['frameworks']['access'])):
        $access    = $scan['frameworks']['access'];
        $a_report  = isset($access['report']) ? $access['report'] : array();
        $a_find    = isset($access['findings']) ? $access['findings'] : array();
        ?>
        <div class="ns-card">
            <h2><?php esc_html_e('Access &amp; integrity', 'nubivio-healthcare-security-hardening'); ?></h2>

            <?php if (!empty($a_report['admins'])): ?>
                <h3><?php esc_html_e('Administrators', 'nubivio-healthcare-security-hardening'); ?></h3>
                <table class="ns-evidence-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Login', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Email', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Registered', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Last login', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('App passwords', 'nubivio-healthcare-security-hardening'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($a_report['admins'] as $admin): ?>
                            <tr>
                                <td>
                                    <?php echo esc_html($admin['login']); ?>
                                    <?php if ($admin['state'] === 'new'): ?>
                                        <span class="ns-chip ns-chip-high"><?php esc_html_e('new', 'nubivio-healthcare-security-hardening'); ?></span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo esc_html($admin['email']); ?></td>
                                <td><?php echo esc_html($admin['registered']); ?></td>
                                <td><?php echo esc_html($admin['last_login']); ?></td>
                                <td><?php echo (int) $admin['app_pw_count']; ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <?php if (!empty($a_report['app_passwords'])): ?>
                <h3><?php esc_html_e('Application passwords', 'nubivio-healthcare-security-hardening'); ?></h3>
                <table class="ns-evidence-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Administrator', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Name', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Created', 'nubivio-healthcare-security-hardening'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($a_report['app_passwords'] as $pw): ?>
                            <tr>
                                <td><?php echo esc_html($pw['login']); ?></td>
                                <td>
                                    <?php echo esc_html($pw['name']); ?>
                                    <?php if (!empty($pw['new'])): ?>
                                        <span class="ns-chip ns-chip-medium"><?php esc_html_e('new', 'nubivio-healthcare-security-hardening'); ?></span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo esc_html($pw['created']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <?php if (!empty($a_report['mu_plugins'])): ?>
                <h3><?php esc_html_e('Must-use plugins', 'nubivio-healthcare-security-hardening'); ?></h3>
                <ul class="ns-file-list">
                    <?php foreach ($a_report['mu_plugins'] as $mu): ?>
                        <li>
                            <code><?php echo esc_html($mu['file']); ?></code>
                            <?php if (empty($mu['known'])): ?>
                                <span class="ns-chip ns-chip-medium"><?php esc_html_e('unexpected', 'nubivio-healthcare-security-hardening'); ?></span>
                            <?php else: ?>
                                <span class="ns-chip ns-chip-ok"><?php esc_html_e('known host plugin', 'nubivio-healthcare-security-hardening'); ?></span>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>

            <h3><?php esc_html_e('Findings', 'nubivio-healthcare-security-hardening'); ?></h3>
            <?php if (empty($a_find)): ?>
                <p class="ns-ok-line"><?php esc_html_e('No issues detected.', 'nubivio-healthcare-security-hardening'); ?></p>
            <?php else: ?>
                <ul class="ns-finding-list">
                    <?php foreach ($a_find as $f):
                        $sev = isset($f['severity']) ? $f['severity'] : 'low';
                        ?>
                        <li class="ns-finding ns-finding-<?php echo esc_attr($sev); ?>">
                            <span class="ns-chip ns-chip-<?php echo esc_attr($sev === 'warn' ? 'medium' : $sev); ?>"><?php echo esc_html(strtoupper($sev)); ?></span>
                            <?php echo esc_html(isset($f['message']) ? $f['message'] : ''); ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>

            <?php if (!empty($a_report['needs_approval'])): ?>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="ns-approve-form">
                    <input type="hidden" name="action" value="<?php echo esc_attr(Nubivio_HSH::APPROVE_ACTION); ?>">
                    <?php wp_nonce_field(Nubivio_HSH::APPROVE_ACTION); ?>
                    <button type="submit" class="ns-btn ns-btn-ghost"><?php esc_html_e('Approve current admins', 'nubivio-healthcare-security-hardening'); ?></button>
                    <span class="ns-by"><?php esc_html_e('Records the accounts above as the approved baseline for future scans.', 'nubivio-healthcare-security-hardening'); ?></span>
                </form>
            <?php endif; ?>

            <p class="ns-desc"><?php
                esc_html_e(
                    'These checks are read-only snapshots taken during the scan. Nothing here changes users, roles or files.',
                    'nubivio-healthcare-security-hardening'
                );
            ?></p>
        </div>
    <?php endif; ?>

    <?php
    // v2.4.0 HSTS preload readiness.
    $hsts = isset($scan['frameworks']['hsts']['summary']) ? $scan['frameworks']['hsts']['summary'] : array();
    if ($hsts):
        $hsts_present = __('present', 'nubivio-healthcare-security-hardening');
        $hsts_missing = __('missing', 'nubivio-healthcare-security-hardening');
        $hsts_rows    = array(
            array(
                'label' => __('HSTS header present', 'nubivio-healthcare-security-hardening'),
                'ok'    => !empty($hsts['header_present']),
                'value' => !empty($hsts['header_present']) ? $hsts_present : $hsts_missing,
            ),
            array(
                'label' => __('max-age at least one year', 'nubivio-healthcare-security-hardening'),
                'ok'    => !empty($hsts['max_age_ok']),
                'value' => (string) (int) $hsts['max_age'],
            ),
            array(
                'label' => __('includeSubDomains', 'nubivio-healthcare-security-hardening'),
                'ok'    => !empty($hsts['include_subdomains']),
                'value' => !empty($hsts['include_subdomains']) ? $hsts_present : $hsts_missing,
            ),
            array(
                'label' => __('preload directive', 'nubivio-healthcare-security-hardening'),
                'ok'    => !empty($hsts['preload']),
                'value' => !empty($hsts['preload']) ? $hsts_present : $hsts_missing,
            ),
        );
        ?>
        <div class="ns-card">
            <h2><?php esc_html_e('HSTS preload readiness', 'nubivio-healthcare-security-hardening'); ?></h2>
            <table class="ns-evidence-table">
                <tbody>
                    <?php foreach ($hsts_rows as $row): ?>
                        <tr>
                            <td><?php echo esc_html($row['label']); ?></td>
                            <td>
                                <span class="ns-chip <?php echo $row['ok'] ? 'ns-chip-ok' : 'ns-chip-high'; ?>"><?php
                                    echo $row['ok']
                                        ? esc_html__('yes', 'nubivio-healthcare-security-hardening')
                                        : esc_html__('no', 'nubivio-healthcare-security-hardening');
                                ?></span>
                            </td>
                            <td><?php echo esc_html($row['value']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <p class="ns-v240-warning"><?php
                esc_html_e(
                    'Preload is nearly irreversible. Removal takes months and remains cached in older browsers. Every subdomain must serve valid HTTPS for as long as your entry stays on the list.',
                    'nubivio-healthcare-security-hardening'
                );
            ?></p>
            <?php if (!empty($hsts['ready_for_preload']) && !empty($hsts['host'])): ?>
                <p>
                    <a class="ns-btn ns-btn-ghost" target="_blank" rel="noopener"
                        href="<?php echo esc_url('https://hstspreload.org/?domain=' . rawurlencode($hsts['host'])); ?>"><?php
                        esc_html_e('Submit at hstspreload.org →', 'nubivio-healthcare-security-hardening');
                    ?></a>
                </p>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php
    // v2.4.0 DNS health.
    $dns = isset($scan['frameworks']['dns']['summary']) ? $scan['frameworks']['dns']['summary'] : array();
    if ($dns):
        $dns_action = wp_nonce_url(
            admin_url('admin-post.php?action=' . Nubivio_HSH::DNS_REFRESH_ACTION),
            Nubivio_HSH::DNS_REFRESH_ACTION
        );
        $dns_present = '<span class="ns-chip ns-chip-ok">' . esc_html__('present', 'nubivio-healthcare-security-hardening') . '</span>';
        $dns_missing = '<span class="ns-chip ns-chip-medium">' . esc_html__('missing', 'nubivio-healthcare-security-hardening') . '</span>';
        $dns_copy    = esc_html__('Copy', 'nubivio-healthcare-security-hardening');
        ?>
        <div class="ns-card">
            <h2><?php esc_html_e('DNS health', 'nubivio-healthcare-security-hardening'); ?></h2>
            <p>
                <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($dns_action); ?>"><?php
                    esc_html_e('Force-refresh DNS data', 'nubivio-healthcare-security-hardening');
                ?></a>
            </p>
            <table class="ns-evidence-table"><tbody>
                <tr>
                    <td>SPF</td>
                    <td><?php
                    // phpcs:disable WordPress.Security.EscapeOutput -- every dynamic part below is escaped.
                    if (!empty($dns['spf']['records'])) {
                        echo $dns_present . '<br><code>' . esc_html(implode("\n", (array) $dns['spf']['records'])) . '</code>';
                    } else {
                        echo $dns_missing . '<br><code>v=spf1 -all</code> '
                            . '<button type="button" class="ns-copy" data-copy="v=spf1 -all">' . $dns_copy . '</button>';
                    }
                    // phpcs:enable WordPress.Security.EscapeOutput
                    ?></td>
                </tr>
                <tr>
                    <td>DMARC</td>
                    <td><?php
                    // phpcs:disable WordPress.Security.EscapeOutput -- every dynamic part below is escaped.
                    if (!empty($dns['dmarc']['records'])) {
                        echo $dns_present . '<br><code>' . esc_html(implode("\n", (array) $dns['dmarc']['records'])) . '</code>';
                    } else {
                        $dmarc_template = '_dmarc.' . $host . '. IN TXT "v=DMARC1; p=none; rua=mailto:security@' . $host
                            . '; ruf=mailto:security@' . $host . '; fo=1"';
                        echo $dns_missing . '<br><code>' . esc_html($dmarc_template) . '</code> '
                            . '<button type="button" class="ns-copy" data-copy="' . esc_attr($dmarc_template) . '">' . $dns_copy . '</button>';
                    }
                    // phpcs:enable WordPress.Security.EscapeOutput
                    ?></td>
                </tr>
                <tr>
                    <td>DKIM</td>
                    <td><?php
                    echo !empty($dns['dkim']['matched'])
                        ? esc_html(implode(', ', (array) $dns['dkim']['matched']))
                        : esc_html__('No common selector matched.', 'nubivio-healthcare-security-hardening');
                    ?></td>
                </tr>
                <tr>
                    <td>CAA</td>
                    <td><?php
                    // phpcs:disable WordPress.Security.EscapeOutput -- every dynamic part below is escaped.
                    if (!empty($dns['caa']['records'])) {
                        echo $dns_present;
                    } else {
                        echo '<code>' . esc_html($host . '. IN CAA 0 issue "letsencrypt.org"') . '</code> '
                            . '<button type="button" class="ns-copy" data-copy="'
                            . esc_attr($host . '. IN CAA 0 issue &quot;letsencrypt.org&quot;') . '">' . $dns_copy . '</button>';
                    }
                    // phpcs:enable WordPress.Security.EscapeOutput
                    ?></td>
                </tr>
                <tr>
                    <td>MTA-STS</td>
                    <td><?php
                    // phpcs:disable WordPress.Security.EscapeOutput -- every dynamic part below is escaped.
                    echo !empty($dns['mta_sts']['records']) || !empty($dns['mta_sts']['mx'])
                        ? esc_html(implode(', ', (array) $dns['mta_sts']['mx']))
                        : '<code>version: STSv1; mode: enforce; mx: mail.' . esc_html($host) . '; max_age: 604800</code>';
                    // phpcs:enable WordPress.Security.EscapeOutput
                    ?></td>
                </tr>
                <tr>
                    <td>DNSSEC</td>
                    <td><?php
                    echo !empty($dns['dnssec']['indicator'])
                        ? esc_html__('Native indicator found.', 'nubivio-healthcare-security-hardening')
                        : esc_html__('No native indicator found.', 'nubivio-healthcare-security-hardening');
                    if (array_key_exists('doh', (array) $dns['dnssec']) && $dns['dnssec']['doh'] !== null) {
                        echo ' ';
                        echo !empty($dns['dnssec']['doh'])
                            ? esc_html__('Cloudflare DoH validated.', 'nubivio-healthcare-security-hardening')
                            : esc_html__('Cloudflare DoH did not validate.', 'nubivio-healthcare-security-hardening');
                    }
                    ?></td>
                </tr>
                <tr>
                    <td>IPv6 / AAAA</td>
                    <td><?php
                    echo !empty($dns['aaaa']['records'])
                        ? esc_html__('present', 'nubivio-healthcare-security-hardening')
                        : esc_html__('No AAAA record.', 'nubivio-healthcare-security-hardening');
                    ?></td>
                </tr>
            </tbody></table>
        </div>
    <?php endif; ?>

    <?php
    // v2.4.0 CSP report-only card.
    $csp = isset($scan['frameworks']['csp']['summary']) ? $scan['frameworks']['csp']['summary'] : array();
    if ($csp):
        $inventory_action = wp_nonce_url(
            admin_url('admin-post.php?action=' . Nubivio_HSH::CSP_INVENTORY_ACTION),
            Nubivio_HSH::CSP_INVENTORY_ACTION
        );
        $toggle_action    = wp_nonce_url(
            admin_url('admin-post.php?action=' . Nubivio_HSH::CSP_TOGGLE_ACTION),
            Nubivio_HSH::CSP_TOGGLE_ACTION
        );
        $hosts_count      = 0;
        foreach ((array) $csp['seen_hosts'] as $list) {
            $hosts_count += count((array) $list);
        }
        $csp_inventory_at = !empty($csp['inventory_at'])
            ? date_i18n(get_option('date_format'), (int) $csp['inventory_at'])
            : __('never', 'nubivio-healthcare-security-hardening');
        $csp_inventory    = sprintf(
            /* translators: 1: number of hosts, 2: number of inline scripts, 3: date of the last inventory scan. */
            __('Inventory: %1$d hosts detected and %2$d inline scripts counted. Last inventory scan: %3$s.', 'nubivio-healthcare-security-hardening'),
            $hosts_count,
            isset($csp['inline_scripts']) ? (int) $csp['inline_scripts'] : 0,
            $csp_inventory_at
        );
        $date_format      = get_option('date_format');
        ?>
        <div class="ns-card">
            <h2><?php esc_html_e('CSP report-only violations', 'nubivio-healthcare-security-hardening'); ?></h2>
            <p>
                <span class="ns-chip <?php echo !empty($csp['enabled']) ? 'ns-chip-ok' : 'ns-chip-low'; ?>"><?php
                    echo !empty($csp['enabled'])
                        ? esc_html__('enabled', 'nubivio-healthcare-security-hardening')
                        : esc_html__('disabled', 'nubivio-healthcare-security-hardening');
                ?></span>
            </p>
            <p class="ns-card-intro"><?php echo esc_html($csp_inventory); ?></p>
            <p>
                <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($inventory_action); ?>"><?php
                    esc_html_e('Refresh inventory now', 'nubivio-healthcare-security-hardening');
                ?></a>
                <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($toggle_action); ?>"><?php
                    echo !empty($csp['enabled'])
                        ? esc_html__('Disable report-only', 'nubivio-healthcare-security-hardening')
                        : esc_html__('Enable report-only', 'nubivio-healthcare-security-hardening');
                ?></a>
            </p>
            <p class="ns-desc"><?php
                esc_html_e(
                    'This policy reports without blocking. When you see no new relevant violations for 2 weeks, you are ready to enforce (coming in v2.5.0).',
                    'nubivio-healthcare-security-hardening'
                );
            ?></p>
            <?php
            $violations = (array) $csp['violations'];
            usort($violations, function ($a, $b) {
                return (int) $b['count'] <=> (int) $a['count'];
            });
            if ($violations): ?>
                <table class="ns-evidence-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Directive', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Blocked URI', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('First / last seen', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Count', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Action', 'nubivio-healthcare-security-hardening'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($violations as $v): ?>
                            <tr>
                                <td><?php echo esc_html($v['directive']); ?></td>
                                <td><code><?php echo esc_html($v['blocked_uri']); ?></code></td>
                                <td><?php
                                    echo esc_html(
                                        date_i18n($date_format, (int) $v['first_seen']) . ' / ' . date_i18n($date_format, (int) $v['last_seen'])
                                    );
                                ?></td>
                                <td><?php echo (int) $v['count']; ?></td>
                                <td>
                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                        <input type="hidden" name="action" value="<?php echo esc_attr(Nubivio_HSH::CSP_ALLOWLIST_ACTION); ?>">
                                        <input type="hidden" name="directive" value="<?php echo esc_attr($v['directive']); ?>">
                                        <input type="hidden" name="blocked_uri" value="<?php echo esc_attr($v['blocked_uri']); ?>">
                                        <?php wp_nonce_field(Nubivio_HSH::CSP_ALLOWLIST_ACTION); ?>
                                        <button type="submit" class="ns-btn ns-btn-ghost"><?php
                                            esc_html_e('Add to allowlist', 'nubivio-healthcare-security-hardening');
                                        ?></button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <p class="ns-ok-line"><?php esc_html_e('No violations received yet.', 'nubivio-healthcare-security-hardening'); ?></p>
            <?php endif; ?>
            <h3><?php esc_html_e('SRI audit', 'nubivio-healthcare-security-hardening'); ?></h3>
            <p><?php
                esc_html_e('Dynamic scripts (SRI not applicable)', 'nubivio-healthcare-security-hardening');
                echo ': ' . esc_html(implode(', ', (array) $csp['sri']['dynamic']));
            ?></p>
            <p><?php
                esc_html_e('Candidates for SRI', 'nubivio-healthcare-security-hardening');
                echo ': ' . esc_html(implode(', ', (array) $csp['sri']['candidates']));
            ?></p>
            <?php
            $csp_grade      = isset($csp['grade']) ? $csp['grade'] : array('grade' => 'F', 'score' => 0, 'issues' => array());
            $enforce_action = wp_nonce_url(
                admin_url('admin-post.php?action=' . Nubivio_HSH::CSP_ENFORCE_TOGGLE_ACTION),
                Nubivio_HSH::CSP_ENFORCE_TOGGLE_ACTION
            );
            $enforce_on = false;
            $preflight  = array('ok' => false, 'reason' => '');
            if (class_exists('Nubivio_HSH_Csp')) {
                $csp_module = new Nubivio_HSH_Csp(Nubivio_HSH::instance());
                $preflight  = $csp_module->can_enforce();
                $opts       = Nubivio_HSH::instance()->get_options();
                $enforce_on = !empty($opts['csp_enforce_enabled']);
            }
            $grade_class = 'ns-chip-ok';
            if (in_array($csp_grade['grade'], array('C'), true)) {
                $grade_class = 'ns-chip-medium';
            } elseif (in_array($csp_grade['grade'], array('D', 'F'), true)) {
                $grade_class = 'ns-chip-high';
            }
            ?>
            <h3><?php esc_html_e('CSP effectiveness', 'nubivio-healthcare-security-hardening'); ?></h3>
            <p>
                <span class="ns-chip <?php echo esc_attr($grade_class); ?>">
                    <?php echo esc_html(sprintf('%s (%d/100)', $csp_grade['grade'], (int) $csp_grade['score'])); ?>
                </span>
            </p>
            <?php if (!empty($csp_grade['issues'])): ?>
                <ul class="ns-desc">
                    <?php foreach ((array) $csp_grade['issues'] as $issue): ?>
                        <li><?php echo esc_html((string) $issue); ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php else: ?>
                <p class="ns-ok-line">
                    <?php esc_html_e('No effectiveness issues detected in the generated policy.', 'nubivio-healthcare-security-hardening'); ?>
                </p>
            <?php endif; ?>
            <h3><?php esc_html_e('Enforce CSP', 'nubivio-healthcare-security-hardening'); ?></h3>
            <p>
                <span class="ns-chip <?php echo $enforce_on ? 'ns-chip-ok' : 'ns-chip-low'; ?>">
                    <?php echo $enforce_on
                        ? esc_html__('enforcing', 'nubivio-healthcare-security-hardening')
                        : esc_html__('report-only', 'nubivio-healthcare-security-hardening'); ?>
                </span>
            </p>
            <p>
                <a class="ns-btn ns-btn-ghost <?php echo (!$enforce_on && empty($preflight['ok'])) ? 'disabled' : ''; ?>"
                   href="<?php echo esc_url($enforce_action); ?>">
                    <?php echo $enforce_on
                        ? esc_html__('Switch back to report-only', 'nubivio-healthcare-security-hardening')
                        : esc_html__('Enforce Content-Security-Policy', 'nubivio-healthcare-security-hardening'); ?>
                </a>
            </p>
            <?php if (!$enforce_on && !empty($preflight['reason'])): ?>
                <p class="ns-desc"><?php echo esc_html((string) $preflight['reason']); ?></p>
            <?php elseif ($enforce_on): ?>
                <p class="ns-desc">
                    <?php
                    esc_html_e(
                        'The plugin now sends Content-Security-Policy. If a fatal error occurs, the fail-safe reverts to report-only automatically for the next request.',
                        'nubivio-healthcare-security-hardening'
                    );
                    ?>
                </p>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php
    // v2.4.0 TLS overview.
    $tls = isset($scan['frameworks']['tls']['summary']) ? $scan['frameworks']['tls']['summary'] : array();
    if ($tls):
        $days = isset($tls['days_remaining']) ? $tls['days_remaining'] : null;
        if ($days === null) {
            $pill = 'ns-chip-low';
        } elseif ($days < 14) {
            $pill = 'ns-chip-high';
        } elseif ($days < 30) {
            $pill = 'ns-chip-medium';
        } else {
            $pill = 'ns-chip-ok';
        }
        $valid_to = !empty($tls['valid_to']) ? date_i18n(get_option('date_format'), (int) $tls['valid_to']) : '';
        if ($days === null) {
            $days_text = __('unknown', 'nubivio-healthcare-security-hardening');
        } else {
            $days_text = sprintf(
                /* translators: %d: number of days until the certificate expires. */
                _n('%d day', '%d days', (int) $days, 'nubivio-healthcare-security-hardening'),
                (int) $days
            );
        }
        ?>
        <div class="ns-card">
            <h2><?php esc_html_e('TLS overview', 'nubivio-healthcare-security-hardening'); ?></h2>
            <table class="ns-evidence-table">
                <tbody>
                    <tr>
                        <td><?php esc_html_e('Certificate subject', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td><?php echo esc_html($tls['subject_cn']); ?></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('Issuer', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td><?php echo esc_html(trim($tls['issuer_cn'] . ' ' . $tls['issuer_o'])); ?></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('Valid until', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td>
                            <?php echo esc_html($valid_to); ?>
                            <span class="ns-chip <?php echo esc_attr($pill); ?>"><?php echo esc_html($days_text); ?></span>
                        </td>
                    </tr>
                    <tr>
                        <td>SAN</td>
                        <td><?php echo esc_html(implode(', ', (array) $tls['sans'])); ?></td>
                    </tr>
                    <tr>
                        <td><?php esc_html_e('Signature algorithm', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td><?php echo esc_html($tls['signature']); ?></td>
                    </tr>
                    <?php if (!empty($tls['dane'])): ?>
                        <tr>
                            <td>DANE/TLSA</td>
                            <td>
                                <a href="https://ssl-tools.net/dane" target="_blank" rel="noopener"><?php
                                    esc_html_e('DANE/TLSA record present. Validate externally.', 'nubivio-healthcare-security-hardening');
                                ?></a>
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
            <p class="ns-desc">
                <?php esc_html_e('For a full TLS cipher analysis use SSL Labs.', 'nubivio-healthcare-security-hardening'); ?>
                <a href="https://www.ssllabs.com/ssltest/" target="_blank" rel="noopener">SSL Labs</a>.
            </p>
        </div>
    <?php endif; ?>

    <?php // Health checklist.
    if (!empty($scan['frameworks']['health']['checks'])): ?>
        <div class="ns-card">
            <h2><?php esc_html_e('Site health', 'nubivio-healthcare-security-hardening'); ?></h2>
            <ul class="ns-health-list">
                <?php foreach ($scan['frameworks']['health']['checks'] as $c):
                    $st = isset($c['status']) ? $c['status'] : 'warn';
                    ?>
                    <li class="ns-health-row ns-health-<?php echo esc_attr($st); ?>">
                        <span class="ns-dot ns-dot-<?php echo esc_attr($st); ?>" aria-hidden="true"></span>
                        <span class="ns-health-label"><?php echo esc_html(isset($c['label']) ? $c['label'] : ''); ?></span>
                        <span class="ns-health-detail"><?php echo esc_html(isset($c['detail']) ? $c['detail'] : ''); ?></span>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <?php
    // Phase 3: header evidence.
    $scanner = $core->scanner();
    $probe   = $scanner ? $scanner->probe_headers() : array('ok' => false, 'present' => array());
    ?>
    <div class="ns-card ns-evidence">
        <h2><?php esc_html_e('Security headers as compliance evidence', 'nubivio-healthcare-security-hardening'); ?></h2>
        <?php if (empty($probe['ok'])): ?>
            <p class="ns-card-intro"><?php
                esc_html_e(
                    'Live verification was unavailable, so the table shows configured headers. A hardened host may block self-requests.',
                    'nubivio-healthcare-security-hardening'
                );
            ?></p>
        <?php endif; ?>
        <table class="ns-evidence-table">
            <thead>
                <tr>
                    <th><?php esc_html_e('Header', 'nubivio-healthcare-security-hardening'); ?></th>
                    <th><?php esc_html_e('Live status', 'nubivio-healthcare-security-hardening'); ?></th>
                    <th><?php esc_html_e('Supports', 'nubivio-healthcare-security-hardening'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($core->preview_headers() as $name => $val):
                    $clause = isset($header_clauses[$name]) ? $header_clauses[$name] : '';
                    if (!empty($probe['ok'])) {
                        $sent = isset($probe['present'][strtolower($name)]);
                        $badge = $sent
                            ? '<span class="ns-chip ns-chip-ok">' . esc_html__('sent', 'nubivio-healthcare-security-hardening') . '</span>'
                            : '<span class="ns-chip ns-chip-high">' . esc_html__('missing', 'nubivio-healthcare-security-hardening') . '</span>';
                    } else {
                        $badge = '<span class="ns-chip ns-chip-low">' . esc_html__('configured', 'nubivio-healthcare-security-hardening') . '</span>';
                    }
                    ?>
                    <tr>
                        <td><code><?php echo esc_html($name); ?></code></td>
                        <td><?php echo wp_kses_post($badge); ?></td>
                        <td><?php echo esc_html($clause); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <?php
    // Phase 3: security.txt evidence.
    $status = $core->security_txt_status();
    $o_sec  = $core->get_options();
    $can    = $core->canonical_url();
    $home_host = strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
    $can_host  = strtolower((string) wp_parse_url($can, PHP_URL_HOST));
    $can_ok = ($can_host !== '' && $can_host === $home_host);
    $has_contact = trim((string) $o_sec['sectxt_contacts']) !== '';
    $has_pgp = $core->build_pgp_key() !== '' || trim((string) $o_sec['sectxt_encryption']) !== '';
    ?>
    <div class="ns-card ns-evidence">
        <h2><?php esc_html_e('security.txt as compliance evidence', 'nubivio-healthcare-security-hardening'); ?></h2>
        <p class="ns-card-intro"><?php esc_html_e('Maps to CRA Art. 14 (coordinated vulnerability disclosure).', 'nubivio-healthcare-security-hardening'); ?></p>
        <table class="ns-evidence-table">
            <tbody>
                <tr>
                    <td><?php esc_html_e('Expires validity', 'nubivio-healthcare-security-hardening'); ?></td>
                    <td><?php
                        if ($status['mode'] === 'dynamic') {
                            echo '<span class="ns-chip ns-chip-ok">' . esc_html__('dynamic', 'nubivio-healthcare-security-hardening') . '</span>';
                        } elseif ($status['days'] !== null && $status['days'] > 0) {
                            echo '<span class="ns-chip ns-chip-ok">' . esc_html(sprintf(
                                /* translators: %d: days left. */
                                _n('%d day left', '%d days left', (int) $status['days'], 'nubivio-healthcare-security-hardening'),
                                (int) $status['days']
                            )) . '</span>';
                        } else {
                            echo '<span class="ns-chip ns-chip-high">' . esc_html__('not valid', 'nubivio-healthcare-security-hardening') . '</span>';
                        }
                    ?></td>
                </tr>
                <tr>
                    <td><?php esc_html_e('Canonical correctness', 'nubivio-healthcare-security-hardening'); ?></td>
                    <td><?php echo $can_ok
                        ? '<span class="ns-chip ns-chip-ok">' . esc_html__('correct', 'nubivio-healthcare-security-hardening') . '</span>'
                        : '<span class="ns-chip ns-chip-medium">' . esc_html__('check', 'nubivio-healthcare-security-hardening') . '</span>'; // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
                </tr>
                <tr>
                    <td><?php esc_html_e('Contact present', 'nubivio-healthcare-security-hardening'); ?></td>
                    <td><?php echo $has_contact
                        ? '<span class="ns-chip ns-chip-ok">' . esc_html__('yes', 'nubivio-healthcare-security-hardening') . '</span>'
                        : '<span class="ns-chip ns-chip-high">' . esc_html__('missing', 'nubivio-healthcare-security-hardening') . '</span>'; // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
                </tr>
                <tr>
                    <td><?php esc_html_e('PGP / Encryption available', 'nubivio-healthcare-security-hardening'); ?></td>
                    <td><?php echo $has_pgp
                        ? '<span class="ns-chip ns-chip-ok">' . esc_html__('yes', 'nubivio-healthcare-security-hardening') . '</span>'
                        : '<span class="ns-chip ns-chip-low">' . esc_html__('optional', 'nubivio-healthcare-security-hardening') . '</span>'; // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
                </tr>
                <?php
                $docs_sum = isset($scan['frameworks']['docs']['summary']) ? (array) $scan['frameworks']['docs']['summary'] : array();
                $exp_in   = isset($docs_sum['expires_in']) ? (int) $docs_sum['expires_in'] : null;
                $drift    = !empty($docs_sum['drift']);
                ?>
                <?php if ($exp_in !== null): ?>
                    <tr>
                        <td><?php esc_html_e('Expires countdown', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td>
                            <?php
                            $days_left = (int) floor($exp_in / DAY_IN_SECONDS);
                            $exp_class = $exp_in < 30 * DAY_IN_SECONDS ? 'ns-chip-medium' : 'ns-chip-ok';
                            $exp_text  = $days_left < 0
                                ? __('expired', 'nubivio-healthcare-security-hardening')
                                : sprintf(
                                    /* translators: %d: days remaining until security.txt expires. */
                                    _n('%d day left', '%d days left', $days_left, 'nubivio-healthcare-security-hardening'),
                                    $days_left
                                );
                            ?>
                            <span class="ns-chip <?php echo esc_attr($exp_class); ?>"><?php echo esc_html($exp_text); ?></span>
                        </td>
                    </tr>
                <?php endif; ?>
                <?php if (isset($scan['frameworks']['docs'])): ?>
                    <tr>
                        <td><?php esc_html_e('Published copy drift', 'nubivio-healthcare-security-hardening'); ?></td>
                        <td><?php echo $drift
                            ? '<span class="ns-chip ns-chip-low">' . esc_html__('drift detected', 'nubivio-healthcare-security-hardening') . '</span>'
                            : '<span class="ns-chip ns-chip-ok">' . esc_html__('in sync', 'nubivio-healthcare-security-hardening') . '</span>'; // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
        <p><a href="<?php echo esc_url($intnl); ?>" target="_blank" rel="noopener">internet.nl/site/<?php echo esc_html($host); ?></a></p>
    </div>

    <?php
    // Cookies and trackers panel.
    $ck = isset($scan['frameworks']['cookies']) ? $scan['frameworks']['cookies'] : null;
    if ($ck):
        $ck_sum      = isset($ck['summary']) ? (array) $ck['summary'] : array();
        $ck_cookies  = isset($ck_sum['cookies']) ? (array) $ck_sum['cookies'] : array();
        $ck_trackers = isset($ck_sum['trackers']) ? (array) $ck_sum['trackers'] : array();
        $ck_consent  = isset($ck_sum['consent_plugin']) ? (string) $ck_sum['consent_plugin'] : '';
        ?>
        <div class="ns-card ns-cookies">
            <h2><?php esc_html_e('Cookies and trackers (pre-consent)', 'nubivio-healthcare-security-hardening'); ?></h2>
            <p class="ns-card-intro"><?php
                esc_html_e(
                    'This analysis reads what the server sends to an anonymous visitor. Cookies set later by JavaScript are not visible here.',
                    'nubivio-healthcare-security-hardening'
                );
            ?></p>
            <?php if (empty($ck_cookies)): ?>
                <p class="ns-ok-line"><?php esc_html_e('No Set-Cookie headers on the home response.', 'nubivio-healthcare-security-hardening'); ?></p>
            <?php else: ?>
                <table class="ns-evidence-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Cookie', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th>Secure</th>
                            <th>HttpOnly</th>
                            <th>SameSite</th>
                            <th><?php esc_html_e('Domain', 'nubivio-healthcare-security-hardening'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($ck_cookies as $c):
                        $sec_class  = !empty($c['secure']) ? 'ns-chip-ok' : 'ns-chip-high';
                        $sec_text   = !empty($c['secure']) ? __('yes', 'nubivio-healthcare-security-hardening') : __('no', 'nubivio-healthcare-security-hardening');
                        $ho_class   = !empty($c['httponly']) ? 'ns-chip-ok' : 'ns-chip-medium';
                        $ho_text    = !empty($c['httponly']) ? __('yes', 'nubivio-healthcare-security-hardening') : __('no', 'nubivio-healthcare-security-hardening');
                        $ss_val     = isset($c['samesite']) ? (string) $c['samesite'] : '';
                        $ss_class   = $ss_val === '' ? 'ns-chip-medium' : 'ns-chip-ok';
                        $ss_text    = $ss_val === '' ? __('unset', 'nubivio-healthcare-security-hardening') : $ss_val;
                        ?>
                        <tr>
                            <td><code><?php echo esc_html($c['name']); ?></code></td>
                            <td><span class="ns-chip <?php echo esc_attr($sec_class); ?>"><?php echo esc_html($sec_text); ?></span></td>
                            <td><span class="ns-chip <?php echo esc_attr($ho_class); ?>"><?php echo esc_html($ho_text); ?></span></td>
                            <td><span class="ns-chip <?php echo esc_attr($ss_class); ?>"><?php echo esc_html($ss_text); ?></span></td>
                            <td><?php echo esc_html(isset($c['domain']) ? (string) $c['domain'] : ''); ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <h3><?php esc_html_e('Trackers detected before consent', 'nubivio-healthcare-security-hardening'); ?></h3>
            <?php if (empty($ck_trackers)): ?>
                <p class="ns-ok-line"><?php esc_html_e('No known tracker hosts detected in the home response.', 'nubivio-healthcare-security-hardening'); ?></p>
            <?php else: ?>
                <ul class="ns-finding-list">
                <?php foreach ($ck_trackers as $t): ?>
                    <li><code><?php echo esc_html($t); ?></code></li>
                <?php endforeach; ?>
                </ul>
            <?php endif; ?>

            <h3><?php esc_html_e('Consent-management plugin', 'nubivio-healthcare-security-hardening'); ?></h3>
            <?php if ($ck_consent === ''): ?>
                <span class="ns-chip ns-chip-medium"><?php esc_html_e('none detected', 'nubivio-healthcare-security-hardening'); ?></span>
            <?php else: ?>
                <span class="ns-chip ns-chip-ok"><?php echo esc_html($ck_consent); ?></span>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php
    // Compliance mapping panel (NEN 7510 and ISO 27001).
    $cm = isset($scan['frameworks']['compliance_map']) ? $scan['frameworks']['compliance_map'] : null;
    if ($cm && !empty($cm['summary'])):
        $cm_sum = (array) $cm['summary'];
        $cm_norm_labels = array(
            'nen7510'  => __('NEN 7510-2:2024', 'nubivio-healthcare-security-hardening'),
            'iso27001' => __('ISO 27001:2022 Annex A', 'nubivio-healthcare-security-hardening'),
        );
        ?>
        <div class="ns-card ns-compliance-map">
            <h2><?php esc_html_e('Standards mapping', 'nubivio-healthcare-security-hardening'); ?></h2>
            <p class="ns-card-intro"><?php echo esc_html(Nubivio_HSH_Compliance_Map::disclaimer_text()); ?></p>
            <?php foreach ($cm_norm_labels as $norm_key => $norm_label):
                if (empty($cm_sum[$norm_key])) {
                    continue;
                }
                $ns          = (array) $cm_sum[$norm_key];
                $assessable  = isset($ns['assessable']) ? (array) $ns['assessable'] : array();
                $covered     = isset($ns['covered']) ? (array) $ns['covered'] : array();
                $total       = isset($ns['total_count']) ? (int) $ns['total_count'] : count($assessable);
                $cov_count   = count($covered);
                $pass_count  = isset($ns['pass_count']) ? (int) $ns['pass_count'] : max(0, $total - $cov_count);
                ?>
                <h3><?php echo esc_html($norm_label); ?></h3>
                <p class="ns-desc"><?php echo esc_html(sprintf(
                    /* translators: 1: number of controls without findings, 2: total assessable controls, 3: number of controls with findings. */
                    __('%1$d of %2$d assessable controls have no findings; %3$d have at least one finding.', 'nubivio-healthcare-security-hardening'),
                    $pass_count,
                    $total,
                    $cov_count
                )); ?></p>
                <table class="ns-evidence-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Control', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Short title', 'nubivio-healthcare-security-hardening'); ?></th>
                            <th><?php esc_html_e('Status', 'nubivio-healthcare-security-hardening'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($assessable as $ctrl_id => $ctrl_title):
                        $ctrl_findings = isset($covered[$ctrl_id]) ? (array) $covered[$ctrl_id] : array();
                        $has           = !empty($ctrl_findings);
                        ?>
                        <tr>
                            <td><code><?php echo esc_html($ctrl_id); ?></code></td>
                            <td><?php echo esc_html($ctrl_title); ?></td>
                            <td>
                                <?php if (!$has): ?>
                                    <span class="ns-chip ns-chip-ok"><?php esc_html_e('no findings', 'nubivio-healthcare-security-hardening'); ?></span>
                                <?php else: ?>
                                    <span class="ns-chip ns-chip-medium"><?php echo esc_html(sprintf(
                                        /* translators: %d: number of findings mapped to this control. */
                                        _n('%d finding', '%d findings', count($ctrl_findings), 'nubivio-healthcare-security-hardening'),
                                        count($ctrl_findings)
                                    )); ?></span>
                                    <details>
                                        <summary><?php esc_html_e('show findings', 'nubivio-healthcare-security-hardening'); ?></summary>
                                        <ul class="ns-finding-list">
                                        <?php foreach ($ctrl_findings as $cf): ?>
                                            <?php $sev = isset($cf['severity']) ? $cf['severity'] : 'low'; ?>
                                            <li class="ns-finding ns-finding-<?php echo esc_attr($sev); ?>">
                                                <span class="ns-chip ns-chip-<?php echo esc_attr($sev); ?>"><?php echo esc_html(strtoupper($sev)); ?></span>
                                                <?php if (!empty($cf['module'])): ?><strong><?php echo esc_html($cf['module']); ?>:</strong> <?php endif; ?>
                                                <?php echo esc_html(isset($cf['message']) ? $cf['message'] : ''); ?>
                                            </li>
                                        <?php endforeach; ?>
                                        </ul>
                                    </details>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
<?php endif; ?>

<div class="ns-card ns-docs">
    <h2><?php esc_html_e('Compliance documents', 'nubivio-healthcare-security-hardening'); ?></h2>
    <p class="ns-card-intro"><?php
        esc_html_e(
            'Generated from your own settings. Printable HTML you can save as PDF from the browser. These are starting-point documents, not certifications.',
            'nubivio-healthcare-security-hardening'
        );
    ?></p>
    <div class="ns-doc-links">
        <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($doc_url('vdp')); ?>"><?php esc_html_e('Vulnerability Disclosure Policy', 'nubivio-healthcare-security-hardening'); ?></a>
        <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($doc_url('sbom')); ?>"><?php esc_html_e('CycloneDX SBOM (JSON)', 'nubivio-healthcare-security-hardening'); ?></a>
        <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($doc_url('conformity')); ?>"><?php esc_html_e('Conformity declaration', 'nubivio-healthcare-security-hardening'); ?></a>
        <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($doc_url('report')); ?>"><?php esc_html_e('Compliance report', 'nubivio-healthcare-security-hardening'); ?></a>
    </div>
</div>
