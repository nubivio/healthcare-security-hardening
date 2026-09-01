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
        <?php esc_html_e('Optional CRA, GDPR and NIS2 checks plus site health, built around the headers and security.txt this plugin already enforces. Nothing here changes your hardening; it verifies and documents it.', 'nubivio-healthcare-security-hardening'); ?>
    </p>

    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="ns-scan-form">
        <input type="hidden" name="action" value="<?php echo esc_attr(Nubivio_HSH::SCAN_ACTION); ?>">
        <?php wp_nonce_field(Nubivio_HSH::SCAN_ACTION); ?>
        <button type="submit" class="ns-btn ns-run-scan"><?php esc_html_e('Run compliance scan', 'nubivio-healthcare-security-hardening'); ?></button>
        <span class="ns-by"><?php esc_html_e('This may take a few seconds. Scans query the WordPress.org Plugins API (see External Services in the readme).', 'nubivio-healthcare-security-hardening'); ?></span>
    </form>
</div>

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
                echo esc_html($band === 'green' ? __('Green', 'nubivio-healthcare-security-hardening') : ($band === 'amber' ? __('Amber', 'nubivio-healthcare-security-hardening') : __('Red', 'nubivio-healthcare-security-hardening')));
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

            <p class="ns-desc"><?php esc_html_e('Uses the official WordPress.org checksums API (MD5). This detects unintended or malicious file changes; it is not a cryptographic tamper-proof check.', 'nubivio-healthcare-security-hardening'); ?></p>
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

            <p class="ns-desc"><?php esc_html_e('These checks are read-only snapshots taken during the scan. Nothing here changes users, roles or files.', 'nubivio-healthcare-security-hardening'); ?></p>
        </div>
    <?php endif; ?>

    <?php
    // v2.4.0 HSTS preload readiness.
    $hsts = isset($scan['frameworks']['hsts']['summary']) ? $scan['frameworks']['hsts']['summary'] : array();
    if ($hsts):
        $hsts_rows = array(
            __('HSTS header present', 'nubivio-healthcare-security-hardening') => !empty($hsts['header_present']) ? __('present', 'nubivio-healthcare-security-hardening') : __('missing', 'nubivio-healthcare-security-hardening'),
            __('max-age at least one year', 'nubivio-healthcare-security-hardening') => !empty($hsts['max_age_ok']) ? (string) (int) $hsts['max_age'] : (string) (int) $hsts['max_age'],
            __('includeSubDomains', 'nubivio-healthcare-security-hardening') => !empty($hsts['include_subdomains']) ? __('present', 'nubivio-healthcare-security-hardening') : __('missing', 'nubivio-healthcare-security-hardening'),
            __('preload directive', 'nubivio-healthcare-security-hardening') => !empty($hsts['preload']) ? __('present', 'nubivio-healthcare-security-hardening') : __('missing', 'nubivio-healthcare-security-hardening'),
        ); ?>
        <div class="ns-card">
            <h2><?php esc_html_e('HSTS preload readiness', 'nubivio-healthcare-security-hardening'); ?></h2>
            <table class="ns-evidence-table"><tbody><?php $i=0; foreach ($hsts_rows as $label => $value): $ok = $i === 0 ? !empty($hsts['header_present']) : ($i === 1 ? !empty($hsts['max_age_ok']) : ($i === 2 ? !empty($hsts['include_subdomains']) : !empty($hsts['preload']))); $i++; ?><tr><td><?php echo esc_html($label); ?></td><td><span class="ns-chip <?php echo $ok ? 'ns-chip-ok' : 'ns-chip-high'; ?>"><?php echo $ok ? esc_html__('yes', 'nubivio-healthcare-security-hardening') : esc_html__('no', 'nubivio-healthcare-security-hardening'); ?></span></td><td><?php echo esc_html($value); ?></td></tr><?php endforeach; ?></tbody></table>
            <p class="ns-v240-warning"><?php esc_html_e('Preload is nearly irreversible. Removal takes months and remains cached in older browsers. Every subdomain must serve valid HTTPS for as long as your entry stays on the list.', 'nubivio-healthcare-security-hardening'); ?></p>
            <?php if (!empty($hsts['ready_for_preload']) && !empty($hsts['host'])): ?><p><a class="ns-btn ns-btn-ghost" target="_blank" rel="noopener" href="<?php echo esc_url('https://hstspreload.org/?domain=' . rawurlencode($hsts['host'])); ?>"><?php esc_html_e('Submit at hstspreload.org →', 'nubivio-healthcare-security-hardening'); ?></a></p><?php endif; ?>
        </div>
    <?php endif; ?>

    <?php
    // v2.4.0 DNS health.
    $dns = isset($scan['frameworks']['dns']['summary']) ? $scan['frameworks']['dns']['summary'] : array();
    if ($dns): $dns_action = wp_nonce_url(admin_url('admin-post.php?action=' . Nubivio_HSH::DNS_REFRESH_ACTION), Nubivio_HSH::DNS_REFRESH_ACTION); ?>
        <div class="ns-card">
            <h2><?php esc_html_e('DNS health', 'nubivio-healthcare-security-hardening'); ?></h2>
            <p><a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($dns_action); ?>"><?php esc_html_e('Force-refresh DNS data', 'nubivio-healthcare-security-hardening'); ?></a></p>
            <table class="ns-evidence-table"><tbody>
                <tr><td>SPF</td><td><?php echo !empty($dns['spf']['records']) ? '<span class="ns-chip ns-chip-ok">' . esc_html__('present', 'nubivio-healthcare-security-hardening') . '</span><br><code>' . esc_html(implode("\n", (array) $dns['spf']['records'])) . '</code>' : '<span class="ns-chip ns-chip-medium">' . esc_html__('missing', 'nubivio-healthcare-security-hardening') . '</span><br><code>v=spf1 -all</code> <button type="button" class="ns-copy" data-copy="v=spf1 -all">' . esc_html__('Copy', 'nubivio-healthcare-security-hardening') . '</button>'; // phpcs:ignore WordPress.Security.EscapeOutput ?></td></tr>
                <tr><td>DMARC</td><td><?php if (!empty($dns['dmarc']['records'])): ?><span class="ns-chip ns-chip-ok"><?php esc_html_e('present', 'nubivio-healthcare-security-hardening'); ?></span><br><code><?php echo esc_html(implode("\n", (array) $dns['dmarc']['records'])); ?></code><?php else: $dmarc_template = '_dmarc.' . $host . '. IN TXT "v=DMARC1; p=none; rua=mailto:security@' . $host . '; ruf=mailto:security@' . $host . '; fo=1"'; ?><span class="ns-chip ns-chip-medium"><?php esc_html_e('missing', 'nubivio-healthcare-security-hardening'); ?></span><br><code><?php echo esc_html($dmarc_template); ?></code> <button type="button" class="ns-copy" data-copy="<?php echo esc_attr($dmarc_template); ?>"><?php esc_html_e('Copy', 'nubivio-healthcare-security-hardening'); ?></button><?php endif; ?></td></tr>
                <tr><td>DKIM</td><td><?php echo !empty($dns['dkim']['matched']) ? esc_html(implode(', ', (array) $dns['dkim']['matched'])) : esc_html__('No common selector matched.', 'nubivio-healthcare-security-hardening'); ?></td></tr>
                <tr><td>CAA</td><td><?php echo !empty($dns['caa']['records']) ? '<span class="ns-chip ns-chip-ok">' . esc_html__('present', 'nubivio-healthcare-security-hardening') . '</span>' : '<code>' . esc_html($host . '. IN CAA 0 issue "letsencrypt.org"') . '</code> <button type="button" class="ns-copy" data-copy="' . esc_attr($host . '. IN CAA 0 issue &quot;letsencrypt.org&quot;') . '">' . esc_html__('Copy', 'nubivio-healthcare-security-hardening') . '</button>'; // phpcs:ignore WordPress.Security.EscapeOutput ?></td></tr>
                <tr><td>MTA-STS</td><td><?php echo !empty($dns['mta_sts']['records']) || !empty($dns['mta_sts']['mx']) ? esc_html(implode(', ', (array) $dns['mta_sts']['mx'])) : '<code>version: STSv1; mode: enforce; mx: mail.' . esc_html($host) . '; max_age: 604800</code>'; // phpcs:ignore WordPress.Security.EscapeOutput ?></td></tr>
                <tr><td>DNSSEC</td><td><?php echo !empty($dns['dnssec']['indicator']) ? esc_html__('Native indicator found.', 'nubivio-healthcare-security-hardening') : esc_html__('No native indicator found.', 'nubivio-healthcare-security-hardening'); ?><?php if (array_key_exists('doh', (array) $dns['dnssec']) && $dns['dnssec']['doh'] !== null): ?> <?php echo !empty($dns['dnssec']['doh']) ? esc_html__('Cloudflare DoH validated.', 'nubivio-healthcare-security-hardening') : esc_html__('Cloudflare DoH did not validate.', 'nubivio-healthcare-security-hardening'); ?><?php endif; ?></td></tr>
                <tr><td>IPv6 / AAAA</td><td><?php echo !empty($dns['aaaa']['records']) ? esc_html__('present', 'nubivio-healthcare-security-hardening') : esc_html__('No AAAA record.', 'nubivio-healthcare-security-hardening'); ?></td></tr>
            </tbody></table>
        </div>
    <?php endif; ?>

    <?php
    // v2.4.0 CSP report-only card.
    $csp = isset($scan['frameworks']['csp']['summary']) ? $scan['frameworks']['csp']['summary'] : array();
    if ($csp): $inventory_action = wp_nonce_url(admin_url('admin-post.php?action=' . Nubivio_HSH::CSP_INVENTORY_ACTION), Nubivio_HSH::CSP_INVENTORY_ACTION); $toggle_action = wp_nonce_url(admin_url('admin-post.php?action=' . Nubivio_HSH::CSP_TOGGLE_ACTION), Nubivio_HSH::CSP_TOGGLE_ACTION); $hosts_count=0; foreach ((array) $csp['seen_hosts'] as $list) $hosts_count += count((array) $list); ?>
        <div class="ns-card">
            <h2><?php esc_html_e('CSP report-only violations', 'nubivio-healthcare-security-hardening'); ?></h2>
            <p><span class="ns-chip <?php echo !empty($csp['enabled']) ? 'ns-chip-ok' : 'ns-chip-low'; ?>"><?php echo !empty($csp['enabled']) ? esc_html__('enabled', 'nubivio-healthcare-security-hardening') : esc_html__('disabled', 'nubivio-healthcare-security-hardening'); ?></span></p>
            <p class="ns-card-intro"><?php echo esc_html(sprintf(__('Inventory: %1$d hosts detected and %2$d inline scripts counted. Last inventory scan: %3$s.', 'nubivio-healthcare-security-hardening'), $hosts_count, isset($csp['inline_scripts']) ? (int) $csp['inline_scripts'] : 0, !empty($csp['inventory_at']) ? date_i18n(get_option('date_format'), (int) $csp['inventory_at']) : __('never', 'nubivio-healthcare-security-hardening'))); ?></p>
            <p><a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($inventory_action); ?>"><?php esc_html_e('Refresh inventory now', 'nubivio-healthcare-security-hardening'); ?></a> <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($toggle_action); ?>"><?php echo !empty($csp['enabled']) ? esc_html__('Disable report-only', 'nubivio-healthcare-security-hardening') : esc_html__('Enable report-only', 'nubivio-healthcare-security-hardening'); ?></a></p>
            <p class="ns-desc"><?php esc_html_e('This policy reports without blocking. When you see no new relevant violations for 2 weeks, you are ready to enforce (coming in v2.5.0).', 'nubivio-healthcare-security-hardening'); ?></p>
            <?php $violations = (array) $csp['violations']; usort($violations, function($a, $b) { return (int) $b['count'] <=> (int) $a['count']; }); if ($violations): ?><table class="ns-evidence-table"><thead><tr><th><?php esc_html_e('Directive', 'nubivio-healthcare-security-hardening'); ?></th><th><?php esc_html_e('Blocked URI', 'nubivio-healthcare-security-hardening'); ?></th><th><?php esc_html_e('First / last seen', 'nubivio-healthcare-security-hardening'); ?></th><th><?php esc_html_e('Count', 'nubivio-healthcare-security-hardening'); ?></th><th><?php esc_html_e('Action', 'nubivio-healthcare-security-hardening'); ?></th></tr></thead><tbody><?php foreach ($violations as $v): ?><tr><td><?php echo esc_html($v['directive']); ?></td><td><code><?php echo esc_html($v['blocked_uri']); ?></code></td><td><?php echo esc_html(date_i18n(get_option('date_format'), (int) $v['first_seen']) . ' / ' . date_i18n(get_option('date_format'), (int) $v['last_seen'])); ?></td><td><?php echo (int) $v['count']; ?></td><td><form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><input type="hidden" name="action" value="<?php echo esc_attr(Nubivio_HSH::CSP_ALLOWLIST_ACTION); ?>"><input type="hidden" name="directive" value="<?php echo esc_attr($v['directive']); ?>"><input type="hidden" name="blocked_uri" value="<?php echo esc_attr($v['blocked_uri']); ?>"><?php wp_nonce_field(Nubivio_HSH::CSP_ALLOWLIST_ACTION); ?><button type="submit" class="ns-btn ns-btn-ghost"><?php esc_html_e('Add to allowlist', 'nubivio-healthcare-security-hardening'); ?></button></form></td></tr><?php endforeach; ?></tbody></table><?php else: ?><p class="ns-ok-line"><?php esc_html_e('No violations received yet.', 'nubivio-healthcare-security-hardening'); ?></p><?php endif; ?>
            <h3><?php esc_html_e('SRI audit', 'nubivio-healthcare-security-hardening'); ?></h3><p><?php esc_html_e('Dynamic scripts (SRI not applicable)', 'nubivio-healthcare-security-hardening'); ?>: <?php echo esc_html(implode(', ', (array) $csp['sri']['dynamic'])); ?></p><p><?php esc_html_e('Candidates for SRI', 'nubivio-healthcare-security-hardening'); ?>: <?php echo esc_html(implode(', ', (array) $csp['sri']['candidates'])); ?></p>
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
    if ($tls): $days = isset($tls['days_remaining']) ? $tls['days_remaining'] : null; $pill = $days === null ? 'ns-chip-low' : ($days < 14 ? 'ns-chip-high' : ($days < 30 ? 'ns-chip-medium' : 'ns-chip-ok')); ?>
        <div class="ns-card"><h2><?php esc_html_e('TLS overview', 'nubivio-healthcare-security-hardening'); ?></h2><table class="ns-evidence-table"><tbody><tr><td><?php esc_html_e('Certificate subject', 'nubivio-healthcare-security-hardening'); ?></td><td><?php echo esc_html($tls['subject_cn']); ?></td></tr><tr><td><?php esc_html_e('Issuer', 'nubivio-healthcare-security-hardening'); ?></td><td><?php echo esc_html(trim($tls['issuer_cn'] . ' ' . $tls['issuer_o'])); ?></td></tr><tr><td><?php esc_html_e('Valid until', 'nubivio-healthcare-security-hardening'); ?></td><td><?php echo !empty($tls['valid_to']) ? esc_html(date_i18n(get_option('date_format'), (int) $tls['valid_to'])) : ''; ?> <span class="ns-chip <?php echo esc_attr($pill); ?>"><?php echo $days === null ? esc_html__('unknown', 'nubivio-healthcare-security-hardening') : esc_html(sprintf(_n('%d day', '%d days', (int) $days, 'nubivio-healthcare-security-hardening'), (int) $days)); ?></span></td></tr><tr><td>SAN</td><td><?php echo esc_html(implode(', ', (array) $tls['sans'])); ?></td></tr><tr><td><?php esc_html_e('Signature algorithm', 'nubivio-healthcare-security-hardening'); ?></td><td><?php echo esc_html($tls['signature']); ?></td></tr><?php if (!empty($tls['dane'])): ?><tr><td>DANE/TLSA</td><td><a href="https://ssl-tools.net/dane" target="_blank" rel="noopener"><?php esc_html_e('DANE/TLSA record present. Validate externally.', 'nubivio-healthcare-security-hardening'); ?></a></td></tr><?php endif; ?></tbody></table><p class="ns-desc"><?php esc_html_e('For a full TLS cipher analysis use SSL Labs.', 'nubivio-healthcare-security-hardening'); ?> <a href="https://www.ssllabs.com/ssltest/" target="_blank" rel="noopener">SSL Labs</a>.</p></div>
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
            <p class="ns-card-intro"><?php esc_html_e('Live verification was unavailable, so the table shows configured headers. A hardened host may block self-requests.', 'nubivio-healthcare-security-hardening'); ?></p>
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
    <p class="ns-card-intro"><?php esc_html_e('Generated from your own settings. Printable HTML you can save as PDF from the browser. These are starting-point documents, not certifications.', 'nubivio-healthcare-security-hardening'); ?></p>
    <div class="ns-doc-links">
        <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($doc_url('vdp')); ?>"><?php esc_html_e('Vulnerability Disclosure Policy', 'nubivio-healthcare-security-hardening'); ?></a>
        <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($doc_url('sbom')); ?>"><?php esc_html_e('CycloneDX SBOM (JSON)', 'nubivio-healthcare-security-hardening'); ?></a>
        <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($doc_url('conformity')); ?>"><?php esc_html_e('Conformity declaration', 'nubivio-healthcare-security-hardening'); ?></a>
        <a class="ns-btn ns-btn-ghost" href="<?php echo esc_url($doc_url('report')); ?>"><?php esc_html_e('Compliance report', 'nubivio-healthcare-security-hardening'); ?></a>
    </div>
</div>
