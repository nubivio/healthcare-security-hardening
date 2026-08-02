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
            </tbody>
        </table>
        <p><a href="<?php echo esc_url($intnl); ?>" target="_blank" rel="noopener">internet.nl/site/<?php echo esc_html($host); ?></a></p>
    </div>
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
