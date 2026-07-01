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
