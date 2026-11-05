=== Nubivio Security Headers, security.txt & NIS2 Compliance for Healthcare ===
Contributors: nubivio
Tags: security, security-txt, nis2, hsts, php2shell
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.6.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security headers, security.txt, a PHP2Shell runtime check and an optional CRA, GDPR and NIS2 scanner for healthcare WordPress sites.

== Description ==

Set the security headers that matter, publish a self-renewing **security.txt** (RFC 9116), and check your site against **NIS2**, the EU Cyber Resilience Act (CRA), GDPR and NEN 7510, all from one settings page. Built for general practitioners, psychologists and other healthcare professionals who need a defensible security baseline without a consultant.

The defaults are safe to ship on a live site, and the plugin is built to move your score on the internet.nl test in the right direction. The compliance features are optional and read-only: they verify and document what you already have, and never change your hardening.

**PHP2Shell check (new in 2.6.0)**

PHP2Shell is the name for two critical PHP vulnerabilities, CVE-2026-109618 and CVE-2026-109619 (CVSS 9.2), that allow remote code execution without logging in. The plugin checks the version of the PHP process that actually serves your site, not a guess from response headers.

* PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 (21 October 2026) contain the fix. Older versions in those branches are reported as vulnerable.
* PHP 8.1 and older are no longer supported by the PHP project. The plugin reports them as vulnerable and advises an upgrade.
* Distribution builds (for example Ubuntu or Debian) may carry a backported fix under an older version number. The plugin then reports "verify with host" and asks you to compare the package version with the distribution advisory, instead of calling the site vulnerable.
* It also checks `session.upload_progress.enabled`. If it is on, the plugin advises setting it to 0, as PHP recommends. That is a temporary measure and does not replace the update.
* The result appears on the Compliance tab and in WordPress Site Health (Tools, Site Health).
* The check only reads version and ini values, makes no network requests and changes nothing. A plugin cannot change PHP: the update has to be done by your hosting provider or server administrator.
* Sources: NCSC-NL (https://github.com/NCSC-NL/php2shell) and the PHP security advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp.

**Why healthcare sites use this**

* One click to a strong header set and a valid security.txt, the two things the internet.nl test and most security reviews check first.
* An optional Compliance tab that turns those headers and your security.txt into evidence, mapped to NIS2 Art. 21, CRA Art. 14 and GDPR clauses.
* A compliance score with a plain-language breakdown, so you know where you stand and what to fix next.
* Available in English and Dutch.

It covers four areas:

**Security headers**

* Strict-Transport-Security (HSTS) with configurable max-age, includeSubDomains and preload
* Content-Security-Policy with an internet.nl compliant baseline and a Report-Only test mode
* Referrer-Policy with the internet.nl rating shown per value
* X-Content-Type-Options (nosniff)
* X-Frame-Options
* Permissions-Policy
* Active removal of the deprecated X-XSS-Protection and Expect-CT headers
* Optional COOP, COEP credentialless, CORP and an extended Permissions-Policy

**security.txt (RFC 9116)**

* Writes /.well-known/security.txt and serves it dynamically when the docroot is read-only
* Refreshes the Expires field automatically so it never lapses and stays under one year
* Fields for Contact, Encryption, Policy, Acknowledgments, Hiring (careers), CSAF, Preferred-Languages and Canonical
* Paste your PGP public key and the plugin hosts it at /.well-known/openpgp-key.txt and links it as Encryption automatically
* A free-text message to researchers and an optional signature line
* CRLF line endings and a valid Canonical URL, exactly as the internet.nl test expects

**Compliance scanner (optional, new in 2.2.0)**

* A Compliance tab with a single compliance score and a red / amber / green band
* CRA plugin readiness: checks each active plugin against the WordPress.org directory for update currency, compatibility and abandonment
* GDPR checks: detects third-party scripts, forms and consent tooling, and cross-references your Content-Security-Policy
* NIS2 Art. 21 signals: encryption in transit, MFA, backups, WAF, activity logging and auto-updates
* Site health checks: security.txt validity, live header verification, WordPress and PHP currency, TLS, debug mode, XML-RPC and REST user exposure
* WordPress core integrity: verifies your core files against the official WordPress.org checksums and reports modified or missing files (new in 2.3.0)
* Access and integrity: an approved administrator baseline, recently created admins, roles and users with unexpected administrator capabilities, an application password audit, a must-use plugin audit and a siteurl sanity check (new in 2.3.0)
* Live verification that your configured security headers are actually being sent, not just set
* Security headers and security.txt shown as compliance evidence, mapped to the relevant NIS2, CRA and GDPR clauses
* HSTS preload readiness, DNS health (SPF, DMARC, DKIM, CAA, MTA-STS, DNSSEC and AAAA), CSP report-only inventory and violation viewer, SRI detector, and TLS certificate overview (new in 2.4.0)
* One-click documents generated from your own settings: a Vulnerability Disclosure Policy, a CycloneDX SBOM, an EU and NEN 7510 conformity declaration, and a printable compliance report
* Exposure scan: checks your own site for publicly reachable files and listings such as /.git, /.env, wp-config backups, debug.log, an open uploads directory and user enumeration (new in 2.6.0)
* Redirect chain check: follows the http, https and www variants of your domain and reports chains that skip HTTPS or HSTS (new in 2.6.0)
* Domain registration check via RDAP (opt-in): expiry date, transfer lock and DNSSEC delegation of your domain (new in 2.6.0)
* Certificate Transparency check via crt.sh (opt-in): lists the issuers of certificates for your domain and warns about new issuers or issuers outside your CAA record (new in 2.6.0)
* Risk scenarios: combines signals from the scan into a short list of attack scenarios, each with the underlying signals and a first step. Scenarios are based on signals, not confirmed vulnerabilities or intrusions (new in 2.6.0)

**Gravity Forms (optional)**

* Block submissions from one or more email domains, with a custom error message
* The section only appears when Gravity Forms is active

This plugin configures headers and a security.txt and helps you document your posture. It is one building block toward NIS2, CRA, GDPR and NEN 7510, not a full compliance programme, and the generated documents are self-assessment starting points, not certifications. It cannot change DNS or server level items such as IPv6, the CAA record, the TLS key-exchange hash or DANE. Those are handled at your host or DNS provider.

== Installation ==

1. Upload the plugin folder to /wp-content/plugins/, or install the ZIP via Plugins, Add New, Upload Plugin.
2. Activate the plugin.
3. Open Settings, Nubivio Security.
4. Set a Contact value under security.txt.
5. To pass the internet.nl Content-Security-Policy check, enable CSP, test in Report-Only, add the domains your site needs, then turn Report-Only off to enforce.

== Frequently Asked Questions ==

= Will activating the plugin break my site? =
No. HSTS, nosniff, X-Frame-Options, Referrer-Policy and Permissions-Policy are safe defaults. Content-Security-Policy is off by default because a strict policy needs tuning per site.

= How do I get a fully green internet.nl result? =
Enable and enforce a Content-Security-Policy that fits your site, set Referrer-Policy to no-referrer or same-origin, and set a Contact for security.txt. IPv6, CAA, the TLS hash and DANE are out of scope and must be fixed at your host or DNS.

= Can I publish a PGP key? =
Yes. Paste your ASCII-armored public key in the security.txt section. The plugin hosts it at /.well-known/openpgp-key.txt and references it from security.txt as the Encryption field automatically.

= Does this make me NIS2, CRA, GDPR or NEN 7510 compliant? =
No single plugin can. It covers the public web hardening part (transport security, browser protections and a vulnerability disclosure contact), verifies it live, and generates starting-point documents such as a Vulnerability Disclosure Policy, an SBOM and a conformity declaration. It is a useful building block and an evidence tool, not a full compliance programme or a certification.

= Is the Compliance tab safe to use? =
Yes. It is optional and read-only. Scanning only reads your site and public WordPress.org data; it never changes your settings or hardening. If you never open the tab, nothing about your site changes.

= Does this plugin check for PHP2Shell? =
Yes. Since 2.6.0 it reads the version of the PHP process that serves your site and compares it with the fixed releases 8.2.35, 8.3.36, 8.4.27 and 8.5.12 (CVE-2026-109618 and CVE-2026-109619). It also checks whether `session.upload_progress.enabled` is on. The result is shown on the Compliance tab and in Site Health. For distribution builds with a backported fix it reports "verify with host" instead of "vulnerable".

= Can the plugin fix PHP2Shell for me? =
No. PHP2Shell is a vulnerability in PHP itself, which runs below WordPress. A plugin cannot update or patch PHP. Only your hosting provider or server administrator can install a fixed PHP version. The plugin tells you which version you need, so you can ask your host. Setting `session.upload_progress.enabled=0` in php.ini, which PHP recommends, is a temporary measure and does not replace the update.

= Is Gravity Forms required? =
No. The header and security.txt features work on any site. The form section only appears when Gravity Forms is active.

== External Services ==

The core hardening features (security headers and security.txt) make no external requests. The optional Compliance tab, introduced in 2.2.0, uses the following external services only when you run a scan (manually or via the optional scheduled scan). Nothing here runs on normal front-end page loads.

**WordPress.org Plugins API**

When a compliance scan runs, the plugin looks up each active plugin in the WordPress.org Plugins directory to check update currency and compatibility.

* What is sent: the public plugin slug only (for example, "akismet"). No personal data, no site data.
* When: only during a manual or scheduled compliance scan.
* Endpoint: https://api.wordpress.org/plugins/info/1.0/{slug}.json and https://api.wordpress.org/core/version-check/1.7/
* Caching: results are cached in a transient for 12 hours.
* This is a first-party WordPress.org endpoint. Terms: https://wordpress.org/about/privacy/

**WordPress.org Checksums API**

When a compliance scan runs, the plugin retrieves the published MD5 checksums for your WordPress version so it can verify that your core files have not been altered.

* What is sent: your WordPress version and site locale (for example, "6.8" and "nl_NL"). No personal data, no site data, no file contents. Files are hashed locally and only the hashes are compared.
* When: only during a manual or scheduled compliance scan.
* Endpoint: https://api.wordpress.org/core/checksums/1.0/
* Caching: the checksum list is cached in a transient for 12 hours (1 hour if the request fails).
* This is a first-party WordPress.org endpoint. Terms: https://wordpress.org/about/privacy/

**Loopback self-request (header and REST probe)**

When a compliance scan runs, the plugin makes a request to its own home URL to verify that the configured security headers are actually being sent and to check whether the REST users endpoint exposes user data.

* What is sent: a normal HTTP GET to the site's own home URL. No third-party service is contacted.
* When: only during a manual or scheduled compliance scan, or admin/cron context. Never on normal front-end page loads.
* Timeout: short (8 seconds). Result cached in a transient for 10 minutes.
* If the request fails (some hardened hosts block self-requests), the plugin falls back to showing configured values and reports that live verification was unavailable.
* Since 2.6.0 the exposure scan and the redirect chain check also send a small number of GET requests to your own domain (the http, https and www variants and a fixed list of paths such as /.git/HEAD and /.env). Only the status code and a yes/no result are kept. No third-party service is contacted.

**RDAP domain registration lookup (optional, off by default)**

When you turn on "Domain registration check via RDAP", the plugin looks up the registration of your domain with RDAP, the successor of Whois.

* What is sent: your registered domain name only (for example, "example.nl"). No personal data, no site content.
* Step 1: the IANA RDAP bootstrap file is downloaded to find the RDAP server for your top-level domain. Endpoint: https://data.iana.org/rdap/dns.json. The IANA website is operated by Public Technical Identifiers (PTI), an affiliate of ICANN. Privacy policy: https://www.icann.org/privacy/policy. Terms of service: https://www.icann.org/privacy/tos
* Step 2: your domain name is sent to the RDAP server of your domain's registry, as listed in that bootstrap file. For .nl this is SIDN (https://rdap.sidn.nl/), privacy information: https://www.sidn.nl/en/nl-domain-name/sidn-and-privacy and https://www.sidn.nl/en/about-sidn/privacy. For .com this is Verisign (https://rdap.verisign.com/com/v1/), terms of service: https://www.verisign.com/domain-names/registration-data-access-protocol/terms-service/index.xhtml. Other registries publish their own terms, usually linked in the RDAP response.
* When: only during a manual or scheduled compliance scan, and only when the setting is on. Never on normal page loads.
* Caching: the bootstrap file is cached for 7 days, the domain result for 24 hours (1 hour after a failed request). Timeout 10 seconds.
* How to turn it off: Settings, Nubivio Security, External sources (opt-in), untick "Domain registration check via RDAP". When it is off, no request is made.

**crt.sh Certificate Transparency search by Sectigo (optional, off by default)**

When you turn on "Certificate Transparency check via crt.sh", the plugin asks crt.sh which certificates have been issued for your domain, using the public Certificate Transparency logs.

* What is sent: your registered domain name only (for example, "example.nl"), in two queries: the domain itself and its subdomains. No personal data, no site content. The plugin makes no requests to the subdomains it finds.
* Endpoint: https://crt.sh/?q={domain}&output=json and https://crt.sh/?q=%25.{domain}&output=json
* crt.sh is operated by Sectigo Limited. Terms of use (crt.sh is listed as a Sectigo site): https://www.sectigo.com/terms-of-use. Privacy policy: https://www.sectigo.com/privacy-policy
* When: only during a manual or scheduled compliance scan, and only when the setting is on. Never on normal page loads.
* Caching: results are cached for 24 hours (1 hour after a failed request). Timeout 10 seconds, response limited to 2 MB and 500 certificates. If crt.sh is unavailable, the scan continues without it.
* How to turn it off: Settings, Nubivio Security, External sources (opt-in), untick "Certificate Transparency check via crt.sh". When it is off, no request is made.

**Cloudflare DNS over HTTPS (optional)**

When you opt in to DNSSEC validation through Cloudflare DoH, the plugin sends only the site hostname to Cloudflare's DNS resolver.

* What is sent: the site hostname. No personal data or site content.
* When: only during a manual or scheduled compliance scan, and only when the optional DNSSEC DoH setting is enabled.
* Endpoint: https://cloudflare-dns.com/dns-query
* Caching: response is cached in a transient for 6 hours.

**Local CSP report endpoint**

When CSP report-only is enabled, browsers may POST reports to the local endpoint /wp-json/nubivio-hsh/v1/csp-report. This is not an outbound or third-party service call. Reports are rate-limited and stored as a rolling local option buffer.

== Screenshots ==

1. The Nubivio Security settings page: header status card with the live security.txt state, the security headers section with per-header toggles, and the RFC 9116 security.txt fields.
2. The Compliance tab: compliance score, CRA, GDPR and NIS2 findings, site health checks and the security headers and security.txt evidence panels.
3. The compliance score at a glance, with the red / amber / green band and the high, medium and low finding counts.

== Changelog ==

= 2.6.0 =
* New: PHP2Shell runtime check (CVE-2026-109618, CVE-2026-109619). Reads the running PHP version and compares it with the fixed releases 8.2.35, 8.3.36, 8.4.27 and 8.5.12, reports distribution builds as "verify with host", checks session.upload_progress and shows the result on the Compliance tab, in an admin notice and in Site Health. The plugin does not change PHP.
* New: exposure scan for publicly reachable files and listings (/.git, /.env, wp-config backups, debug.log, uploads listing, readme and license files, user enumeration, generator tag).
* New: redirect chain check for the http, https and www variants of the domain, including HSTS on every HTTPS hop.
* New: RDAP domain registration check (opt-in, off by default): expiry, transfer lock and DNSSEC delegation.
* New: Certificate Transparency check via crt.sh (opt-in, off by default): known issuer baseline, new issuers in the last 30 days, issuers outside the CAA record, and a "Mark current issuers as known" button.
* New: risk scenarios panel at the top of the Compliance tab. Combines existing signals into attack scenarios with a first step. It adds no findings and does not change the score.
* New: "External sources (opt-in)" settings card. Each external source has its own checkbox and is off by default.
* New: ISO 27001 and NEN 7510 mapping for the new checks (A.5.30, A.8.8, A.8.12, A.8.24).
* New filters: nubivio_hsh_php_advisories, nubivio_hsh_redirects_variant_resolves, nubivio_hsh_registered_domain, nubivio_hsh_rdap_no_lock_status_tlds, nubivio_hsh_ct_caa_map, nubivio_hsh_scenario_upload_plugins, nubivio_hsh_csp_enforce_min_inventory_days, nubivio_hsh_csp_enforce_quiet_days and nubivio_hsh_sectxt_drift_check.
* Fix: the cookie and tracker analysis and the NEN 7510 / ISO 27001 compliance mapping announced in 2.5.0 are now actually loaded. In 2.5.0 their files were missing from the include list, so they did not run.
* Fix: removed the outdated "coming in v2.5.0" note from the CSP report-only panel; the enforce switch is available since 2.5.0.

= 2.5.0 =
* Compliance mapping to NEN 7510-2:2024 and ISO 27001:2022 Annex A control level.
* Pre-consent cookie and tracker analysis with consent-plugin detection.
* SPF policy grading, RFC 7208 lookup-limit counting, DKIM key strength, TLS-RPT, BIMI, no-mail detection.
* DNS NS redundancy and SOA freshness checks.
* CSP policy effectiveness grading (A-F) on the plugin's own generated policy.
* CSP enforce switch with 14-day inventory preflight and fail-safe fallback to report-only.
* security.txt Expires countdown and drift detection.
* Reformatted v2.4.0 modules to WordPress Coding Standards (no behavior change).

= 2.4.0 =
* Additional optional hardening headers: COOP, COEP credentialless, CORP and extended Permissions-Policy
* HSTS preload readiness check and Compliance card
* DNS health dashboard for SPF, DMARC, DKIM, CAA, MTA-STS, DNSSEC indicator with optional Cloudflare DoH validation, and AAAA
* CSP report-only phase 1: inventory scanner, local browser report endpoint, violation viewer and add-to-allowlist action
* SRI audit detector for external script and stylesheet candidates, without auto-injection
* TLS overview card for certificate expiry, signature algorithm, subject and SANs, plus DANE/TLSA presence

= 2.3.1 =
* Compatibility: tested on WordPress 7.1. No code changes; all scanners verified against the 7.1 API surface.

= 2.3.0 =
* CRA precision: plugins that are not in the WordPress.org directory are now classified as commercial, possibly removed or unknown, so premium plugins such as Gravity Forms or ACF Pro no longer show up as high severity findings
* New setting to list your own private or commercial plugin slugs and skip them from the "not in directory" warning
* New WordPress core integrity check using the official WordPress.org checksums API, reporting modified and missing core files
* New Access and integrity card: administrator baseline with an approve action, so any later change to the administrator list is flagged
* Detection of administrator accounts created in the last 30 days
* Detection of non-administrator roles and users that hold administrator capabilities
* Application password audit across administrator accounts, flagging passwords created since the approved baseline
* Must-use plugin audit with an allowlist for the common managed hosts
* siteurl sanity check against the current request host
* Scan for core files modified well after the last core update
* All new checks are read-only and only run during a manual or scheduled compliance scan

= 2.2.2 =
* Fix: the optional signature line in security.txt now uses a plain ASCII separator, so servers that do not declare UTF-8 no longer render mojibake (e.g. "Â·") for the middle dot.

= 2.2.1 =
* Listing and documentation refresh: clearer description covering the NIS2, CRA and security.txt features, and two new screenshots of the Compliance tab. No code changes.

= 2.2.0 =
* New Compliance tab: CRA, GDPR and NIS2 scanning plus site health checks
* Live verification that configured security headers are actually sent
* security.txt and headers now scored and mapped to CRA / NIS2 / GDPR clauses
* Compliance score with per-framework breakdown
* Generators: Vulnerability Disclosure Policy, CycloneDX SBOM, EU/NEN 7510 conformity declaration
* Printable compliance report (browser print to PDF, no added dependencies)
* Existing header and security.txt hardening unchanged

= 2.1.2 =
* Added plugin icon, banner and a settings page screenshot for the WordPress.org listing

= 2.1.1 =
* All filesystem reads, writes and deletes now go through the WP_Filesystem API and wp_delete_file()

= 2.1.0 =
* Renamed the plugin to Nubivio Healthcare Security Hardening
* Admin CSS and JavaScript are now enqueued instead of printed inline
* The security.txt and PGP key files are now located via get_home_path() so they land at the public site root on subdirectory and custom installs
* Internal option, cron and nonce keys renamed to the new namespace

= 2.0.0 =
* Settings page for all options
* internet.nl compliant Content-Security-Policy baseline with Report-Only mode
* Self-renewing security.txt with CRLF line endings and an expiry kept under one year
* Hosted PGP public key, linked from security.txt as Encryption
* Extra security.txt fields: Hiring, CSAF, researcher message and an optional signature
* Removal of deprecated X-XSS-Protection and Expect-CT headers
* Gravity Forms email-domain blocking, shown only when Gravity Forms is active

== Upgrade Notice ==

= 2.6.0 =
Adds a PHP2Shell runtime check, an exposure scan, a redirect chain check, opt-in RDAP and Certificate Transparency checks, and risk scenarios. Also makes the cookie analysis and NEN 7510 / ISO 27001 mapping from 2.5.0 actually load. External sources are off by default; existing hardening is unchanged.

= 2.5.0 =
Adds compliance mapping to NEN 7510-2:2024 and ISO 27001:2022 controls, pre-consent cookie and tracker analysis, deeper email checks (SPF grading, RFC 7208 lookups, DKIM key strength, TLS-RPT, BIMI), DNS NS and SOA checks, CSP grading and an opt-in enforce switch with preflight, and security.txt Expires plus drift detection. All new checks are read-only; existing hardening is unchanged.

= 2.4.0 =
Adds optional advanced hardening headers, HSTS preload readiness, DNS and TLS overview cards, and CSP report-only monitoring. Existing hardening remains unchanged; CSP report-only is off until you enable it.

= 2.3.1 =
Compatibility bump for WordPress 7.1. No functional changes.

= 2.3.0 =
Fewer false positives for commercial plugins, a WordPress core integrity check, and a new Access and integrity card covering administrators, application passwords and must-use plugins. Existing hardening is unchanged.

= 2.2.2 =
Small fix to the optional signature line in security.txt. No functional changes elsewhere.

= 2.2.1 =
Documentation and listing update only. No functional changes.

= 2.2.0 =
Adds an optional Compliance tab. Existing hardening is unchanged.

= 2.1.2 =
Adds listing assets (icon, banner, screenshot). No functional changes.

= 2.1.1 =
Filesystem operations now use the WP_Filesystem API.

= 2.1.0 =
Plugin renamed and code updated to meet WordPress.org review requirements. Settings move to Settings, Nubivio Security.

= 2.0.0 =
First public release.
