# Nubivio Healthcare Security Hardening

Security headers, a self-renewing `security.txt` (RFC 9116), a PHP2Shell runtime check and an optional CRA, GDPR and NIS2 compliance scanner for healthcare-related WordPress sites. Built for general practitioners, psychologists and other healthcare professionals. Recommended as a building block toward NIS2, GDPR and NEN 7510 compliance.

- **Version:** 2.6.0
- **Requires WordPress:** 5.8 or higher
- **Tested up to:** 7.1
- **Requires PHP:** 7.4
- **License:** [GPL-2.0-or-later](LICENSE)

## What it does

Everything is managed from one settings page, with defaults that are safe to ship on a live site. It is built to move your [internet.nl](https://internet.nl/) test score in the right direction.

### PHP2Shell check (new in 2.6.0)

PHP2Shell is the name for two critical PHP vulnerabilities, CVE-2026-109618 and CVE-2026-109619 (CVSS 9.2), that allow remote code execution without logging in. The plugin checks the version of the PHP process that actually serves your site, not a guess from response headers.

- PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 (21 October 2026) contain the fix. PHP 8.1 and older are no longer supported by the PHP project and are reported as vulnerable.
- Distribution builds (for example Ubuntu or Debian) may carry a backported fix under an older version number; these are reported as "verify with host".
- `session.upload_progress.enabled` is checked too. If it is on, the plugin advises setting it to 0, as PHP recommends. This is temporary and does not replace the update.
- The result appears on the Compliance tab and in WordPress Site Health.
- The plugin changes nothing in PHP. The update has to be done by your hosting provider or server administrator.
- Sources: [NCSC-NL PHP2Shell](https://github.com/NCSC-NL/php2shell), [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

### Security headers

- Strict-Transport-Security (HSTS) with configurable `max-age`, `includeSubDomains` and `preload`
- Content-Security-Policy with an internet.nl-compliant baseline and a Report-Only test mode
- Referrer-Policy with the internet.nl rating shown per value
- X-Content-Type-Options (`nosniff`)
- X-Frame-Options
- Permissions-Policy
- Active removal of the deprecated `X-XSS-Protection` and `Expect-CT` headers

### security.txt (RFC 9116)

- Writes `/.well-known/security.txt` and serves it dynamically when the docroot is read-only
- Refreshes the `Expires` field automatically so it never lapses and stays under one year
- Fields for Contact, Encryption, Policy, Acknowledgments, Hiring, CSAF, Preferred-Languages and Canonical
- Paste a PGP public key and the plugin hosts it at `/.well-known/openpgp-key.txt` and links it as `Encryption`
- A free-text message to researchers and an optional signature line
- CRLF line endings and a valid Canonical URL, exactly as the internet.nl test expects

### Compliance scanner (optional)

- CRA plugin readiness, GDPR and NIS2 Art. 21 signals, site health, WordPress core integrity and an administrator baseline
- HSTS preload readiness, DNS and email health, CSP inventory and grading, TLS overview and pre-consent cookie analysis
- Mapping to NEN 7510-2:2024 and ISO 27001:2022 Annex A controls
- New in 2.6.0: exposure scan of your own site, redirect chain check, opt-in RDAP domain registration check, opt-in Certificate Transparency check via crt.sh, and a risk scenarios panel
- Generated documents: Vulnerability Disclosure Policy, CycloneDX SBOM, conformity declaration and a printable report

### Gravity Forms (optional)

- Block submissions from one or more email domains, with a custom error message
- The section only appears when Gravity Forms is active

## Installation

1. Upload the plugin folder to `/wp-content/plugins/`, or install the ZIP via **Plugins → Add New → Upload Plugin**.
2. Activate the plugin.
3. Open **Settings → Nubivio Security**.
4. Set a Contact value under security.txt.
5. To pass the internet.nl Content-Security-Policy check, enable CSP, test in Report-Only, add the domains your site needs, then turn Report-Only off to enforce.

## Scope and limitations

This plugin configures headers and a `security.txt`. It is one building block toward NIS2, GDPR and NEN 7510, not a full compliance programme. It cannot change DNS or server-level items such as IPv6, the CAA record, the TLS key-exchange hash or DANE. Those are handled at your host or DNS provider.

## Privacy

No user data leaves the site and there are no trackers. The security headers and `security.txt` make no external requests. The optional compliance scan contacts WordPress.org, and, only when you turn them on, Cloudflare DNS over HTTPS, RDAP (IANA and your domain's registry) and crt.sh; for those sources only your domain name is sent. See the External Services section in `readme.txt` for details. All admin input is nonce protected, capability checked (`manage_options`), sanitized on save and escaped on output.

## Links

- Author: [Nubivio](https://nubivio.com/)

## License

This plugin is free software, released under the [GNU General Public License v2.0 or later](LICENSE).
