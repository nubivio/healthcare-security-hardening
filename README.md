# Nubivio Salus – Security Hardening for Healthcare

Security headers, a self-renewing `security.txt` (RFC 9116) and advanced form protection for healthcare-related WordPress sites. Built for general practitioners, psychologists and other healthcare professionals. Recommended as a building block toward NIS2, GDPR and NEN 7510 compliance.

> The public listing name is **Nubivio Salus – Security Hardening for Healthcare**. The in-app admin menu label is the shorter **Nubivio Salus**. Both are intentional.

- **Version:** 2.0.0
- **Requires WordPress:** 5.8 or higher
- **Tested up to:** 7.0
- **Requires PHP:** 7.4
- **License:** [GPL-2.0-or-later](LICENSE)

## What it does

Everything is managed from one settings page, with defaults that are safe to ship on a live site. It is built to move your [internet.nl](https://internet.nl/) test score in the right direction across three areas.

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

### Gravity Forms (optional)

- Block submissions from one or more email domains, with a custom error message
- The section only appears when Gravity Forms is active

## Installation

1. Upload the plugin folder to `/wp-content/plugins/`, or install the ZIP via **Plugins → Add New → Upload Plugin**.
2. Activate the plugin.
3. Open **Settings → Nubivio Salus**.
4. Set a Contact value under security.txt.
5. To pass the internet.nl Content-Security-Policy check, enable CSP, test in Report-Only, add the domains your site needs, then turn Report-Only off to enforce.

## Scope and limitations

This plugin configures headers and a `security.txt`. It is one building block toward NIS2, GDPR and NEN 7510 — not a full compliance programme. It cannot change DNS or server-level items such as IPv6, the CAA record, the TLS key-exchange hash or DANE. Those are handled at your host or DNS provider.

## Privacy

No user data leaves the site. There are no external requests or trackers. All admin input is nonce protected, capability checked (`manage_options`), sanitized on save and escaped on output.

## Links

- Author: [Nubivio](https://nubivio.com/)

## License

This plugin is free software, released under the [GNU General Public License v2.0 or later](LICENSE).
