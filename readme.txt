=== Nubivio Healthcare Security Hardening ===
Contributors: nubivio
Tags: security, headers, security-txt, csp, hsts
Requires at least: 5.8
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 2.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security headers, a self-renewing security.txt (RFC 9116) and advanced form protection for healthcare related WordPress sites.

== Description ==

Security headers, a self-renewing security.txt (RFC 9116) and advanced form protection for healthcare related WordPress sites. Built for general practitioners, psychologists and other healthcare professionals. Recommended for NIS2, GDPR and NEN7510 compliance.

Everything is managed from one settings page, and the defaults are safe to ship on a live site. The plugin is built to move your score on the internet.nl test in the right direction.

It covers three areas:

**Security headers**

* Strict-Transport-Security (HSTS) with configurable max-age, includeSubDomains and preload
* Content-Security-Policy with an internet.nl compliant baseline and a Report-Only test mode
* Referrer-Policy with the internet.nl rating shown per value
* X-Content-Type-Options (nosniff)
* X-Frame-Options
* Permissions-Policy
* Active removal of the deprecated X-XSS-Protection and Expect-CT headers

**security.txt (RFC 9116)**

* Writes /.well-known/security.txt and serves it dynamically when the docroot is read-only
* Refreshes the Expires field automatically so it never lapses and stays under one year
* Fields for Contact, Encryption, Policy, Acknowledgments, Hiring (careers), CSAF, Preferred-Languages and Canonical
* Paste your PGP public key and the plugin hosts it at /.well-known/openpgp-key.txt and links it as Encryption automatically
* A free-text message to researchers and an optional signature line
* CRLF line endings and a valid Canonical URL, exactly as the internet.nl test expects

**Gravity Forms (optional)**

* Block submissions from one or more email domains, with a custom error message
* The section only appears when Gravity Forms is active

This plugin configures headers and a security.txt. It is one building block toward NIS2, GDPR and NEN7510, not a full compliance programme. It cannot change DNS or server level items such as IPv6, the CAA record, the TLS key-exchange hash or DANE. Those are handled at your host or DNS provider.

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

= Does this make me NIS2, GDPR or NEN7510 compliant? =
It covers the public web hardening part: transport security, browser protections and a vulnerability disclosure contact. It is a useful building block, not a full compliance programme.

= Is Gravity Forms required? =
No. The header and security.txt features work on any site. The form section only appears when Gravity Forms is active.

== Changelog ==

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

= 2.1.0 =
Plugin renamed and code updated to meet WordPress.org review requirements. Settings move to Settings, Nubivio Security.

= 2.0.0 =
First public release.
