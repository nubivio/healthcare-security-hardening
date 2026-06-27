# WordPress.org submission guide — Nubivio Salus

Everything is prepared up to the point that requires a logged-in WordPress.org account and a human reviewer. Those steps cannot be automated and must be done by the owning account holder. This guide walks you through them.

## Status of pre-submission checks (done for you)

| Check | Result |
|---|---|
| Version consistency (header `Version`, `const VERSION`, readme `Stable tag`) | ✅ all `2.0.0` |
| Changelog has a `= 2.0.0 =` entry | ✅ |
| Required readme sections (Description, Installation, FAQ, Changelog, Upgrade Notice) | ✅ all present |
| Short description length (≤150 chars) | ✅ 126 chars |
| Tags count (≤5) | ✅ exactly 5 |
| PHP syntax (`php -l`) | ✅ no syntax errors (PHP 8.5) |
| `readme.txt` header fields complete | ✅ Contributors, Tags, Requires at least, Tested up to, Requires PHP, Stable tag, License, License URI |
| Submission zip structure (folder → main php + readme at its root) | ✅ `healthcare-security-hardening.zip` |

> The official online **readme validator** result is summarized in `README-VALIDATOR-RESULT.md` (run against the current readme).

## What still needs a human (cannot be automated)

1. **Plugin Check (PCP)** must be run inside a real WordPress install (it is a runtime plugin, not a static linter). See step 1 below.
2. **Submitting** the zip at the upload form requires being logged in to the owning WordPress.org account.
3. **Manual review** by the Plugins Team (days to weeks). You must reply to their email if they ask for changes.
4. **SVN commit** after approval uses your WordPress.org SVN credentials.

---

## Step 1 — Run Plugin Check (PCP)

The Plugin Check plugin runs inside WordPress; there is no CLI-only equivalent the directory accepts.

1. On a local or staging WordPress site, install **Plugin Check**: https://wordpress.org/plugins/plugin-check/
2. Install and activate **Nubivio Salus** from `healthcare-security-hardening.zip`.
3. Go to **Tools → Plugin Check**, select the plugin, run all checks.
4. Clear every item flagged as **Error**. Warnings are advisory but worth reviewing.

What the plugin already does right (so PCP should be clean on these):
- Escapes output and sanitizes input; nonce + `manage_options` capability checks on the settings form.
- No external HTTP requests, trackers, or bundled third-party libraries.
- GPL-2.0-or-later license declared in both the header and readme.
- Text Domain `healthcare-security-hardening` matches the intended slug.

## Step 2 — Validate the readme online (already run)

Form: https://wordpress.org/plugins/developers/readme-validator/
See `README-VALIDATOR-RESULT.md` for the captured result. Re-run after any readme edit.

## Step 3 — Submit for review

1. Log in to the **owning** WordPress.org account (the one that should be the listed contributor — currently `nubivio` in the readme).
2. Go to https://wordpress.org/plugins/developers/add/
3. Upload `healthcare-security-hardening.zip` (from this delivery, root contains the folder `healthcare-security-hardening/` with the main php + readme).
4. Submit. You'll get a confirmation email; review is manual.

### Slug note (important)

The directory derives the slug from the **plugin name** at submission, so the assigned slug may be longer than `healthcare-security-hardening` — e.g. `healthcare-security-hardening-zorg-avg-nen-7510`. Once the team assigns the slug:
- Set the `Text Domain:` header to the assigned slug.
- Rename the plugin folder to match.
- Update the GitHub repo's `Plugin URI` only if you want it to track the final slug (the repo name itself can stay `healthcare-security-hardening`).

## Step 4 — After approval: SVN

The directory uses **Subversion**, not Git. After you get the approval email with your SVN URL:

```bash
# 1. Check out the (empty) repo
svn co https://plugins.svn.wordpress.org/<assigned-slug>/ nubivio-salus-svn
cd nubivio-salus-svn

# 2. Put the current code in trunk
cp /path/to/healthcare-security-hardening.php trunk/
cp /path/to/readme.txt trunk/
svn add trunk/* --force

# 3. Commit trunk
svn ci -m "Initial commit: Nubivio Salus 2.0.0" --username YOUR_WPORG_USER

# 4. Tag the release by copying trunk -> tags/2.0.0 (preserves history)
svn cp trunk tags/2.0.0
svn ci -m "Tagging 2.0.0" --username YOUR_WPORG_USER
```

- `Stable tag: 2.0.0` in `readme.txt` tells the directory to serve `tags/2.0.0`.
- Do **not** put the main plugin file in a subfolder of `trunk` (e.g. `trunk/healthcare-security-hardening/...`) — that breaks downloads. The php + readme go **directly** in `trunk/`.

## Step 5 — Store assets (recommended, SVN `assets/`)

These are not shipped to users; they only power the directory listing page. Put them in the repo's top-level `assets/` folder (sibling of `trunk/`), then `svn add` + `svn ci`.

| File | Size | Purpose |
|---|---|---|
| `icon-128x128.png` | 128×128 | Listing icon |
| `icon-256x256.png` | 256×256 | Retina listing icon |
| `banner-772x250.png` | 772×250 | Listing banner |
| `banner-1544x500.png` | 1544×500 | Retina banner |
| `screenshot-1.png` | any | The settings page (matches a `1. ...` line you'd add under a `== Screenshots ==` readme section) |

**Brand kit** (from the handoff brief):
- Primary `#044172`, navy `#13274C`
- Logo gradient `#22C9F5` → `#224AF1`
- Fonts: Nunito (display), Montserrat
- The Nubivio mark reads well on the navy gradient.

> Note: the current `readme.txt` has no `== Screenshots ==` section. If you ship `screenshot-1.png`, add a `== Screenshots ==` section with `1. The Nubivio Salus settings page` so the caption renders.

## Optional — Automated deploys later (GitHub → SVN)

To push tagged Git releases straight to SVN in future, add the [`10up/action-wordpress-plugin-deploy`](https://github.com/10up/action-wordpress-plugin-deploy) GitHub Action. It needs `SVN_USERNAME` and `SVN_PASSWORD` repo secrets. Not required for the first manual submission. A ready-to-use workflow file is provided at `deploy.yml` in this delivery if you want to add it to `.github/workflows/`.

## Reviewer notes (if asked)

- The plugin writes `/.well-known/security.txt` under the site root and falls back to serving it dynamically when that directory is not writable. This is the documented purpose (RFC 9116) and the only filesystem write it performs.
- All admin input is nonce protected, capability checked (`manage_options`), sanitized on save and escaped on output. No user data leaves the site; there are no external requests or trackers.
- The internal option key and class prefix use `nubivio_salus` for namespacing. This is intentional and unrelated to the public slug.
- Two names are intentional: public listing name `Nubivio Salus - Security Hardening for Healthcare`; in-app menu label `Nubivio Salus`.
