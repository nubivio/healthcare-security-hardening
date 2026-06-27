# Official readme validator result

Run against the current `readme.txt` at https://wordpress.org/plugins/developers/readme-validator/ on 27 June 2026.

## Verdict: no errors ✅

The validator reports **no Errors**. The readme is valid for submission. It does flag 1 warning and 3 notes.

### Warning (1) — action recommended before submission

- **Contributor `nubivio` not found on WordPress.org.** The validator could not find a WordPress.org user named `nubivio`, so it would be ignored. The `Contributors:` field must contain real **WordPress.org** usernames (this is a different account from your GitHub `nubivio` account).
  - **Action:** create/confirm the `nubivio` account at https://login.wordpress.org/register, or change `Contributors:` to the actual WordPress.org username that will own the listing. The account you upload from must be listed here.

### Notes (3) — advisory, not blockers

1. **Tags `nis2` and `security.txt` are not widely used.** Allowed, but uncommon. Optionally swap for more common tags (e.g. `security`, `headers`, `hsts`, `csp`) to improve discoverability. Keep the total at ≤5.
2. **No `== Screenshots ==` section.** Fine to ship without, but if you upload `screenshot-1.png` to SVN `assets/`, add a `== Screenshots ==` section so the caption renders.
3. **No donate link.** Purely optional.

## Other pre-submission checks (local)

- `php -l` on the main file: **no syntax errors** (PHP 8.5).
- Version consistency: header `2.0.0`, `const VERSION '2.0.0'`, readme `Stable tag: 2.0.0` — all agree.
- Required sections, short-description length, and tag count all pass.
