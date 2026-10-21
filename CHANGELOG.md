# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/). `check-php2shell.sh` exit codes
(0 PATCHED, 1 MITIGATED, 2 EXPOSED, 3 UNKNOWN) are a stable interface and did not change.

## [1.1.0] - 2026-10-22

### Fixed (`check-php2shell.sh`)
- **False `EXPOSED` on hosts patched by a distribution backport.** Debian, Ubuntu and RHEL fix PHP without
  changing the upstream number (Ubuntu 24.04 `8.3.6-0ubuntu0.24.04.13` still reports `PHP_VERSION` 8.3.6).
  The script now reads the changelog of the dpkg/rpm package owning each binary and reports `PATCHED` when
  both `CVE-2026-109618` and `CVE-2026-109619` are listed. This also resolves vendor-packaged EOL runtimes.
- **Wrong FPM pools with a relative `include=`** (Docker official image): the script resolved the glob against
  the config directory, FPM resolves it against its prefix. Pools are now read from `php-fpm -tt`, i.e. what
  FPM itself applies; reading the files is only a fallback.
- **Pre-release builds counted as fixed.** `8.5.12RC1` / `8.3.36-dev` sorted above `8.5.12` / `8.3.36`.
- **PHP 8.6 (RC published 21 Oct) reported `EXPOSED`.** Unknown newer branches are now `UNKNOWN-BRANCH`
  (exit 3) unless `FIXED_<major>_<minor>` is set.
- `session.upload_progress.enabled` = `n/a` (no session extension) no longer blocks `MITIGATED`.
- Empty arrays under `set -u` on bash 4.2/4.3; explicit bash 4+ check.
- `-h` / unknown options were silently ignored; the stock Apache `php_admin_flag engine Off` line is no
  longer listed as a directive to review; `pm.max_requests=0` (default) is no longer reported.

### Added (`check-php2shell.sh`)
- **Restart check:** running php-fpm / php-cgi / lsphp / frankenphp (and Apache with mod_php) processes whose
  binary or library was replaced on disk make the verdict `EXPOSED (restart required)`.
- php-cgi inspection; version check for LiteSpeed `lsphp` and FrankenPHP; RLIMIT_AS / RLIMIT_DATA check now
  covers all web SAPI processes.
- `-h/--help`, `-V/--version`, `--quiet`; exit code 64 for usage errors.

### Added (repository)
- `mitigation/nginx.conf.example` and `mitigation/apache.conf.example`: request body / header limits
  (chunked bodies included), multipart block, mod_php `php_admin_*`. Tested on real nginx 1.24 + PHP-FPM
  and Apache 2.4 + mod_php.
- `mitigation/php.ini.snippet`: optional `max_input_*` lines and a warning that the default 7M upload cap
  breaks sites that need larger uploads.
- `tests/run-tests.sh` (hermetic, 42 checks) and a GitHub Actions workflow (shellcheck, tests, integration
  job on a real `php-fpm` / `php-cgi`).
- README / PATCHING.md: per-advisory SAPI nuances, local changelog check for Debian/Ubuntu, restart guidance.

## [1.0.0] - 2026-10-22
- Initial release: check script, interim mitigation files, patch notes, aligned with the official advisories
  GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp.
