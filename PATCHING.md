# Patching PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

> **Status (22 Oct 2026): official fix released.** php.net published security releases on
> 21 October 2026: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**
> ([notice](https://www.php.net/archive/2026.php#2026-10-21-1), [ChangeLog](https://www.php.net/ChangeLog-8.php)).
> Vulnerable: **< 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12** (both
> [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and
> [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)).
>
> PHP 8.1 and older get no release, but the PHP security team published **minimal source backports
> for 7.4, 8.0 and 8.1** ([below](#end-of-life-branches-74--80--81-official-source-backports)).
> Linux distributions and LTS vendors received the patches in advance: check your vendor first.

These versions are preset at the top of `check-php2shell.sh` (`FIXED_8_2` … `FIXED_8_5`);
override them with environment variables if needed, then re-run the check.

**Distribution backports:** Debian, Ubuntu (main archive), RHEL/AppStream and Alpine often backport
security fixes *without* changing the upstream version number (e.g. `8.2.x-1+deb12uN`). Example seen
on Ubuntu 24.04: the fix is in package `8.3.6-0ubuntu0.24.04.13` (changelog dated 19 Oct 2026) while
`php -r 'echo PHP_VERSION;'` still prints `8.3.6`. `PHP_VERSION` therefore cannot tell you whether you
are patched: `check-php2shell.sh` reads the changelog of the package that owns each binary (`dpkg`,
`rpm`) and counts the runtime as patched when it lists **both** `CVE-2026-109618` and
`CVE-2026-109619`. Alpine ships no local changelog: use the Alpine secdb.

After upgrading, **restart** (not only reload) PHP-FPM / Apache / php-cgi / FrankenPHP / LiteSpeed so
every worker runs the new binary, then re-run `check-php2shell.sh`. A package update does not
restart the workers on every distribution, and until it does the vulnerable code stays in memory:
the script reports `EXPOSED (restart required)` while any process runs a binary that was replaced on
disk (run it as root).

---

## Debian / Ubuntu

### Distribution packages
```bash
sudo apt-get update
apt list --upgradable 2>/dev/null | grep -i php
sudo apt-get install --only-upgrade 'php*'
sudo systemctl restart 'php*-fpm'       # and/or: sudo systemctl restart apache2 (mod_php)
# confirm the fix is in the INSTALLED package changelog (local, no network); both ids must be listed:
zgrep -hE '^\s+- CVE-2026-10961[89]' /usr/share/doc/php8.2-common/changelog.Debian.gz   # adjust to your version
# before installing, the candidate's changelog:  apt-get changelog php8.2-common | grep -iE 'CVE-2026-10961[89]'
```
Expected output once fixed (two lines, one per CVE):
```
    - CVE-2026-109618
    - CVE-2026-109619
```

### ondrej/php PPA (Ubuntu) / packages.sury.org (Debian)
```bash
sudo apt-get update
apt-cache policy php8.3-fpm             # check the candidate is the fixed upstream version
sudo apt-get install --only-upgrade 'php8.3*'   # repeat for every installed X.Y
sudo systemctl restart php8.3-fpm
```

## RHEL / AlmaLinux / Rocky Linux

### Distribution (AppStream) packages
```bash
sudo dnf check-update 'php*'
sudo dnf update 'php*'
sudo systemctl restart php-fpm        # and/or: sudo systemctl restart httpd
```

### Remi repository (`rpms.remirepo.net`)
> **php.net (21 Oct 2026):** "If you rely on the volunteer-maintained rpms.remirepo.net, we urge you
> to switch to distribution packages or build from source, so you can immediately apply updates.
> The repo will not have updates today." Until Remi ships the fix, apply the
> [interim measures](README.md#if-you-cannot-update-immediately-official-interim-measures) and
> move to AppStream packages or a source build. When Remi updates are available:

```bash
# module stream (php:remi-8.3 etc.)
sudo dnf clean metadata
sudo dnf update 'php*'
sudo systemctl restart php-fpm        # and/or: sudo systemctl restart httpd

# parallel SCL installs (php83-php-*, php84-php-*)
sudo dnf update 'php83-php*'
sudo systemctl restart php83-php-fpm
```

## SUSE Linux Enterprise Server (SLES) / openSUSE

> **Validation status.** `check-php2shell.sh` and the commands below follow SUSE's packaging conventions
> (RPM, `php7` / `php8` packages, `/etc/php7` or `/etc/php8`, Apache module read from `LoadModule`). They
> were **not validated on a real SLES host**: the environment this was written in could not reach any
> SUSE repository. The script's SUSE-style code paths are covered by tests that use stubs shaped after those
> conventions, which test the logic, not SLES itself. If a path differs on your hosts, open an issue with the
> output of `php --ini`, `rpm -qa 'php*' 'apache2-mod_php*'` and `grep -r LoadModule /etc/apache2 | grep -i php`.

On SLES 15 PHP comes from the **Web and Scripting Module**; enable it first if the packages are missing:
```bash
sudo SUSEConnect -l                                          # modules and their state
sudo SUSEConnect -p sle-module-web-scripting/15.6/x86_64     # adjust the service pack / architecture
```
Then update from the maintenance channel and restart:
```bash
sudo zypper refresh
zypper list-patches --cve=CVE-2026-109618     # pending patches for each CVE; empty = none pending
zypper list-patches --cve=CVE-2026-109619     #   (already installed, or none released for your service pack)
sudo zypper patch                             # all pending patches; or: sudo zypper patch --cve=CVE-2026-109618
sudo zypper ps -s                             # processes still running pre-update files, and their service
sudo systemctl restart php-fpm apache2        # whichever you run; then re-run the check
```
SUSE ships the fix as a patch on the **existing** package version, so `PHP_VERSION` does not move. Confirm
from the installed package, not from the version number (works for any RPM distribution):
```bash
rpm -q --changelog "$(rpm -qf "$(readlink -f /usr/bin/php)")" | grep -E 'CVE-2026-10961[89]'
```
Both ids must be listed; this is what `check-php2shell.sh` does for each binary and for the Apache module.
SUSE also tracks each CVE on its security page (`https://www.suse.com/security/cve/CVE-2026-109618.html`),
which shows which products and service packs are affected and fixed.

Layout notes for the mitigation files on SUSE-style systems (check with `php --ini` / `php-fpm -i`):
- `php.ini` per SAPI under `/etc/php8/{cli,apache2,fpm,cgi}/`, drop-ins in the scan directory that
  `php --ini` prints ("Scan for additional .ini files in").
- FPM: `/etc/php8/fpm/php-fpm.d/`. If only `*.default` templates are there, FPM loads nothing: copy one to
  `www.conf` first (the check script reports a lone template).
- Apache: put [`mitigation/apache.conf.example`](mitigation/apache.conf.example) in `/etc/apache2/conf.d/`,
  then `apache2ctl configtest && systemctl restart apache2`. PHP 7 names its module `mod_php7.c`, PHP 8
  `mod_php.c`: the example covers both.

## Alpine Linux
```bash
apk update
apk version -l '<' | grep -i php          # show outdated php packages
apk upgrade 'php83*'                      # or php82* / php84* / php85*
rc-service php-fpm83 restart              # OpenRC; in containers restart the container
```
Alpine stable branches may ship the fix later than upstream; check <https://security.alpinelinux.org/>.

## Docker — official `php` image
The image tag pins the PHP version. Bump the tag to the fixed release and rebuild **without cache**:

```dockerfile
# Before
FROM php:8.3.35-fpm
# After
FROM php:8.3.36-fpm        # 8.2.35 / 8.4.27 / 8.5.12 for the other branches
```
```bash
docker build --pull --no-cache -t myapp:php-fixed .
docker compose up -d --force-recreate
docker run --rm myapp:php-fixed php -v
```
Floating tags (`php:8.3-fpm`, `php:8.3-apache`) are rebuilt by Docker Official Images shortly after
upstream releases: `docker pull` the tag, check `php -v`, then rebuild/recreate.
Check a container with: `docker exec -i <container> bash -s < check-php2shell.sh`
(on Alpine-based images install bash first, or run the checks manually).

## From source (supported branches)
```bash
# https://www.php.net/downloads.php - verify the tarball signature / checksum
curl -fLO https://www.php.net/distributions/php-8.4.27.tar.xz
tar xf php-8.4.27.tar.xz && cd php-8.4.27
./configure <your usual flags> && make -j"$(nproc)" && sudo make install
sudo systemctl restart php-fpm   # or your service / web server
php -v
```
Same for 8.2.35, 8.3.36 and 8.5.12. Windows source and binaries are on the same downloads page.

## End-of-life branches (7.4 / 8.0 / 8.1): official source backports
PHP 8.1 and older no longer receive releases. Prefer, in order: your distribution / LTS vendor's
backported packages, an upgrade to a supported branch, or the official minimal source backports
published by the PHP security team:

| Branch | Backport branch |
|---|---|
| 7.4 | [`PHP-7.4-CVE-2026-109618-109619`](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619) |
| 8.0 | [`PHP-8.0-CVE-2026-109618-109619`](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619) |
| 8.1 | [`PHP-8.1-CVE-2026-109618-109619`](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619) |

```bash
# example for 8.1 (replace 8.1 with 8.0 or 7.4)
git clone --depth 1 -b PHP-8.1-CVE-2026-109618-109619 https://github.com/php/php-src.git php-8.1-cve
cd php-8.1-cve
./buildconf --force
./configure <the flags of your current build>   # php -i | grep -i "configure command"
make -j"$(nproc)"
sudo make install
sudo systemctl restart php-fpm   # or your service / web server
```
The backport branches keep the version string of their base (`8.1.34`, `8.0.30`, and `7.4.31-dev`
on the 7.4 branch), so `check-php2shell.sh` cannot tell a source build apart from an unpatched one and
reports end-of-life runtimes as `EOL-VERIFY` (exit 3). Once you have confirmed the backport is installed,
run it with `PHP2SHELL_EOL_BACKPORTED=1`. EOL runtimes installed from a vendor package (e.g. Ubuntu ESM,
Debian LTS) are resolved automatically from the package changelog.
