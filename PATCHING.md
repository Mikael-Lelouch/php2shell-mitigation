# Patching PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

> **Status (22 Oct 2026):** the official fix is **out**. php.net published security releases on
> 21 October 2026: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**. See <https://www.php.net/> and
> <https://www.php.net/ChangeLog-8.php>.
> The 24 September 2026 releases (8.5.11 / 8.4.26 / 8.3.35 / 8.2.34) predate the announcement
> and do not contain the fix.
>
> PHP 8.1 and older are end-of-life and will not receive an official fix: move to a supported branch.

These versions are preset at the top of `check-php2shell.sh` (`FIXED_8_2` … `FIXED_8_5`);
override them with environment variables if needed, then re-run the check.

**Distribution backports:** Debian, Ubuntu (main archive), RHEL/AppStream and Alpine often backport
security fixes *without* changing the upstream version number (e.g. `8.2.x-1+deb12uN`).
In that case trust your vendor's security advisory (DSA/USN/RHSA/Alpine secdb) and the package
changelog rather than `PHP_VERSION`; the check script compares upstream version numbers only.

Always reload PHP-FPM / restart Apache after upgrading, then re-run `check-php2shell.sh`.

---

## Debian / Ubuntu

### Distribution packages
```bash
sudo apt-get update
apt list --upgradable 2>/dev/null | grep -i php
sudo apt-get install --only-upgrade 'php*'
sudo systemctl reload 'php*-fpm'        # or: sudo systemctl restart apache2 (mod_php)
# confirm the fix is in the package changelog:
apt-get changelog php8.2-common | grep -iE 'CVE-2026-10961[89]'   # adjust to your version
```

### ondrej/php PPA (Ubuntu) / packages.sury.org (Debian)
```bash
sudo apt-get update
apt-cache policy php8.3-fpm             # check the candidate is the fixed upstream version
sudo apt-get install --only-upgrade 'php8.3*'   # repeat for every installed X.Y
sudo systemctl reload php8.3-fpm
```

## RHEL / AlmaLinux / Rocky Linux

### Distribution (AppStream) packages
```bash
sudo dnf check-update 'php*'
sudo dnf update 'php*'
sudo systemctl reload php-fpm
```

### Remi repository (`rpms.remirepo.net`)
> According to Sansec (citing the PHP Foundation, 21 Oct 2026 08:48 UTC), the volunteer-run Remi
> repository **will not publish updates on 21 October**. Expect a delay; apply the mitigations meanwhile.

```bash
# module stream (php:remi-8.3 etc.)
sudo dnf clean metadata
sudo dnf update 'php*'
sudo systemctl reload php-fpm

# parallel SCL installs (php83-php-*, php84-php-*)
sudo dnf update 'php83-php*'
sudo systemctl reload php83-php-fpm
```

## Alpine Linux
```bash
apk update
apk version -l '<' | grep -i php          # show outdated php packages
apk upgrade 'php83*'                      # or php82* / php84* / php85*
rc-service php-fpm83 reload               # OpenRC; in containers restart the container
```
Alpine stable branches may ship the fix later than upstream; check <https://security.alpinelinux.org/>.

## Docker — official `php` image
The image tag pins the PHP version. Bump the tag to the fixed release and rebuild **without cache**:

```dockerfile
# Before
FROM php:8.3.35-fpm
# After (replace with the real fixed version once released)
FROM php:8.3.<FIXED>-fpm
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

## From source
```bash
# after the release, from https://www.php.net/downloads.php (verify signatures)
./configure <your usual flags> && make -j"$(nproc)" && sudo make install
```
