# php2shell-mitigation

Mitigation, exposure check and patch notes for **PHP2Shell** — **CVE-2026-109618 / CVE-2026-109619**,
two critical PHP vulnerabilities (CVSS v4.0 9.2) linked to `session.upload_progress`.

🇬🇧 [English](#english) · 🇫🇷 [Français](#français)

> **Patch status — last checked 21 Oct 2026, 13:20 UTC: PENDING.**
> php.net announced a critical security release for **21 Oct 2026, 14:00 UTC**. Fixed versions will be
> published by PHP with the release. **Upgrading PHP is the only real fix**; the settings below are a stopgap.

---

## English

### What is it?
On 20 Oct 2026 the PHP security team gave advance notice of a security release fixing **two critical
vulnerabilities, both rated CVSS v4.0 9.2**, scheduled for **Wednesday 21 Oct 2026 at 14:00 UTC**
(or earlier if details leak or exploitation is seen). Full details, affected and fixed versions are to be
published with the release ([php.net](https://www.php.net/)).

**Reported by third parties (not yet confirmed by PHP):**
- The CVE identifiers are **CVE-2026-109618** and **CVE-2026-109619** (watchTowr, via Sansec).
- Unauthenticated remote code execution; an exploit tool named "PHP2Shell" leaked alongside the advisory.
- Root cause is reported as a **heap use-after-free** in the session upload-progress handler
  (`php_session_rfc1867_callback`, `ext/session/session.c`): cached `zval` pointers into session
  HashTables that are freed when the session is re-decoded mid-request.
- A second attack path through `multipart/form-data` parsing is suspected, which disabling upload
  progress would **not** close.
- Cloudflare reported early attacks on 21 Oct 2026 07:43 UTC and deployed WAF rules.

### Affected versions
- **Reported:** every PHP version since **5.4.0** that has `session.upload_progress`, up to and
  including the 24 Sept 2026 releases **8.5.11 / 8.4.26 / 8.3.35 / 8.2.34** (these predate the
  announcement and do not fix it).
- Official list: to be published by PHP with the release.
- **PHP 8.1 and older are end-of-life: no official fix.** Only 8.2+ will be patched.

### Fixed versions
| Branch | Fixed version | Status |
|---|---|---|
| 8.5 | **8.5.12** | released 21 Oct 2026 (security) |
| 8.4 | **8.4.27** | released 21 Oct 2026 (security) |
| 8.3 | **8.3.36** | released 21 Oct 2026 (security) |
| 8.2 | **8.2.35** | released 21 Oct 2026 (security) |
| ≤ 8.1 | none | end-of-life |

Confirmed on [php.net](https://www.php.net/) (security releases of 21 Oct 2026); details in the
[ChangeLog](https://www.php.net/ChangeLog-8.php).

### Temporary mitigation (until you patch)
These settings disable the suspected code path. PHP core developers state that patching is the only
real mitigation, so treat them as defence in depth, **not a fix**.

1. **php.ini** — copy [`mitigation/php.ini.snippet`](mitigation/php.ini.snippet) into your `conf.d`:
   ```ini
   session.upload_progress.enabled = 0
   session.use_strict_mode = 1
   ```
2. **PHP-FPM** — FPM pools can override php.ini. Add to **every** pool
   (see [`mitigation/php-fpm-pool.conf.example`](mitigation/php-fpm-pool.conf.example)):
   ```ini
   php_admin_flag[session.upload_progress.enabled] = off
   php_admin_flag[session.use_strict_mode] = on
   ```
3. **Reload**: `php-fpmX.Y -t && systemctl reload phpX.Y-fpm` (FPM) or restart Apache (mod_php).
   Confirm the values inside a request served by FPM, not only on the CLI.
4. Optional, stronger (breaks file uploads): block `multipart/form-data` at the web server / WAF
   until patched, e.g. nginx:
   ```nginx
   if ($http_content_type ~* "multipart/form-data") { return 403; }
   ```

Side effects: native `$_SESSION` upload-progress bars stop working; normal uploads keep working.
`use_strict_mode` has no effect with session handlers that do not validate IDs (some Redis/DB handlers).

### Check a host
```bash
curl -fsSLO https://raw.githubusercontent.com/Mikael-Lelouch/php2shell-mitigation/main/check-php2shell.sh
less check-php2shell.sh        # read it first
sudo bash check-php2shell.sh
```
Read-only. Finds PHP CLI, PHP-FPM (including per-pool `php_admin_flag`/`php_flag` overrides) and Debian
mod_php runtimes, prints each version and the effective values, then a verdict:

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | `PATCHED` | every runtime runs a fixed version |
| 1 | `MITIGATED` | not patched, but both settings applied everywhere |
| 2 | `EXPOSED` | at least one runtime unpatched and unmitigated |
| 3 | `UNKNOWN` | no PHP found |

Fixed versions are preset (`FIXED_8_2`…`FIXED_8_5` at the top); override if needed, e.g.
`sudo FIXED_8_3=8.3.36 bash check-php2shell.sh`. Containers: `docker exec -i <c> bash -s < check-php2shell.sh`.
Distro backports may keep the old upstream version number — see [PATCHING.md](PATCHING.md).

### Patch
Per-distribution commands (Debian/Ubuntu incl. ondrej/sury, RHEL/Alma/Rocky incl. Remi, Alpine,
official Docker image): **[PATCHING.md](PATCHING.md)**.

---

## Français

### De quoi s'agit-il ?
Le 20 oct. 2026, l'équipe sécurité de PHP a annoncé une version de sécurité corrigeant **deux
vulnérabilités critiques, notées CVSS v4.0 9.2**, prévue le **mercredi 21 oct. 2026 à 14:00 UTC**
(16:00 heure de Paris), voire plus tôt si les détails fuitent ou si une exploitation est observée.
Les détails, versions touchées et versions corrigées seront publiés avec la release ([php.net](https://www.php.net/)).

**Informations rapportées par des tiers (non encore confirmées par PHP) :**
- Identifiants **CVE-2026-109618** et **CVE-2026-109619** (watchTowr, cité par Sansec).
- Exécution de code à distance sans authentification ; un outil d'exploitation nommé « PHP2Shell » a fuité.
- Cause rapportée : **use-after-free** dans le gestionnaire de progression d'upload des sessions
  (`php_session_rfc1867_callback`, `ext/session/session.c`).
- Un second vecteur via le parsing `multipart/form-data` est suspecté ; désactiver l'upload progress
  ne le fermerait **pas**.
- Cloudflare a signalé des premières attaques le 21 oct. 2026 à 07:43 UTC et déployé des règles WAF.

### Versions touchées
- **Rapporté :** toutes les versions depuis **5.4.0** disposant de `session.upload_progress`, y compris
  les versions du 24 sept. 2026 **8.5.11 / 8.4.26 / 8.3.35 / 8.2.34** (antérieures à l'annonce, elles ne corrigent pas).
- Liste officielle : publiée par PHP avec la release.
- **PHP 8.1 et antérieurs sont en fin de vie : aucun correctif officiel.** Seules les branches 8.2+ seront corrigées.

### Versions corrigées
| Branche | Version corrigée | Statut |
|---|---|---|
| 8.5 | **8.5.12** | publiée le 21 oct. 2026 (sécurité) |
| 8.4 | **8.4.27** | publiée le 21 oct. 2026 (sécurité) |
| 8.3 | **8.3.36** | publiée le 21 oct. 2026 (sécurité) |
| 8.2 | **8.2.35** | publiée le 21 oct. 2026 (sécurité) |
| ≤ 8.1 | aucune | fin de vie |

Confirmé sur [php.net](https://www.php.net/) (releases de sécurité du 21 oct. 2026) ; détails dans le
[ChangeLog](https://www.php.net/ChangeLog-8.php).

### Mitigation temporaire (en attendant le patch)
Ces réglages désactivent le chemin de code suspecté. Les développeurs de PHP rappellent que seule la mise
à jour corrige réellement : c'est une **défense en profondeur, pas un correctif**.

1. **php.ini** — copiez [`mitigation/php.ini.snippet`](mitigation/php.ini.snippet) dans `conf.d` :
   ```ini
   session.upload_progress.enabled = 0
   session.use_strict_mode = 1
   ```
2. **PHP-FPM** — les pools peuvent surcharger php.ini. Ajoutez dans **chaque** pool
   (voir [`mitigation/php-fpm-pool.conf.example`](mitigation/php-fpm-pool.conf.example)) :
   ```ini
   php_admin_flag[session.upload_progress.enabled] = off
   php_admin_flag[session.use_strict_mode] = on
   ```
3. **Rechargez** : `php-fpmX.Y -t && systemctl reload phpX.Y-fpm` (FPM) ou redémarrez Apache (mod_php).
   Vérifiez les valeurs dans une requête servie par FPM, pas seulement en CLI.
4. Optionnel, plus radical (casse les uploads) : bloquer `multipart/form-data` au niveau du serveur web / WAF
   jusqu'au patch (exemple nginx ci-dessus).

Effets de bord : les barres de progression d'upload natives via `$_SESSION` ne fonctionnent plus ; les
uploads classiques fonctionnent. `use_strict_mode` est sans effet avec les handlers de session qui ne
valident pas les IDs (certains handlers Redis/BDD).

### Vérifier un hôte
```bash
sudo bash check-php2shell.sh      # lecture seule
```
Le script détecte PHP CLI, PHP-FPM (y compris les surcharges `php_admin_flag`/`php_flag` par pool) et
mod_php (Debian), affiche versions et valeurs effectives, puis un verdict : `PATCHED` (code 0),
`MITIGATED` (1), `EXPOSED` (2), `UNKNOWN` (3). Les versions corrigées sont préremplies
(`FIXED_8_2`…`FIXED_8_5` en tête du script, modifiables en variables d'environnement). Attention : les rétroportages
des distributions peuvent conserver l'ancien numéro de version — voir [PATCHING.md](PATCHING.md).

### Patch
Commandes par distribution (Debian/Ubuntu dont ondrej/sury, RHEL/Alma/Rocky dont Remi, Alpine, image Docker
officielle) : **[PATCHING.md](PATCHING.md)**.

---

## Sources
- PHP — announcement of the critical security release (20 Oct 2026): <https://www.php.net/>
- PHP ChangeLog: <https://www.php.net/ChangeLog-8.php> · Downloads: <https://www.php.net/downloads.php>
- php-src security advisories: <https://github.com/php/php-src/security/advisories>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2026-109618> · <https://nvd.nist.gov/vuln/detail/CVE-2026-109619>
- Sansec — *Critical PHP RCE: CVE-2026-109618 and CVE-2026-109619*: <https://sansec.io/research/php2shell>
- Flare — *A critical PHP vulnerability: what we did and what you should do*: <https://flareapp.io/blog/a-critical-php-vulnerability-what-we-did-and-what-you-should-do>

## Disclaimer
Provided as-is, without warranty. The mitigations reduce exposure but do not replace the official patch.
This repository contains no exploit code.

## License
[MIT](LICENSE) © 2026 Mikael Lelouch
