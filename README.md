# php2shell-mitigation

Exposure check, interim mitigation and patch notes for **PHP2Shell**: **CVE-2026-109618** and
**CVE-2026-109619**, two critical unauthenticated remote code execution vulnerabilities in PHP,
both rated **CVSS v4.0 9.2** by the PHP security team.

🇬🇧 [English](#english) · 🇫🇷 [Français](#français)

> **Status (22 Oct 2026): OFFICIAL FIX RELEASED.** PHP **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** were
> published on 21 Oct 2026. Official minimal source backports exist for **7.4 / 8.0 / 8.1**.
> **Update now.** In PHP's own words: *"There are no complete mitigations, updating is the only safe choice."*
> The settings in this repository only reduce exposure to specific attack paths; they do not make an
> installation safe.

---

## English

### The vulnerabilities (official)
| CVE | Advisory | Title | CVSS v4.0 | Weaknesses |
|---|---|---|---|---|
| **CVE-2026-109618** | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | RCE via OOM corruption | **9.2** critical | CWE-416, 755, 824, 1325, 1419 |
| **CVE-2026-109619** | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | RCE via stale global state | **9.2** critical | CWE-416, 755, 824, 1325, 1419 |

Vector (both): `CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`

- **CVE-2026-109618 – RCE via OOM corruption.** PHP uses `longjmp()` to abort a request on
  out-of-memory. In some contexts request memory is reachable before it is fully initialised; an
  allocation failure at that point leaves it in an invalid state that request shutdown then reads.
  Multipart parsing can be driven to OOM while staying within apparent limits (bodies without a usable
  `Content-Length`, unlimited headers per part, empty file controls and nested field names).
  The fix replaces `longjmp()` on OOM with a delayed "soft OOM" and an immediate "hard OOM" (`_exit()`).
- **CVE-2026-109619 – RCE via stale global state (use-after-free).** Request-owned global state
  (error, session, object, extension state) can survive after the request heap is freed. A later
  request on the **same worker** can use it before normal initialisation resets it. Confirmed cases:
  the PHP 8.5 **fatal error backtrace** state (`fatal_error_backtraces`) and the **session upload
  progress** lifecycle. INI diagnostics raised before request initialisation are a confirmed consumer.

### Who is affected
Per php.net: **all PHP installations serving web requests** — PHP-FPM, Apache mod_php, php-cgi,
FrankenPHP and LiteSpeed. Vulnerable ranges: **< 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12**, and the
end-of-life branches unless they carry a backport.

| SAPI | Exposure according to the advisories |
|---|---|
| **Apache mod_php** | **Highest risk.** Complete unauthenticated RCE validated over HTTP, triggered before any application code runs. |
| **PHP-FPM** | Susceptible. 109619 session-lifecycle RCE validated on FPM (needs a suitable application operation); 109618 susceptible by source analysis. |
| **FrankenPHP** | Likely susceptible (source analysis). |
| **LiteSpeed (LSAPI)** | Likely susceptible / conditional candidate (unvalidated). |

### Fixed versions
| Branch | Fixed in | Notes |
|---|---|---|
| 8.5 | **8.5.12** | released 21 Oct 2026 |
| 8.4 | **8.4.27** | released 21 Oct 2026 |
| 8.3 | **8.3.36** | released 21 Oct 2026 |
| 8.2 | **8.2.35** | released 21 Oct 2026 |
| 8.1 / 8.0 / 7.4 | official **source backport** branch | end-of-life: no release; see [PATCHING.md](PATCHING.md#end-of-life-branches-74--80--81-official-source-backports) |

Linux distributions and LTS vendors received the patches in advance: check your vendor. Distro
packages may keep the old version number (see [PATCHING.md](PATCHING.md)): e.g. Ubuntu 24.04 ships the
fix in `8.3.6-0ubuntu0.24.04.13` while `PHP_VERSION` still reads `8.3.6`. The Remi repository
(`rpms.remirepo.net`) had **no update on 21 Oct**; php.net advises switching to distribution packages or
building from source.

Per-advisory nuances (from the advisories, not covered by the table above):
- **CVE-2026-109619 on FPM:** the INI-diagnostic path is conditional: it needs a frontend that passes
  `PHP_VALUE` / `PHP_ADMIN_VALUE` triggering a diagnostic.
- **CVE-2026-109619 on FrankenPHP:** no early consumer was established in its default configuration;
  the advisory notes this does not make it immune.
- **CVE-2026-109619 on mod_php:** early INI consumption can come from `.htaccess` and directory-level
  `php_value` / `php_admin_*` settings.

### If you cannot update immediately (official interim measures)
These reduce exposure to specific attack paths **but do not make an installation safe**. Apply them
administratively (`php.ini`, FPM pool `php_admin_value`/`php_admin_flag`, Apache config), **not** with
`ini_set()` or `.user.ini`, then **restart every worker**.

**CVE-2026-109618 (OOM corruption)**
1. `memory_limit = -1`, set so applications cannot override it (`php_admin_value` in the FPM pool or
   Apache config). Check that no pool, directory or application setting puts a finite limit back.
   An underlying allocation failure can still reach the vulnerable path.
2. Low `post_max_size`: **8M** if the application needs no uploads, **32M** if it does.
   Keep `upload_max_filesize` **below** `post_max_size`.
3. Enforce limits at the web server / proxy: decoded request size, input field count, multipart part
   count, header count and nesting depth — **including requests without a usable `Content-Length`**.
   If the application does not use `multipart/form-data`, block it at the frontend.
   Lowering `max_input_nesting_level` / `max_input_vars` / `max_file_uploads` also helps.
4. Use a **container or cgroup memory limit** (`memory.max`) as an availability boundary, preferably
   one that kills only the affected worker (a per-container kill can take the FPM master with it).
5. **Do not** use `RLIMIT_AS` or `RLIMIT_DATA` (e.g. `ulimit -v`, systemd `LimitAS=`/`LimitDATA=`):
   they make `mmap()` fail and trigger the vulnerable path.

**CVE-2026-109619 (stale global state)**
1. `session.upload_progress.enabled = 0` via `php.ini`, FPM pool or server config applied before request
   parsing; restart every worker. Blocks the confirmed session paths only.
   PHP suggests keeping it off even after patching if you don't use the feature.
2. **PHP 8.5 only:** `fatal_error_backtraces = 0`; restart every worker. Blocks the confirmed fatal
   backtrace path only.
3. Remove invalid or deprecated settings applied **per request** that emit diagnostics before
   initialisation (`.htaccess` / Apache `php_value`, nginx `fastcgi_param PHP_VALUE`/`PHP_ADMIN_VALUE`,
   obsolete directives such as `auto_detect_line_endings`, `mbstring.internal_encoding`,
   `iconv.*_encoding`, legacy `assert.*`…). Hiding diagnostics with `error_reporting`, `display_errors`
   or `@` **does not help**.
4. Fix attacker-reachable fatal errors and execution timeouts (callbacks, upload/import processing,
   cleanup, error pages, destructors…).
5. Optional, if performance allows: `pm.max_requests = 1` (FPM) so a worker never serves a second request.

Ready-to-use files:
- [`mitigation/php.ini.snippet`](mitigation/php.ini.snippet) – `conf.d` drop-in (all branches)
- [`mitigation/php85-only.ini`](mitigation/php85-only.ini) – `fatal_error_backtraces = 0`, **PHP 8.5 only**
- [`mitigation/php-fpm-pool.conf.example`](mitigation/php-fpm-pool.conf.example) – per-pool `php_admin_*` lines
- [`mitigation/nginx.conf.example`](mitigation/nginx.conf.example) – body/header limits (chunked bodies included) and multipart block
- [`mitigation/apache.conf.example`](mitigation/apache.conf.example) – `LimitRequest*`, multipart block and mod_php `php_admin_*`

The nginx and Apache files were checked on a real nginx 1.24 (in front of PHP-FPM) and a real Apache 2.4 with
mod_php: multipart refused (415 / 403), a 9 MB body refused with **413 both with a `Content-Length` and chunked**
(no `Content-Length`), normal requests unaffected, and on Apache `ini_set()` cannot override the `php_admin_*` values.

> `session.use_strict_mode = 1` is **not** part of the official advisory. It is general session
> hardening only and is no longer required by the check script.

### Check a host
```bash
curl -fsSLO https://raw.githubusercontent.com/Mikael-Lelouch/php2shell-mitigation/main/check-php2shell.sh
less check-php2shell.sh        # read it first
sudo bash check-php2shell.sh
```
Read-only. Finds PHP CLI, PHP-FPM (every pool, with its `php_admin_*`/`php_*` overrides as reported by
`php-fpm -tt`), php-cgi and Debian mod_php runtimes, plus LiteSpeed `lsphp` and FrankenPHP (version check
only: their settings are not evaluated). It prints each version and the effective
`session.upload_progress.enabled`, `memory_limit`, `fatal_error_backtraces` (8.5), `post_max_size`,
`upload_max_filesize`, then a verdict:

| Exit | Verdict | Meaning |
|---|---|---|
| 0 | `PATCHED` | every runtime runs a fixed upstream version **or** a vendor backport (see below) |
| 1 | `MITIGATED` | not patched, but the official interim settings are applied everywhere (`session.upload_progress.enabled=0` **and** `memory_limit=-1`, plus `fatal_error_backtraces=0` where that directive exists). Still unsafe: update. |
| 2 | `EXPOSED` | at least one runtime unpatched and unmitigated, **or** a process still runs a PHP binary that was replaced on disk after it started (update without restart) |
| 3 | `UNKNOWN` | no PHP found, **or** a runtime that cannot be classified: end-of-life 7.4/8.0/8.1 without a known backport (`EOL-VERIFY`), or a branch newer than the script knows (`UNKNOWN-BRANCH`, e.g. 8.6) |
| 64 | – | usage error (unknown option) |

Options: `-q` (only the verdict), `-h` (help), `-V` (version).

- **Vendor backports.** Debian, Ubuntu and RHEL fix PHP without changing the upstream version number. On
  `dpkg` and `rpm` systems the script reads the changelog of the package that owns each binary and counts the
  runtime as `PATCHED` when **both** `CVE-2026-109618` and `CVE-2026-109619` are listed (one id is not enough:
  a changelog can name a patch file `CVE-2026-109618_109619.patch`). Alpine has no local changelog: check
  <https://security.alpinelinux.org/>.
- **SUSE Linux Enterprise Server.** RPM changelogs are read as above; Apache's PHP module is located from its
  `LoadModule php*_module` lines (so `mod_php8.so`, `libphp*.so`… all work) and a `/etc/php<N>/apache2/php.ini`
  layout is evaluated like the Debian one. See [PATCHING.md](PATCHING.md#suse-linux-enterprise-server-sles--opensuse)
  for the `zypper` steps. **Not validated on a real SLES host** (tested with stubs only): please report differences.
- **Restart check.** A package update leaves the old code in memory until the workers restart. The script
  flags running `php-fpm` / `php-cgi` / `lsphp` / `frankenphp` processes (and Apache processes with mod_php)
  whose binary or library was replaced on disk. Run it as root to see them.
- **Pre-releases.** `8.5.12RC1`, `8.3.36-dev`… are not counted as the fixed release even though the number matches.
- End-of-life runtimes: if you built the official backport, re-run with `PHP2SHELL_EOL_BACKPORTED=1` to
  count them as patched.
- Fixed versions are preset (`FIXED_8_2`…`FIXED_8_5`); override with environment variables if needed, and set
  `FIXED_8_6` etc. to classify a newer branch.
- Containers: `docker exec -i <c> bash -s < check-php2shell.sh` (needs bash 4+; on Alpine `apk add bash`).
- The script cannot see `PHP_VALUE` sent by nginx/Apache to FPM, `.htaccess` files or cgroup limits:
  review those by hand.

### Tests
```bash
bash tests/run-tests.sh      # hermetic: PHP, dpkg/rpm and /etc are stubbed, no PHP install needed
shellcheck check-php2shell.sh tests/run-tests.sh
```
CI runs both, plus an integration job against a real `php-fpm` / `php-cgi` install.

### Patch
Per-distribution commands, Docker, building from source and the EOL backport branches:
**[PATCHING.md](PATCHING.md)**.

---

## Français

### Les vulnérabilités (officiel)
| CVE | Avis | Titre | CVSS v4.0 |
|---|---|---|---|
| **CVE-2026-109618** | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | RCE via OOM corruption (corruption sur manque de mémoire) | **9.2** critique |
| **CVE-2026-109619** | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | RCE via stale global state (état global périmé, use-after-free) | **9.2** critique |

- **CVE-2026-109618.** PHP utilise `longjmp()` pour interrompre une requête en cas de manque de mémoire
  (OOM). Dans certains contextes, la mémoire de la requête est accessible avant d'être entièrement
  initialisée ; un échec d'allocation à ce moment la laisse dans un état invalide, que l'arrêt de la
  requête lit ensuite. Le parsing multipart permet d'atteindre l'OOM tout en restant sous les limites
  apparentes (corps sans `Content-Length` exploitable, en-têtes illimités par partie, champs fichier vides,
  noms de champs imbriqués). Le correctif remplace `longjmp()` par un « soft OOM » différé et un
  « hard OOM » immédiat (`_exit()`).
- **CVE-2026-109619.** De l'état global appartenant à une requête (erreurs, session, objets, extensions)
  peut survivre à la libération de la mémoire de la requête. Une requête suivante traitée par le
  **même worker** peut l'utiliser avant que l'initialisation normale ne le réinitialise. Cas confirmés :
  le backtrace des erreurs fatales de PHP 8.5 (`fatal_error_backtraces`) et le cycle de vie de la
  **progression d'upload des sessions**. Les diagnostics INI émis avant l'initialisation de la requête
  sont un déclencheur confirmé.

### Qui est concerné
Selon php.net : **toutes les installations PHP qui servent des requêtes web** — PHP-FPM, Apache mod_php,
php-cgi, FrankenPHP et LiteSpeed. Versions vulnérables : **< 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12**, ainsi
que les branches en fin de vie sans rétroportage.

| SAPI | Exposition selon les avis |
|---|---|
| **Apache mod_php** | **Risque maximal.** RCE complète sans authentification validée en HTTP, avant tout code applicatif. |
| **PHP-FPM** | Vulnérable. RCE validée sur FPM pour 109619 (cycle de session, nécessite une opération applicative adaptée) ; 109618 vulnérable d'après l'analyse du code. |
| **FrankenPHP** | Probablement vulnérable (analyse du code). |
| **LiteSpeed (LSAPI)** | Probablement vulnérable / candidat conditionnel (non validé). |

### Versions corrigées
| Branche | Corrigée en | Remarques |
|---|---|---|
| 8.5 | **8.5.12** | publiée le 21 oct. 2026 |
| 8.4 | **8.4.27** | publiée le 21 oct. 2026 |
| 8.3 | **8.3.36** | publiée le 21 oct. 2026 |
| 8.2 | **8.2.35** | publiée le 21 oct. 2026 |
| 8.1 / 8.0 / 7.4 | **rétroportage officiel en source** | fin de vie, pas de release : voir [PATCHING.md](PATCHING.md#end-of-life-branches-74--80--81-official-source-backports) |

Les distributions Linux et les fournisseurs LTS ont reçu les correctifs en avance : vérifiez auprès de
votre fournisseur. Leurs paquets peuvent garder l'ancien numéro de version (voir [PATCHING.md](PATCHING.md)) :
par exemple Ubuntu 24.04 livre le correctif dans `8.3.6-0ubuntu0.24.04.13` alors que `PHP_VERSION` affiche
toujours `8.3.6`. Le dépôt Remi (`rpms.remirepo.net`) n'a **pas** été mis à jour le 21 oct. ; php.net conseille
de passer aux paquets de la distribution ou de compiler depuis les sources.

Nuances par avis (issues des avis, absentes du tableau ci-dessus) :
- **CVE-2026-109619 sur FPM :** le chemin par diagnostic INI est conditionnel : il faut un frontal qui transmet
  des `PHP_VALUE` / `PHP_ADMIN_VALUE` provoquant un diagnostic.
- **CVE-2026-109619 sur FrankenPHP :** aucun consommateur précoce établi dans la configuration par défaut ;
  l'avis précise que cela ne le rend pas immunisé.
- **CVE-2026-109619 sur mod_php :** la consommation précoce de l'INI peut venir de `.htaccess` et des
  réglages `php_value` / `php_admin_*` au niveau répertoire.

### Si vous ne pouvez pas mettre à jour tout de suite (mesures officielles)
Elles réduisent l'exposition à certains chemins d'attaque **sans rendre l'installation sûre**. À appliquer
côté administrateur (`php.ini`, `php_admin_value`/`php_admin_flag` du pool FPM, configuration Apache),
**pas** via `ini_set()` ni `.user.ini`, puis **redémarrer tous les workers**.

**CVE-2026-109618 (corruption sur OOM)**
1. `memory_limit = -1`, non surchargeable par l'application (`php_admin_value` dans le pool FPM ou la
   configuration Apache). Vérifiez qu'aucun pool, répertoire ou réglage applicatif ne remet une limite finie.
2. `post_max_size` bas : **8M** sans upload, **32M** si l'application a besoin d'uploads.
   `upload_max_filesize` doit rester **inférieur** à `post_max_size`.
3. Limites au niveau du serveur web / proxy : taille décodée de la requête, nombre de champs, de parties
   multipart, d'en-têtes et profondeur d'imbrication, **y compris pour les requêtes sans `Content-Length`
   exploitable**. Si l'application n'utilise pas `multipart/form-data`, bloquez-le en frontal.
4. Une **limite mémoire conteneur ou cgroup** (`memory.max`) comme garde-fou de disponibilité, de
   préférence en ne tuant que le worker concerné.
5. **Ne pas** utiliser `RLIMIT_AS` ni `RLIMIT_DATA` (`ulimit -v`, `LimitAS=`/`LimitDATA=` systemd) :
   ils font échouer `mmap()` et déclenchent le chemin vulnérable.

**CVE-2026-109619 (état global périmé)**
1. `session.upload_progress.enabled = 0` dans `php.ini`, le pool FPM ou la configuration serveur
   appliquée avant le parsing de la requête ; redémarrez tous les workers. Ne bloque que les chemins
   de session confirmés. PHP suggère de le laisser désactivé même après le patch si vous n'utilisez pas
   cette fonction.
2. **PHP 8.5 uniquement :** `fatal_error_backtraces = 0` ; redémarrez tous les workers.
3. Supprimez les réglages INI invalides ou obsolètes appliqués **par requête** qui émettent des
   diagnostics avant l'initialisation (`.htaccess` / `php_value` Apache, `fastcgi_param PHP_VALUE` nginx,
   directives obsolètes…). Masquer les diagnostics avec `error_reporting`, `display_errors` ou `@`
   **ne sert à rien**.
4. Corrigez les erreurs fatales et dépassements de temps d'exécution atteignables par un attaquant.
5. Optionnel si les performances le permettent : `pm.max_requests = 1` (FPM).

Fichiers prêts à l'emploi : [`mitigation/php.ini.snippet`](mitigation/php.ini.snippet),
[`mitigation/php85-only.ini`](mitigation/php85-only.ini) (**PHP 8.5 uniquement**),
[`mitigation/php-fpm-pool.conf.example`](mitigation/php-fpm-pool.conf.example),
[`mitigation/nginx.conf.example`](mitigation/nginx.conf.example) et
[`mitigation/apache.conf.example`](mitigation/apache.conf.example) (limites de corps et d'en-têtes, blocage
multipart). Ces deux derniers ont été testés sur un vrai nginx 1.24 devant PHP-FPM et un vrai Apache 2.4 avec
mod_php : multipart refusé (415 / 403), corps de 9 Mo refusé en **413 avec `Content-Length` comme en chunked**
(sans `Content-Length`), requêtes normales intactes.

> `session.use_strict_mode = 1` **ne fait pas partie** de l'avis officiel : simple durcissement général
> des sessions, il n'est plus exigé par le script.

### Vérifier un hôte
```bash
sudo bash check-php2shell.sh      # lecture seule
```
Le script détecte PHP CLI, PHP-FPM (chaque pool, avec ses surcharges `php_admin_*`/`php_*` telles que
rapportées par `php-fpm -tt`), php-cgi et mod_php (Debian), ainsi que `lsphp` (LiteSpeed) et FrankenPHP
(version uniquement), affiche les versions et les valeurs effectives, puis un verdict :
`PATCHED` (0), `MITIGATED` (1 : `session.upload_progress.enabled=0` **et** `memory_limit=-1`, plus
`fatal_error_backtraces=0` là où la directive existe — toujours à mettre à jour), `EXPOSED` (2), `UNKNOWN` (3 :
aucun PHP, ou runtime non classable : fin de vie 7.4/8.0/8.1 sans rétroportage connu, `EOL-VERIFY`, ou branche
plus récente que le script, `UNKNOWN-BRANCH`, par ex. 8.6). Code 64 : option inconnue. Options : `-q`, `-h`, `-V`.

- **Rétroportages des distributions.** Debian, Ubuntu et RHEL corrigent PHP sans changer le numéro upstream.
  Avec `dpkg` et `rpm`, le script lit le changelog du paquet propriétaire de chaque binaire et compte le runtime
  comme `PATCHED` quand **les deux** `CVE-2026-109618` et `CVE-2026-109619` y figurent (un seul identifiant ne
  suffit pas : un changelog peut nommer un fichier `CVE-2026-109618_109619.patch`). Alpine n'a pas de changelog
  local : voir <https://security.alpinelinux.org/>.
- **SUSE Linux Enterprise Server.** Les changelogs RPM sont lus comme ci-dessus ; le module PHP d'Apache est
  localisé à partir de ses lignes `LoadModule php*_module` (donc `mod_php8.so`, `libphp*.so`… fonctionnent) et
  une disposition `/etc/php<N>/apache2/php.ini` est évaluée comme celle de Debian. Voir
  [PATCHING.md](PATCHING.md#suse-linux-enterprise-server-sles--opensuse) pour les étapes `zypper`.
  **Non validé sur un vrai hôte SLES** (testé avec des simulations uniquement) : merci de signaler les écarts.
- **Contrôle du redémarrage.** Une mise à jour laisse l'ancien code en mémoire tant que les workers ne sont pas
  redémarrés. Le script signale les processus `php-fpm` / `php-cgi` / `lsphp` / `frankenphp` (et Apache avec
  mod_php) dont le binaire ou la bibliothèque a été remplacé sur disque : verdict `EXPOSED`. À lancer en root.
- **Pré-versions.** `8.5.12RC1`, `8.3.36-dev`… ne comptent pas comme la version corrigée.
- Si vous avez installé le rétroportage officiel : `PHP2SHELL_EOL_BACKPORTED=1`. `FIXED_8_6` etc. permettent de
  classer une branche plus récente.
- Le script ne voit ni les `PHP_VALUE` envoyés par nginx/Apache, ni les `.htaccess`, ni les limites cgroup : à
  vérifier à la main.

### Tests
```bash
bash tests/run-tests.sh      # hermétique : PHP, dpkg/rpm et /etc simulés, aucun PHP requis
shellcheck check-php2shell.sh tests/run-tests.sh
```
La CI lance les deux, plus un job d'intégration sur un vrai `php-fpm` / `php-cgi`.

### Patch
Commandes par distribution, Docker, compilation et branches de rétroportage : **[PATCHING.md](PATCHING.md)**.

---

## Sources
- php.net security notice (21 Oct 2026): <https://www.php.net/archive/2026.php#2026-10-21-1>
- GHSA-w8hw-w9fx-j79w / CVE-2026-109618 – RCE via OOM corruption: <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- GHSA-6wmf-4rv5-p3rp / CVE-2026-109619 – RCE via stale global state: <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- PHP ChangeLog: <https://www.php.net/ChangeLog-8.php> · Downloads: <https://www.php.net/downloads.php>
- Official EOL source backports:
  [PHP 7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619) ·
  [PHP 8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619) ·
  [PHP 8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619)

## Disclaimer
Provided as-is, without warranty. The mitigations reduce exposure but do not replace the official patch.
This repository contains no exploit code.

## License
[MIT](LICENSE) © 2026 Mikael Lelouch
