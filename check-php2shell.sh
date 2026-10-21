#!/usr/bin/env bash
# check-php2shell.sh - read-only exposure check for PHP2Shell
#   CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) RCE via OOM corruption
#   CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp) RCE via stale global state
# Official notice: https://www.php.net/archive/2026.php#2026-10-21-1
#
# Inspects every PHP CLI, PHP-FPM and Apache mod_php (Debian layout) runtime it
# can find and reports its version plus the effective values of the official
# interim settings:
#   session.upload_progress.enabled   want 0            (CVE-2026-109619)
#   memory_limit                      want -1           (CVE-2026-109618)
#   fatal_error_backtraces            want 0, PHP 8.5   (CVE-2026-109619)
#   post_max_size                     8M, max 32M       (reported, warning only)
#   upload_max_filesize               < post_max_size   (reported, warning only)
#   session.use_strict_mode           informational only (not in the advisory)
# including per-pool php_admin_value/flag and php_value/flag overrides in
# PHP-FPM pool files, and RLIMIT_AS / RLIMIT_DATA on running FPM processes.
#
# It changes nothing on the host. Run as root for complete FPM results
# (php-fpm -tt, pool files and /proc/<pid>/limits are often root-only).
#
# Exit codes (worst result wins):
#   0  PATCHED     every runtime found runs a fixed PHP version
#   1  MITIGATED   not (all) patched, but every unpatched runtime has the
#                  official interim settings. STILL UNSAFE: update PHP.
#   2  EXPOSED     at least one runtime is unpatched and not mitigated
#   3  UNKNOWN     no PHP runtime found, or an end-of-life runtime (7.4/8.0/8.1
#                  or older) that is not mitigated and whose backport status
#                  cannot be determined from its version ("EOL-VERIFY")
#
# Usage: ./check-php2shell.sh [-q]      (-q: only print the final verdict)
#
# Environment:
#   FIXED_8_2 ... FIXED_8_5    override the fixed version of a branch
#   PHP2SHELL_EOL_BACKPORTED=1 count end-of-life runtimes as patched (only if
#                              you installed the official 7.4/8.0/8.1 source
#                              backport or a vendor backport)
#   PHP2SHELL_BIN_DIRS / PHP2SHELL_SBIN_DIRS
#                              colon-separated dirs that REPLACE the default
#                              search dirs for php / php-fpm binaries
#
# This script cannot see: PHP_VALUE / PHP_ADMIN_VALUE sent by nginx or Apache
# to FPM, .htaccess files, application ini_set() calls, frontend request
# limits or cgroup memory limits. Review those by hand.
#
# Docker: this script does not look inside containers. Run it in each one:
#   docker exec -i <container> bash -s < check-php2shell.sh
#
# License: MIT

set -u

# --------------------------------------------------------------------------
# Fixed versions per branch (php.net security releases of 21 Oct 2026).
# Branches below 8.2 are end-of-life: only source/vendor backports exist.
# --------------------------------------------------------------------------
FIXED_8_2="${FIXED_8_2:-8.2.35}"
FIXED_8_3="${FIXED_8_3:-8.3.36}"
FIXED_8_4="${FIXED_8_4:-8.4.27}"
FIXED_8_5="${FIXED_8_5:-8.5.12}"
EOL_BACKPORTED="${PHP2SHELL_EOL_BACKPORTED:-0}"

QUIET=0
[ "${1:-}" = "-q" ] && QUIET=1

# severity rank: 0 patched, 1 mitigated, 2 eol-verify, 3 exposed
WORST=-1

say() { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }

bump() { # $1 = rank
    if [ "$1" -gt "$WORST" ]; then WORST=$1; fi
}

norm_bool() { # prints 1, 0, n/a or ? for an ini/pool value
    local v
    v=$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '"'"'"' ;')
    case "$v" in
        n/a)                  echo "n/a" ;;
        1|on|true|yes)        echo 1 ;;
        0|off|false|no|none|"") echo 0 ;;
        *)                    echo "?" ;;
    esac
}

norm_val() { # strip quotes/spaces; empty -> ?
    local v
    v=$(printf '%s' "${1:-}" | tr -d '"'"'"' ;')
    [ -n "$v" ] && echo "$v" || echo "?"
}

to_bytes() { # 8M -> 8388608 ; prints "" if not parseable
    local v n u
    v=$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]')
    n=${v%[KMG]}
    u=${v#"$n"}
    case "$n" in ''|*[!0-9-]*) echo ""; return ;; esac
    case "$u" in
        K) echo $((n * 1024)) ;;
        M) echo $((n * 1024 * 1024)) ;;
        G) echo $((n * 1024 * 1024 * 1024)) ;;
        *) echo "$n" ;;
    esac
}

fixed_for() { # $1 = X.Y.Z -> prints fixed version for its branch, "EOL" or ""
    local branch
    branch=$(printf '%s' "$1" | cut -d. -f1,2)
    case "$branch" in
        8.2) echo "$FIXED_8_2" ;;
        8.3) echo "$FIXED_8_3" ;;
        8.4) echo "$FIXED_8_4" ;;
        8.5) echo "$FIXED_8_5" ;;
        8.[6-9]|9.*) echo "" ;;   # newer branches: check upstream yourself
        *)   echo "EOL" ;;
    esac
}

version_ge() { # $1 >= $2 ?
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# evaluate <label> <version> <upload_progress> <memory_limit> <fatal_bt>
#          <post_max_size> <upload_max_filesize> <use_strict_mode> [notes]
evaluate() {
    local label=$1 ver=$2 up=$3 mem=$4 feb=$5 post=$6 upl=$7 strict=$8 extra=${9:-}
    local fixed branch status rank mitigated=0 note="" pb ub
    fixed=$(fixed_for "$ver")
    branch=$(printf '%s' "$ver" | cut -d. -f1,2)

    if [ "$up" = "0" ] && [ "$mem" = "-1" ]; then
        if [ "$branch" != "8.5" ] || [ "$feb" = "0" ]; then mitigated=1; fi
    fi

    if [ "$fixed" = "EOL" ]; then
        if [ "$EOL_BACKPORTED" = "1" ]; then
            status=PATCHED; rank=0; note=" (end-of-life: backport declared via PHP2SHELL_EOL_BACKPORTED=1)"
        elif [ "$mitigated" -eq 1 ]; then
            status=MITIGATED; rank=1; note=" (end-of-life: install the official source backport or a vendor backport)"
        else
            status=EOL-VERIFY; rank=2; note=" (end-of-life: EXPOSED unless it carries the official/vendor backport; verify, see PATCHING.md)"
        fi
    elif [ -n "$fixed" ] && version_ge "$ver" "$fixed"; then
        status=PATCHED; rank=0
    elif [ "$mitigated" -eq 1 ]; then
        status=MITIGATED; rank=1
    else
        status=EXPOSED; rank=3
        [ -z "$fixed" ] && note=" (unknown branch: check upstream)"
    fi
    bump "$rank"

    say "  [$status] $label  PHP $ver$note"
    say "      session.upload_progress.enabled=$up  memory_limit=$mem  fatal_error_backtraces=$feb  post_max_size=$post  upload_max_filesize=$upl  (info: session.use_strict_mode=$strict)"

    [ "$status" = PATCHED ] && [ -z "$extra" ] && return 0
    if [ "$status" != PATCHED ]; then
        [ "$up" != "0" ] && say "      - set session.upload_progress.enabled=0 (CVE-2026-109619)"
        [ "$mem" != "-1" ] && say "      - set memory_limit=-1 administratively (CVE-2026-109618)"
        [ "$branch" = "8.5" ] && [ "$feb" != "0" ] && say "      - PHP 8.5: set fatal_error_backtraces=0 (CVE-2026-109619)"
    fi
    pb=$(to_bytes "$post"); ub=$(to_bytes "$upl")
    if [ -n "$pb" ]; then
        if [ "$pb" -le 0 ]; then
            say "      ! post_max_size=$post means no limit: use 8M (no uploads) or 32M (uploads)"
        elif [ "$pb" -gt $((32 * 1024 * 1024)) ]; then
            say "      ! post_max_size=$post is above the official 32M ceiling (8M if no uploads)"
        fi
        if [ -n "$ub" ] && [ "$pb" -gt 0 ] && [ "$ub" -ge "$pb" ]; then
            say "      ! upload_max_filesize ($upl) must stay below post_max_size ($post)"
        fi
    fi
    [ -n "$extra" ] && say "      ! $extra"
    return 0
}

# ---------------------------------------------------------------- discovery
list_bins() { # $1 = regex for basename, rest = dirs
    local re=$1; shift
    local d f
    for d in "$@"; do
        [ -d "$d" ] || continue
        for f in "$d"/*; do
            if [ ! -f "$f" ] || [ ! -x "$f" ]; then continue; fi
            if printf '%s' "${f##*/}" | grep -Eq "$re"; then
                readlink -f "$f"
            fi
        done
    done | sort -u
}

if [ -n "${PHP2SHELL_BIN_DIRS:-}" ]; then
    IFS=: read -r -a BIN_DIRS <<<"$PHP2SHELL_BIN_DIRS"
else
    BIN_DIRS=(/usr/bin /usr/local/bin /bin)
    for d in /opt/remi/php*/root/usr/bin /opt/cpanel/ea-php*/root/usr/bin /opt/plesk/php/*/bin /opt/alt/php*/usr/bin; do
        [ -d "$d" ] && BIN_DIRS+=("$d")
    done
fi
if [ -n "${PHP2SHELL_SBIN_DIRS:-}" ]; then
    IFS=: read -r -a SBIN_DIRS <<<"$PHP2SHELL_SBIN_DIRS"
else
    SBIN_DIRS=(/usr/sbin /usr/local/sbin /sbin /usr/bin /usr/local/bin)
    for d in /opt/remi/php*/root/usr/sbin /opt/cpanel/ea-php*/root/usr/sbin /opt/plesk/php/*/sbin /opt/alt/php*/usr/sbin; do
        [ -d "$d" ] && SBIN_DIRS+=("$d")
    done
fi

mapfile -t CLI_BINS < <(list_bins '^php([0-9]+(\.[0-9]+)?)?$' "${BIN_DIRS[@]}")
mapfile -t FPM_BINS < <(list_bins '^php-fpm([0-9]+(\.[0-9]+)?)?$' "${SBIN_DIRS[@]}")

# Prints: version|upload_progress|memory_limit|fatal_error_backtraces|post_max_size|upload_max_filesize|use_strict_mode
# (works on PHP 7.x and 8.x; "n/a" when the directive does not exist)
# shellcheck disable=SC2016  # PHP code, must not be expanded by bash
INI_SNIPPET='$g = function ($k) { $v = ini_get($k); return $v === false ? "n/a" : (string) $v; };
echo PHP_VERSION, "|", $g("session.upload_progress.enabled"), "|", $g("memory_limit"), "|", $g("fatal_error_backtraces"), "|", $g("post_max_size"), "|", $g("upload_max_filesize"), "|", $g("session.use_strict_mode");'

# parse_snippet <output> -> sets globals V_VER V_UP V_MEM V_FEB V_POST V_UPL V_ST
parse_snippet() {
    local up feb st
    IFS='|' read -r V_VER up V_MEM feb V_POST V_UPL st <<<"$1"
    V_UP=$(norm_bool "$up"); V_FEB=$(norm_bool "$feb"); V_ST=$(norm_bool "$st")
    V_MEM=$(norm_val "$V_MEM"); V_POST=$(norm_val "$V_POST"); V_UPL=$(norm_val "$V_UPL")
}

# ---------------------------------------------------------------- CLI
say "== PHP CLI (version check; CLI does not serve web requests)"
seen_cli=""
for bin in "${CLI_BINS[@]}"; do
    out=$("$bin" -r "$INI_SNIPPET" 2>/dev/null) || continue
    case "$out" in *"|"*"|"*"|"*"|"*"|"*"|"*) ;; *) continue ;; esac
    case " $seen_cli " in *" $bin "*) continue ;; esac
    seen_cli="$seen_cli $bin"
    parse_snippet "$out"
    evaluate "cli:$bin" "$V_VER" "$V_UP" "$V_MEM" "$V_FEB" "$V_POST" "$V_UPL" "$V_ST"
done
[ -z "$seen_cli" ] && say "  (none found)"

# ---------------------------------------------------------------- Apache mod_php (Debian/Ubuntu layout)
for ini in /etc/php/*/apache2/php.ini; do
    [ -f "$ini" ] || continue
    xy=$(printf '%s' "$ini" | cut -d/ -f4)
    bin=$(command -v "php$xy" 2>/dev/null) || continue
    say "== Apache mod_php $xy (approximation via php$xy CLI with apache2 ini; highest-risk SAPI)"
    out=$(PHP_INI_SCAN_DIR="/etc/php/$xy/apache2/conf.d" "$bin" -c "$ini" -r "$INI_SNIPPET" 2>/dev/null) || continue
    parse_snippet "$out"
    evaluate "apache2:$ini" "$V_VER" "$V_UP" "$V_MEM" "$V_FEB" "$V_POST" "$V_UPL" "$V_ST"
done
apache_dirs=()
for d in /etc/apache2 /etc/httpd; do [ -d "$d" ] && apache_dirs+=("$d"); done
if [ "${#apache_dirs[@]}" -gt 0 ]; then
    hits=$(grep -rEn '^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]' "${apache_dirs[@]}" 2>/dev/null)
    if [ -n "$hits" ]; then
        say "== Apache php_value / php_flag directives (applied per request before startup: check they"
        say "   are valid and do not put back a finite memory_limit or enable upload progress)"
        while IFS= read -r h; do say "  $h"; done <<<"$hits"
    fi
fi

# ---------------------------------------------------------------- PHP-FPM
fpm_main_conf() { # $1 = fpm binary, $2 = X.Y
    local bin=$1 xy=$2 nodot c
    nodot=${xy/./}
    c=$("$bin" -tt 2>&1 | grep -Eo 'configuration file [^ ]+' | head -n1 | awk '{print $3}')
    if [ -n "$c" ] && [ -f "$c" ]; then echo "$c"; return; fi
    for c in "/etc/php/$xy/fpm/php-fpm.conf" "/etc/php$nodot/php-fpm.conf" \
             "/etc/opt/remi/php$nodot/php-fpm.conf" "/usr/local/etc/php-fpm.conf" \
             "/etc/php-fpm.conf"; do
        [ -f "$c" ] && { echo "$c"; return; }
    done
}

conf_files() { # main conf + its include= globs
    local main=$1 dir inc pattern f
    echo "$main"
    dir=$(dirname "$main")
    while IFS= read -r inc; do
        pattern=$(printf '%s' "$inc" | sed -E 's/^[[:space:]]*include[[:space:]]*=[[:space:]]*//; s/[[:space:]]+$//; s/^"//; s/"$//')
        pattern=${pattern//\$\{prefix\}/\/usr}
        case "$pattern" in /*) ;; *) pattern="$dir/$pattern" ;; esac
        for f in $pattern; do [ -f "$f" ] && echo "$f"; done
    done < <(grep -E '^[[:space:]]*include[[:space:]]*=' "$main" 2>/dev/null)
}

# prints "pool|kind|directive|value" (kind = admin or user) for overrides of
# the relevant directives, plus "pool|-|-|-" for every pool
pool_overrides() {
    awk '
        /^[[:space:]]*[;#]/ { next }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            pool=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", pool)
            if (pool != "global") print pool "|-|-|-"
            next
        }
        /^[[:space:]]*php(_admin)?_(flag|value)\[(session\.upload_progress\.enabled|session\.use_strict_mode|memory_limit|post_max_size|upload_max_filesize|fatal_error_backtraces)\]/ {
            line=$0
            kind = (line ~ /^[[:space:]]*php_admin_/) ? "admin" : "user"
            d=line; sub(/^[^[]*\[/, "", d); sub(/\].*$/, "", d)
            v=line; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]*([;#].*)?$/, "", v)
            if (pool != "" && pool != "global") print pool "|" kind "|" d "|" v
        }
        /^[[:space:]]*pm\.max_requests[[:space:]]*=/ {
            v=$0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]*([;#].*)?$/, "", v)
            if (pool != "" && pool != "global") print pool "|pm|pm.max_requests|" v
        }
    ' "$@" 2>/dev/null
}

info_val() { # $1 = php -i output, $2 = directive -> local value or n/a
    local v
    v=$(printf '%s\n' "$1" | awk -F' => ' -v k="$2" '$1==k {print $2; found=1; exit} END {if (!found) print "\001"}')
    if [ "$v" = $'\001' ]; then echo "n/a"; else echo "$v"; fi
}

# RLIMIT_AS / RLIMIT_DATA on running php-fpm processes (must stay unlimited)
check_rlimits() {
    local pid lim bad=0
    for pid in $(pgrep -f 'php-fpm' 2>/dev/null); do
        [ -r "/proc/$pid/limits" ] || continue
        lim=$(awk '/^Max (address space|data size)/ { if ($4 != "unlimited") print $1" "$2" "$3" = "$4 }' "/proc/$pid/limits")
        if [ -n "$lim" ]; then
            say "  ! pid $pid ($(tr '\0' ' ' < "/proc/$pid/cmdline" | cut -c1-60)): $lim"
            bad=1
        fi
    done
    [ "$bad" -eq 1 ] && say "    RLIMIT_AS / RLIMIT_DATA must not be used (they trigger CVE-2026-109618); use a cgroup limit instead."
    return 0
}

say "== PHP-FPM"
[ "${#FPM_BINS[@]}" -eq 0 ] && say "  (none found)"
for fpm in "${FPM_BINS[@]}"; do
    ver=$("$fpm" -v 2>/dev/null | head -n1 | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    [ -n "$ver" ] || continue
    xy=$(printf '%s' "$ver" | cut -d. -f1,2)
    info=$("$fpm" -i 2>/dev/null)
    if [ -n "$info" ]; then
        b_up=$(norm_bool "$(info_val "$info" session.upload_progress.enabled)")
        b_st=$(norm_bool "$(info_val "$info" session.use_strict_mode)")
        b_feb=$(norm_bool "$(info_val "$info" fatal_error_backtraces)")
        b_mem=$(norm_val "$(info_val "$info" memory_limit)")
        b_post=$(norm_val "$(info_val "$info" post_max_size)")
        b_upl=$(norm_val "$(info_val "$info" upload_max_filesize)")
    else
        b_up="?"; b_st="?"; b_feb="?"; b_mem="?"; b_post="?"; b_upl="?"
    fi
    say "  $fpm (PHP $ver) php.ini: upload_progress.enabled=$b_up memory_limit=$b_mem fatal_error_backtraces=$b_feb post_max_size=$b_post"
    main=$(fpm_main_conf "$fpm" "$xy")
    if [ -z "$main" ]; then
        say "  ! php-fpm.conf not found/readable (run as root?) - evaluating php.ini values only"
        evaluate "fpm:$fpm" "$ver" "$b_up" "$b_mem" "$b_feb" "$b_post" "$b_upl" "$b_st"
        continue
    fi
    mapfile -t files < <(conf_files "$main")
    mapfile -t ovr < <(pool_overrides "${files[@]}")
    pools=$(printf '%s\n' "${ovr[@]}" | cut -d'|' -f1 | grep -v '^$' | awk '!seen[$0]++')
    if [ -z "$pools" ]; then
        say "  ! no pool found in $main includes - evaluating php.ini values only"
        evaluate "fpm:$fpm" "$ver" "$b_up" "$b_mem" "$b_feb" "$b_post" "$b_upl" "$b_st"
        continue
    fi
    while IFS= read -r pool; do
        up=$b_up; mem=$b_mem; feb=$b_feb; post=$b_post; upl=$b_upl; st=$b_st
        mem_kind=ini; maxreq=""
        # php_value first, then php_admin_value (admin wins), last line wins
        for pass in user admin pm; do
            for o in "${ovr[@]}"; do
                IFS='|' read -r p k d v <<<"$o"
                if [ "$p" != "$pool" ] || [ "$k" != "$pass" ]; then continue; fi
                case "$d" in
                    session.upload_progress.enabled) up=$(norm_bool "$v") ;;
                    session.use_strict_mode)         st=$(norm_bool "$v") ;;
                    fatal_error_backtraces)          feb=$(norm_bool "$v") ;;
                    memory_limit)                    mem=$(norm_val "$v"); mem_kind=$k ;;
                    post_max_size)                   post=$(norm_val "$v") ;;
                    upload_max_filesize)             upl=$(norm_val "$v") ;;
                    pm.max_requests)                 maxreq=$v ;;
                esac
            done
        done
        extra=""
        case "$mem_kind" in
            user) extra="memory_limit is set with php_value: applications can override it with ini_set(); use php_admin_value" ;;
            ini)  [ "$mem" = "-1" ] && extra="memory_limit=-1 comes from php.ini only: applications can override it; prefer php_admin_value[memory_limit] = -1" ;;
        esac
        evaluate "fpm:$fpm pool=[$pool]" "$ver" "$up" "$mem" "$feb" "$post" "$upl" "$st" "$extra"
        [ -n "$maxreq" ] && say "      (info: pm.max_requests=$maxreq)"
    done <<<"$pools"
done
[ "${#FPM_BINS[@]}" -gt 0 ] && check_rlimits

# ---------------------------------------------------------------- verdict
say ""
say "Reminder: these settings are NOT a fix. Update to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35."
case "$WORST" in
    0) echo "VERDICT: PATCHED"; exit 0 ;;
    1) echo "VERDICT: MITIGATED (interim only, still unsafe - update PHP now)"; exit 1 ;;
    2) echo "VERDICT: UNKNOWN (EOL-VERIFY: end-of-life runtime, confirm the official/vendor backport or upgrade)"; exit 3 ;;
    3) echo "VERDICT: EXPOSED"; exit 2 ;;
    *) echo "VERDICT: UNKNOWN (no PHP runtime found)"; exit 3 ;;
esac
