#!/usr/bin/env bash
# check-php2shell.sh - read-only exposure check for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619, PHP session.upload_progress).
#
# Inspects every PHP CLI, PHP-FPM and Apache mod_php (Debian layout) runtime it
# can find, reports its version and the effective values of
#   session.upload_progress.enabled   (want: 0 / Off)
#   session.use_strict_mode           (want: 1 / On)
# including per-pool php_admin_flag / php_flag overrides in PHP-FPM pool files.
#
# It changes nothing on the host. Run as root for complete FPM results
# (php-fpm -tt and pool files are often root-only).
#
# Exit codes (worst result wins):
#   0  PATCHED    every runtime found runs a fixed PHP version
#   1  MITIGATED  not (all) patched, but every runtime has both settings applied
#   2  EXPOSED    at least one runtime is unpatched and not mitigated
#   3  UNKNOWN    no PHP runtime found
#
# Usage: ./check-php2shell.sh [-q]      (-q: only print the final verdict)
#
# Docker: this script does not look inside containers. Run it in each one:
#   docker exec -i <container> bash -s < check-php2shell.sh
#
# License: MIT

set -u

# --------------------------------------------------------------------------
# Fixed versions per branch. EDIT when the official PHP release is out.
# Leave empty while the fix is not released: the branch is then reported as
# "not patched" and only the mitigation settings are evaluated.
# Branches not listed here (8.1 and older) are end-of-life: no official fix.
# --------------------------------------------------------------------------
FIXED_8_2="${FIXED_8_2:-}"
FIXED_8_3="${FIXED_8_3:-}"
FIXED_8_4="${FIXED_8_4:-}"
FIXED_8_5="${FIXED_8_5:-}"

QUIET=0
[ "${1:-}" = "-q" ] && QUIET=1

WORST=-1       # -1 none found, 0 patched, 1 mitigated, 2 exposed
FOUND=0

say() { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }

bump() { # $1 = 0/1/2
    FOUND=1
    if [ "$1" -gt "$WORST" ]; then WORST=$1; fi
}

norm_bool() { # prints 1, 0 or ? for an ini/pool value
    local v
    v=$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '"'"'"' ;')
    case "$v" in
        1|on|true|yes)        echo 1 ;;
        0|off|false|no|"")    echo 0 ;;
        *)                    echo "?" ;;
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

# evaluate <label> <version> <upload_progress 0|1|?> <strict 0|1|?>
evaluate() {
    local label=$1 ver=$2 up=$3 strict=$4 fixed status note=""
    fixed=$(fixed_for "$ver")
    if [ -n "$fixed" ] && [ "$fixed" != "EOL" ] && version_ge "$ver" "$fixed"; then
        status=PATCHED; bump 0
    elif [ "$up" = "0" ] && [ "$strict" = "1" ]; then
        status=MITIGATED; bump 1
    else
        status=EXPOSED; bump 2
    fi
    case "$fixed" in
        EOL) note=" (branch end-of-life: no official fix, upgrade to a supported branch)" ;;
        "")  [ "$status" != PATCHED ] && note=" (fixed version for this branch not set/released yet)" ;;
    esac
    say "  [$status] $label  PHP $ver  upload_progress.enabled=$up  use_strict_mode=$strict$note"
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

BIN_DIRS=(/usr/bin /usr/local/bin /bin)
SBIN_DIRS=(/usr/sbin /usr/local/sbin /sbin /usr/bin /usr/local/bin)
for d in /opt/remi/php*/root/usr/bin /opt/cpanel/ea-php*/root/usr/bin /opt/plesk/php/*/bin /opt/alt/php*/usr/bin; do
    [ -d "$d" ] && BIN_DIRS+=("$d")
done
for d in /opt/remi/php*/root/usr/sbin /opt/cpanel/ea-php*/root/usr/sbin /opt/plesk/php/*/sbin /opt/alt/php*/usr/sbin; do
    [ -d "$d" ] && SBIN_DIRS+=("$d")
done

mapfile -t CLI_BINS < <(list_bins '^php([0-9]+(\.[0-9]+)?)?$' "${BIN_DIRS[@]}")
mapfile -t FPM_BINS < <(list_bins '^php-fpm([0-9]+(\.[0-9]+)?)?$' "${SBIN_DIRS[@]}")

INI_SNIPPET='echo PHP_VERSION, "|", (int) filter_var(ini_get("session.upload_progress.enabled"), FILTER_VALIDATE_BOOLEAN), "|", (int) filter_var(ini_get("session.use_strict_mode"), FILTER_VALIDATE_BOOLEAN);'

# ---------------------------------------------------------------- CLI
say "== PHP CLI"
seen_cli=""
for bin in "${CLI_BINS[@]}"; do
    out=$("$bin" -r "$INI_SNIPPET" 2>/dev/null) || continue
    case "$out" in *"|"*"|"*) ;; *) continue ;; esac
    # skip duplicates (php -> php8.3 symlinks already resolved by readlink)
    case " $seen_cli " in *" $bin "*) continue ;; esac
    seen_cli="$seen_cli $bin"
    IFS='|' read -r ver up strict <<<"$out"
    evaluate "cli:$bin" "$ver" "$up" "$strict"
done
[ -z "$seen_cli" ] && say "  (none found)"

# ---------------------------------------------------------------- Apache mod_php (Debian/Ubuntu layout)
for ini in /etc/php/*/apache2/php.ini; do
    [ -f "$ini" ] || continue
    xy=$(printf '%s' "$ini" | cut -d/ -f4)
    bin=$(command -v "php$xy" 2>/dev/null) || continue
    say "== Apache mod_php $xy (approximation via php$xy CLI with apache2 ini)"
    out=$(PHP_INI_SCAN_DIR="/etc/php/$xy/apache2/conf.d" "$bin" -c "$ini" -r "$INI_SNIPPET" 2>/dev/null) || continue
    IFS='|' read -r ver up strict <<<"$out"
    evaluate "apache2:$ini" "$ver" "$up" "$strict"
done

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

# prints "pool|directive|value" for overrides of the two directives
pool_overrides() {
    awk '
        /^[[:space:]]*[;#]/ { next }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            pool=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", pool); next
        }
        /^[[:space:]]*php(_admin)?_(flag|value)\[session\.(upload_progress\.enabled|use_strict_mode)\]/ {
            line=$0
            d=line; sub(/^[^[]*\[/, "", d); sub(/\].*$/, "", d)
            v=line; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]*([;#].*)?$/, "", v)
            if (pool != "" && pool != "global") print pool "|" d "|" v
        }
        END { }
    ' "$@" 2>/dev/null
    # also list every pool, even without overrides
    awk '/^[[:space:]]*\[[^]]+\][[:space:]]*$/ { p=$0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", p); if (p != "global") print p "|-|-" }' "$@" 2>/dev/null
}

say "== PHP-FPM"
[ "${#FPM_BINS[@]}" -eq 0 ] && say "  (none found)"
for fpm in "${FPM_BINS[@]}"; do
    ver=$("$fpm" -v 2>/dev/null | head -n1 | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    [ -n "$ver" ] || continue
    xy=$(printf '%s' "$ver" | cut -d. -f1,2)
    info=$("$fpm" -i 2>/dev/null)
    base_up=$(norm_bool "$(printf '%s\n' "$info" | awk -F' => ' '$1=="session.upload_progress.enabled"{print $2; exit}')")
    base_st=$(norm_bool "$(printf '%s\n' "$info" | awk -F' => ' '$1=="session.use_strict_mode"{print $2; exit}')")
    [ -n "$info" ] || { base_up="?"; base_st="?"; }
    say "  $fpm (PHP $ver) php.ini: upload_progress.enabled=$base_up use_strict_mode=$base_st"
    main=$(fpm_main_conf "$fpm" "$xy")
    if [ -z "$main" ]; then
        say "  ! php-fpm.conf not found/readable (run as root?) - evaluating php.ini values only"
        evaluate "fpm:$fpm" "$ver" "$base_up" "$base_st"
        continue
    fi
    mapfile -t files < <(conf_files "$main")
    mapfile -t ovr < <(pool_overrides "${files[@]}")
    pools=$(printf '%s\n' "${ovr[@]}" | cut -d'|' -f1 | sort -u | grep -v '^$')
    if [ -z "$pools" ]; then
        say "  ! no pool found in $main includes - evaluating php.ini values only"
        evaluate "fpm:$fpm" "$ver" "$base_up" "$base_st"
        continue
    fi
    while IFS= read -r pool; do
        up=$base_up; st=$base_st
        for o in "${ovr[@]}"; do
            IFS='|' read -r p d v <<<"$o"
            [ "$p" = "$pool" ] || continue
            case "$d" in
                session.upload_progress.enabled) up=$(norm_bool "$v") ;;
                session.use_strict_mode)         st=$(norm_bool "$v") ;;
            esac
        done
        evaluate "fpm:$fpm pool=[$pool]" "$ver" "$up" "$st"
    done <<<"$pools"
done

# ---------------------------------------------------------------- verdict
say ""
case "$WORST" in
    0) echo "VERDICT: PATCHED"; exit 0 ;;
    1) echo "VERDICT: MITIGATED (temporary - upgrade PHP as soon as the fix is available)"; exit 1 ;;
    2) echo "VERDICT: EXPOSED"; exit 2 ;;
    *) [ "$FOUND" -eq 0 ] && echo "VERDICT: UNKNOWN (no PHP runtime found)"; exit 3 ;;
esac
