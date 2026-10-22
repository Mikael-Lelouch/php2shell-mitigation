#!/usr/bin/env bash
# check-php2shell.sh - read-only exposure check for PHP2Shell
#   CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) RCE via OOM corruption
#   CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp) RCE via stale global state
# Official notice: https://www.php.net/archive/2026.php#2026-10-21-1
#
# Inspects every PHP CLI, PHP-FPM, php-cgi, Apache mod_php (Debian and SUSE-style layouts),
# LiteSpeed (lsphp) and FrankenPHP runtime it can find and reports its version
# plus the effective values of the official interim settings:
#   session.upload_progress.enabled   want 0            (CVE-2026-109619)
#   memory_limit                      want -1           (CVE-2026-109618)
#   fatal_error_backtraces            want 0, PHP 8.5   (CVE-2026-109619)
#   post_max_size                     8M, max 32M       (reported, warning only)
#   upload_max_filesize               < post_max_size   (reported, warning only)
#   session.use_strict_mode           informational only (not in the advisory)
# including per-pool php_admin_value/flag and php_value/flag overrides of every
# PHP-FPM pool (read from `php-fpm -tt`, i.e. what FPM itself will apply), and
# RLIMIT_AS / RLIMIT_DATA on running web SAPI processes.
#
# A runtime counts as PATCHED when its version is a fixed upstream release OR
# when the package that owns it (dpkg / rpm) lists both CVE ids in its
# changelog: Debian, Ubuntu and RHEL backport the fix without changing the
# upstream version number.
#
# It also warns about running processes whose binary (or mod_php library) was
# replaced on disk after they started: a package update without a restart
# leaves the vulnerable code in memory.
#
# It changes nothing on the host. Run as root for complete results (php-fpm
# -tt, pool files, /proc/<pid>/maps and /proc/<pid>/limits are often root-only).
#
# Exit codes (worst result wins):
#   0  PATCHED     every runtime found runs a fixed PHP version / vendor backport
#   1  MITIGATED   not (all) patched, but every unpatched runtime has the
#                  official interim settings. STILL UNSAFE: update PHP.
#   2  EXPOSED     at least one runtime is unpatched and not mitigated, or a
#                  process still runs a binary that was replaced on disk
#   3  UNKNOWN     no PHP runtime found, or a runtime that cannot be classified
#                  (end-of-life 7.4/8.0/8.1 or older without a known backport:
#                  "EOL-VERIFY"; a branch newer than this script knows:
#                  "UNKNOWN-BRANCH"; or bash older than 4)
#   64 usage error (unknown option)
#
# Usage: ./check-php2shell.sh [-q] [-h] [-V]
#   -q, --quiet     only print the final verdict
#   -h, --help      show this help
#   -V, --version   show the script version
#
# Environment:
#   FIXED_8_2 ... FIXED_8_5    override the fixed version of a branch
#                              (FIXED_8_6 etc. can be set to classify newer branches)
#   PHP2SHELL_EOL_BACKPORTED=1 count end-of-life runtimes as patched (only if
#                              you installed the official 7.4/8.0/8.1 source
#                              backport or a vendor backport)
#   PHP2SHELL_BIN_DIRS / PHP2SHELL_SBIN_DIRS
#                              colon-separated dirs that REPLACE the default
#                              search dirs for php / php-fpm binaries
#   PHP2SHELL_ETC, PHP2SHELL_DOC_DIR, PHP2SHELL_PROC
#                              /etc, /usr/share/doc and /proc locations (test hooks)
#
# This script cannot see: PHP_VALUE / PHP_ADMIN_VALUE sent by nginx or Apache
# to FPM, .htaccess files, application ini_set() calls, frontend request
# limits or cgroup memory limits. Review those by hand. lsphp and FrankenPHP
# get a version check only (their settings are not evaluated).
#
# Docker: this script does not look inside containers. Run it in each one:
#   docker exec -i <container> bash -s < check-php2shell.sh
#
# License: MIT

set -u

SCRIPT_VERSION="1.2.0"

# mapfile and the array handling below need bash 4+
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "check-php2shell.sh needs bash 4 or newer (found: ${BASH_VERSION:-unknown})" >&2
    echo "VERDICT: UNKNOWN (bash too old)"
    exit 3
fi

usage() { # static text: the script may be read from stdin (docker exec -i ... bash -s)
    echo "Usage: check-php2shell.sh [-q] [-h] [-V]"
    echo "  -q, --quiet     only print the final verdict"
    echo "  -h, --help      show this help"
    echo "  -V, --version   show the script version"
    echo "Exit codes: 0 PATCHED, 1 MITIGATED, 2 EXPOSED, 3 UNKNOWN, 64 usage error"
}

QUIET=0
while [ $# -gt 0 ]; do
    case "$1" in
        -q|--quiet)   QUIET=1 ;;
        -h|--help)    usage; exit 0 ;;
        -V|--version) echo "check-php2shell.sh $SCRIPT_VERSION"; exit 0 ;;
        *)            echo "check-php2shell.sh: unknown option: $1" >&2; usage >&2; exit 64 ;;
    esac
    shift
done

# --------------------------------------------------------------------------
# Fixed versions per branch (php.net security releases of 21 Oct 2026).
# Branches below 8.2 are end-of-life: only source/vendor backports exist.
# Branches above 8.5 are not listed: they are reported as UNKNOWN-BRANCH
# unless you set FIXED_<major>_<minor> yourself.
# --------------------------------------------------------------------------
FIXED_8_2="${FIXED_8_2:-8.2.35}"
FIXED_8_3="${FIXED_8_3:-8.3.36}"
FIXED_8_4="${FIXED_8_4:-8.4.27}"
FIXED_8_5="${FIXED_8_5:-8.5.12}"
EOL_BACKPORTED="${PHP2SHELL_EOL_BACKPORTED:-0}"

ETC_DIR="${PHP2SHELL_ETC:-/etc}"
DOC_DIR="${PHP2SHELL_DOC_DIR:-/usr/share/doc}"
PROC_DIR="${PHP2SHELL_PROC:-/proc}"

# severity rank: 0 patched, 1 mitigated, 2 unclassified (eol-verify / unknown-branch), 3 exposed
WORST=-1
STALE=0

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

fixed_for() { # $1 = X.Y.Z[suffix] -> fixed version of its branch, "EOL", or "" (branch unknown)
    local major minor var
    [[ $1 =~ ^([0-9]+)\.([0-9]+) ]] || { echo ""; return; }
    major=${BASH_REMATCH[1]}
    minor=${BASH_REMATCH[2]}
    if [ "$major" -lt 8 ] || { [ "$major" -eq 8 ] && [ "$minor" -le 1 ]; }; then
        echo "EOL"
        return
    fi
    var="FIXED_${major}_${minor}"
    echo "${!var:-}"
}

# Pure bash on purpose (no sort | head pipe): a pipeline whose reader exits early
# prints "write error: Broken pipe" on stderr when SIGPIPE is ignored, which is how
# some CI runners and supervisors start their children.
version_ge() { # $1 >= $2 ? dotted numeric versions
    local -a a b
    local i x y
    IFS=. read -r -a a <<<"$1"
    IFS=. read -r -a b <<<"$2"
    for i in 0 1 2 3; do
        x=${a[i]:-0}; y=${b[i]:-0}
        [[ $x =~ ^[0-9]+$ ]] || x=0
        [[ $y =~ ^[0-9]+$ ]] || y=0
        if ((10#$x > 10#$y)); then return 0; fi
        if ((10#$x < 10#$y)); then return 1; fi
    done
    return 0
}

# 8.5.12RC1, 8.3.36-dev ... : a pre-release of a version number is not the release
is_prerelease() { [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+-?(alpha|beta|RC|rc|dev) ]]; }

is_fixed() { # $1 = version as reported by PHP, $2 = fixed version of its branch
    local num=${1%%[!0-9.]*}      # 8.3.36-1+deb12u1 -> 8.3.36, 8.5.12RC1 -> 8.5.12
    version_ge "$num" "$2" || return 1
    ! { is_prerelease "$1" && [ "$num" = "$2" ]; }
}

# ---------------------------------------------------------------- vendor backports
VENDOR_PKG=""

changelog_text() { # $1 = dpkg package name -> installed changelog(s)
    local f
    for f in "$DOC_DIR/$1"/changelog*; do
        [ -f "$f" ] || continue
        case "$f" in
            *.gz) gzip -dc "$f" 2>/dev/null ;;
            *)    cat "$f" 2>/dev/null ;;
        esac
    done
}

# vendor_patched <file>: succeeds when the dpkg/rpm package owning <file> lists
# BOTH CVE ids in its changelog (sets VENDOR_PKG). Both ids must appear: a
# changelog may name the patch file CVE-2026-109618_109619.patch.
vendor_patched() {
    local path=$1 real pkg="" text=""
    VENDOR_PKG=""
    [ -n "$path" ] && [ -e "$path" ] || return 1
    real=$(readlink -f "$path" 2>/dev/null) || real=$path
    if command -v dpkg >/dev/null 2>&1; then
        pkg=$(dpkg -S "$real" 2>/dev/null | head -n1 | sed -E 's/: .*$//; s/,.*$//; s/:[^:]*$//')
        [ -n "$pkg" ] && text=$(changelog_text "$pkg")
    fi
    if [ -z "$text" ] && command -v rpm >/dev/null 2>&1; then
        if pkg=$(rpm -qf "$real" 2>/dev/null | head -n1) && [ -n "$pkg" ]; then
            text=$(rpm -q --changelog "$pkg" 2>/dev/null)
        fi
    fi
    # pattern match, not `printf | grep -q`: see version_ge about early-exit pipes
    # (a Debian changelog is larger than the 64 KiB pipe buffer)
    [[ $text == *CVE-2026-109618* && $text == *CVE-2026-109619* ]] || return 1
    VENDOR_PKG=$pkg
    return 0
}

# evaluate <label> <version> <upload_progress> <memory_limit> <fatal_bt>
#          <post_max_size> <upload_max_filesize> <use_strict_mode> [notes] [vendor file]
# A setting of "?" means "not evaluated" (version-only checks).
evaluate() {
    local label=$1 ver=$2 up=$3 mem=$4 feb=$5 post=$6 upl=$7 strict=$8 extra=${9:-} vfile=${10:-}
    local fixed status rank mitigated=0 note="" pb ub
    fixed=$(fixed_for "$ver")

    if { [ "$up" = "0" ] || [ "$up" = "n/a" ]; } && [ "$mem" = "-1" ] \
        && { [ "$feb" = "0" ] || [ "$feb" = "n/a" ]; }; then
        mitigated=1
    fi

    if [ -n "$vfile" ] && vendor_patched "$vfile"; then
        status=PATCHED; rank=0
        note=" (vendor backport: the changelog of $VENDOR_PKG lists CVE-2026-109618 and CVE-2026-109619)"
    elif [ "$fixed" = "EOL" ]; then
        if [ "$EOL_BACKPORTED" = "1" ]; then
            status=PATCHED; rank=0; note=" (end-of-life: backport declared via PHP2SHELL_EOL_BACKPORTED=1)"
        elif [ "$mitigated" -eq 1 ]; then
            status=MITIGATED; rank=1; note=" (end-of-life: install the official source backport or a vendor backport)"
        else
            status=EOL-VERIFY; rank=2; note=" (end-of-life: EXPOSED unless it carries the official/vendor backport; verify, see PATCHING.md)"
        fi
    elif [ -n "$fixed" ] && is_fixed "$ver" "$fixed"; then
        status=PATCHED; rank=0
    elif [ "$mitigated" -eq 1 ]; then
        status=MITIGATED; rank=1
    elif [ -z "$fixed" ]; then
        status=UNKNOWN-BRANCH; rank=2
        note=" (branch newer than this script knows: confirm upstream that this build has the fix, or set FIXED_<major>_<minor>)"
    else
        status=EXPOSED; rank=3
        is_prerelease "$ver" && note=" (pre-release build: not a fixed release even if the number matches)"
    fi
    bump "$rank"

    say "  [$status] $label  PHP $ver$note"
    say "      session.upload_progress.enabled=$up  memory_limit=$mem  fatal_error_backtraces=$feb  post_max_size=$post  upload_max_filesize=$upl  (info: session.use_strict_mode=$strict)"

    [ "$status" = PATCHED ] && [ -z "$extra" ] && return 0
    if [ "$status" != PATCHED ]; then
        [ "$up" = "1" ] && say "      - set session.upload_progress.enabled=0 (CVE-2026-109619)"
        [ "$mem" != "-1" ] && [ "$mem" != "?" ] && say "      - set memory_limit=-1 administratively (CVE-2026-109618)"
        [ "$feb" = "1" ] && say "      - set fatal_error_backtraces=0 (PHP 8.5, CVE-2026-109619)"
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
            # in-process name match first: /usr/bin holds thousands of files and
            # this runs once per SAPI, so no fork per file
            [[ ${f##*/} =~ $re ]] || continue
            if [ -f "$f" ] && [ -x "$f" ]; then readlink -f "$f"; fi
        done
    done | sort -u
}

if [ -n "${PHP2SHELL_BIN_DIRS:-}" ]; then
    IFS=: read -r -a BIN_DIRS <<<"$PHP2SHELL_BIN_DIRS"
else
    BIN_DIRS=(/usr/bin /usr/local/bin /bin)
    for d in /opt/remi/php*/root/usr/bin /opt/cpanel/ea-php*/root/usr/bin /opt/plesk/php/*/bin \
             /opt/alt/php*/usr/bin /usr/local/lsws/lsphp*/bin; do
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
mapfile -t CGI_BINS < <(list_bins '^php-cgi([0-9]+(\.[0-9]+)?)?$' "${BIN_DIRS[@]}")
mapfile -t LSAPI_BINS < <(list_bins '^lsphp([0-9]+(\.[0-9]+)?)?$' "${BIN_DIRS[@]}")
mapfile -t FRANKEN_BINS < <(list_bins '^frankenphp$' "${BIN_DIRS[@]}")
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

valid_snippet_output() { # 7 pipe-separated fields
    case "$1" in *"|"*"|"*"|"*"|"*"|"*"|"*) return 0 ;; *) return 1 ;; esac
}

version_from_v() { # reads `<bin> -v` / `frankenphp version` output, prints PHP's version string
    local text re='PHP ([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9._+~-]*)'
    text=$(cat)
    if [[ $text =~ $re ]]; then printf '%s\n' "${BASH_REMATCH[1]}"; fi
}

# ---------------------------------------------------------------- CLI
say "== PHP CLI (version check; CLI does not serve web requests)"
seen_cli=""
for bin in ${CLI_BINS[@]+"${CLI_BINS[@]}"}; do
    out=$("$bin" -r "$INI_SNIPPET" 2>/dev/null) || continue
    valid_snippet_output "$out" || continue
    case " $seen_cli " in *" $bin "*) continue ;; esac
    seen_cli="$seen_cli $bin"
    parse_snippet "$out"
    evaluate "cli:$bin" "$V_VER" "$V_UP" "$V_MEM" "$V_FEB" "$V_POST" "$V_UPL" "$V_ST" "" "$bin"
done
[ -z "$seen_cli" ] && say "  (none found)"

# ---------------------------------------------------------------- php-cgi
if [ "${#CGI_BINS[@]}" -gt 0 ]; then
    say "== php-cgi"
    for bin in "${CGI_BINS[@]}"; do
        out=$(printf '<?php %s' "$INI_SNIPPET" | "$bin" -q 2>/dev/null) || continue
        valid_snippet_output "$out" || continue
        parse_snippet "$out"
        evaluate "cgi:$bin" "$V_VER" "$V_UP" "$V_MEM" "$V_FEB" "$V_POST" "$V_UPL" "$V_ST" "" "$bin"
    done
fi

# ---------------------------------------------------------------- LiteSpeed / FrankenPHP (version only)
version_only() { # $1 = label, $2 = binary, $3 = version argument
    local ver
    ver=$("$2" "$3" 2>/dev/null | version_from_v)
    [ -n "$ver" ] || return 0
    evaluate "$1:$2" "$ver" "?" "?" "?" "?" "?" "?" "version check only: settings are not evaluated for this SAPI, review them by hand" "$2"
}
if [ "${#LSAPI_BINS[@]}" -gt 0 ]; then
    say "== LiteSpeed lsphp (version only)"
    for bin in "${LSAPI_BINS[@]}"; do version_only lsapi "$bin" -v; done
fi
if [ "${#FRANKEN_BINS[@]}" -gt 0 ]; then
    say "== FrankenPHP (version only)"
    for bin in "${FRANKEN_BINS[@]}"; do version_only frankenphp "$bin" version; done
fi

# ---------------------------------------------------------------- Apache mod_php
apache_dirs=()
for d in "$ETC_DIR/apache2" "$ETC_DIR/httpd"; do [ -d "$d" ] && apache_dirs+=("$d"); done

# The module file is read from Apache's own `LoadModule php*_module <file>` lines,
# so it does not depend on a distribution's naming (Debian libphp8.3.so, RHEL
# libphp.so, SUSE-style mod_php8.so ...). Relative paths are relative to ServerRoot.
apache_php_modules() { # prints each PHP module file that exists
    local line f c
    [ "${#apache_dirs[@]}" -gt 0 ] || return 0
    while IFS= read -r line; do
        read -r _ _ f _ <<<"$line"
        case "$f" in
            /*) [ -f "$f" ] && printf '%s\n' "$f" ;;
            ?*) for c in "$ETC_DIR/httpd/$f" "$ETC_DIR/apache2/$f"; do
                    if [ -f "$c" ]; then printf '%s\n' "$c"; break; fi
                done ;;
        esac
    done < <(grep -rEh '^[[:space:]]*LoadModule[[:space:]]+php[0-9]*_module[[:space:]]' "${apache_dirs[@]}" 2>/dev/null)
}
mapfile -t APACHE_PHP_MODS < <(apache_php_modules)

pick_module() { # $1 = preferred name fragment, $2 = fallback file -> module file to ask the package manager about
    local m
    for m in ${APACHE_PHP_MODS[@]+"${APACHE_PHP_MODS[@]}"}; do
        case "${m##*/}" in *"$1"*) printf '%s\n' "$m"; return 0 ;; esac
    done
    if [ "${#APACHE_PHP_MODS[@]}" -gt 0 ]; then printf '%s\n' "${APACHE_PHP_MODS[0]}"; else printf '%s\n' "$2"; fi
}

# check_mod_php <apache2 php.ini> <CLI binary> <conf.d dir or ""> <module file>
# "" = keep the CLI's compiled-in scan dir (layouts where conf.d is shared by every SAPI)
check_mod_php() {
    local ini=$1 bin=$2 scan=$3 vlib=$4 out
    if [ -n "$scan" ]; then
        out=$(PHP_INI_SCAN_DIR="$scan" "$bin" -c "$ini" -r "$INI_SNIPPET" 2>/dev/null) || return 0
    else
        out=$("$bin" -c "$ini" -r "$INI_SNIPPET" 2>/dev/null) || return 0
    fi
    valid_snippet_output "$out" || return 0
    parse_snippet "$out"
    evaluate "apache2:$ini" "$V_VER" "$V_UP" "$V_MEM" "$V_FEB" "$V_POST" "$V_UPL" "$V_ST" "" "$vlib"
}

# Debian / Ubuntu layout: /etc/php/X.Y/apache2/{php.ini,conf.d}
for ini in "$ETC_DIR"/php/*/apache2/php.ini; do
    [ -f "$ini" ] || continue
    xy=${ini#"$ETC_DIR"/php/}; xy=${xy%%/*}
    bin=$(command -v "php$xy" 2>/dev/null) || continue
    say "== Apache mod_php $xy (approximation via php$xy CLI with apache2 ini; highest-risk SAPI)"
    vlib="/usr/lib/apache2/modules/libphp$xy.so"
    [ -f "$vlib" ] || vlib=$(pick_module "php$xy" "$bin")
    check_mod_php "$ini" "$bin" "$ETC_DIR/php/$xy/apache2/conf.d" "$vlib"
done

# SUSE-style layout: /etc/php<N>/apache2/php.ini, conf.d shared by the SAPIs.
# (Layout from SUSE packaging conventions: not validated on a real SLES host.)
for ini in "$ETC_DIR"/php[0-9]*/apache2/php.ini; do
    [ -f "$ini" ] || continue
    n=${ini#"$ETC_DIR"/php}; n=${n%%/*}
    bin=$(command -v "php$n" 2>/dev/null) || bin=$(command -v php 2>/dev/null) || continue
    say "== Apache mod_php php$n (SUSE-style layout; approximation via the CLI with the apache2 ini and its compiled-in conf.d; highest-risk SAPI)"
    check_mod_php "$ini" "$bin" "" "$(pick_module "php$n" "$bin")"
done
if [ "${#apache_dirs[@]}" -gt 0 ]; then
    # `php_admin_flag engine` is the stock "no PHP in user dirs" line, unrelated to this advisory
    hits=$(grep -rEn '^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]' "${apache_dirs[@]}" 2>/dev/null \
        | grep -Ev ':[0-9]+:[[:space:]]*php_admin_flag[[:space:]]+engine[[:space:]]')
    if [ -n "$hits" ]; then
        say "== Apache php_value / php_flag directives (applied per request before startup: check they"
        say "   are valid and do not put back a finite memory_limit or enable upload progress)"
        while IFS= read -r h; do say "  $h"; done <<<"$hits"
    fi
fi

# ---------------------------------------------------------------- PHP-FPM
# Effective configuration of every pool, as FPM itself parses it (it resolves
# include= relative to its prefix, which differs between distributions and the
# Docker image). Printed in pool-file syntax; fails when FPM cannot parse it.
fpm_effective_conf() { # $1 = fpm binary
    local out
    out=$("$1" -tt 2>&1) || return 1
    case "$out" in *"ERROR:"*) return 1 ;; *"[global]"*) ;; *) return 1 ;; esac
    printf '%s\n' "$out" | sed -E 's/^\[[^]]*\] [A-Z]+: ?//'
}

# Fallback when `php-fpm -tt` fails: locate and read the pool files ourselves.
fpm_main_conf() { # $1 = fpm binary, $2 = X.Y
    local bin=$1 xy=$2 nodot c
    nodot=${xy/./}
    c=$("$bin" -tt 2>&1)
    if [[ $c =~ configuration\ file\ \'?([^\ \']+) ]]; then
        c=${BASH_REMATCH[1]}
        if [ -f "$c" ]; then echo "$c"; return; fi
    fi
    for c in "$ETC_DIR/php/$xy/fpm/php-fpm.conf" "$ETC_DIR/php$nodot/php-fpm.conf" \
             "$ETC_DIR/opt/remi/php$nodot/php-fpm.conf" "/usr/local/etc/php-fpm.conf" \
             "$ETC_DIR/php-fpm.conf"; do
        [ -f "$c" ] && { echo "$c"; return; }
    done
}

conf_files() { # main conf + its include= globs (relative globs: tried against the conf dir and common prefixes)
    local main=$1 dir inc pattern f base
    echo "$main"
    dir=$(dirname "$main")
    while IFS= read -r inc; do
        pattern=$(printf '%s' "$inc" | sed -E 's/^[[:space:]]*include[[:space:]]*=[[:space:]]*//; s/[[:space:]]+$//; s/^"//; s/"$//')
        pattern=${pattern//\$\{prefix\}/\/usr}
        case "$pattern" in
            /*) for f in $pattern; do [ -f "$f" ] && echo "$f"; done ;;
            *)  for base in "$dir" /usr/local /usr; do
                    for f in "$base"/$pattern; do [ -f "$f" ] && echo "$f"; done
                done ;;
        esac
    done < <(grep -E '^[[:space:]]*include[[:space:]]*=' "$main" 2>/dev/null)
}

# stdin: pool-file syntax. Prints "pool|kind|directive|value" (kind = admin or
# user) for overrides of the relevant directives, plus "pool|-|-|-" for every pool
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
    ' 2>/dev/null
}

info_val() { # $1 = php -i output, $2 = directive -> local value or n/a
    local v
    v=$(printf '%s\n' "$1" | awk -F' => ' -v k="$2" '$1==k {print $2; found=1; exit} END {if (!found) print "\001"}')
    if [ "$v" = $'\001' ]; then echo "n/a"; else echo "$v"; fi
}

say "== PHP-FPM"
[ "${#FPM_BINS[@]}" -eq 0 ] && say "  (none found)"
for fpm in ${FPM_BINS[@]+"${FPM_BINS[@]}"}; do
    ver=$("$fpm" -v 2>/dev/null | version_from_v)
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

    if dump=$(fpm_effective_conf "$fpm"); then
        mapfile -t ovr < <(pool_overrides <<<"$dump")
    else
        main=$(fpm_main_conf "$fpm" "$xy")
        if [ -z "$main" ]; then
            say "  ! php-fpm -tt failed and php-fpm.conf was not found/readable (run as root?) - evaluating php.ini values only"
            evaluate "fpm:$fpm" "$ver" "$b_up" "$b_mem" "$b_feb" "$b_post" "$b_upl" "$b_st" "" "$fpm"
            continue
        fi
        say "  ! php-fpm -tt failed: reading pool files from $main instead"
        mapfile -t files < <(conf_files "$main")
        mapfile -t ovr < <(cat "${files[@]}" 2>/dev/null | pool_overrides)
    fi
    pools=$(printf '%s\n' ${ovr[@]+"${ovr[@]}"} | cut -d'|' -f1 | grep -v '^$' | awk '!seen[$0]++')
    if [ -z "$pools" ]; then
        say "  ! no pool found in the FPM configuration - evaluating php.ini values only"
        # FPM loads *.conf only: a lone *.default template is not a pool
        for f in "$ETC_DIR"/php*/fpm/php-fpm.d/*.default "$ETC_DIR"/php-fpm.d/*.default /usr/local/etc/php-fpm.d/*.default; do
            if [ -f "$f" ]; then say "      only a template exists: $f (FPM does not load it; copy it to a .conf file)"; break; fi
        done
        evaluate "fpm:$fpm" "$ver" "$b_up" "$b_mem" "$b_feb" "$b_post" "$b_upl" "$b_st" "" "$fpm"
        continue
    fi
    while IFS= read -r pool; do
        up=$b_up; mem=$b_mem; feb=$b_feb; post=$b_post; upl=$b_upl; st=$b_st
        mem_kind=ini; maxreq=""
        # php_value first, then php_admin_value (admin wins), last line wins
        for pass in user admin pm; do
            for o in ${ovr[@]+"${ovr[@]}"}; do
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
        evaluate "fpm:$fpm pool=[$pool]" "$ver" "$up" "$mem" "$feb" "$post" "$upl" "$st" "$extra" "$fpm"
        # pm.max_requests = 0 is the default (workers are reused): only report a real setting
        [ -n "$maxreq" ] && [ "$maxreq" != "0" ] && say "      (info: pm.max_requests=$maxreq)"
    done <<<"$pools"
done

# ---------------------------------------------------------------- running processes
# For every running web SAPI process: (1) was its binary / mod_php library
# replaced on disk since it started (update without restart)? (2) does it run
# under RLIMIT_AS / RLIMIT_DATA, which must stay unlimited (CVE-2026-109618)?
scan_processes() {
    local p pid comm exe lim kind stale_list="" n_stale=0 rlimit_list="" n_rlimit=0 shown=0
    for p in "$PROC_DIR"/[0-9]*; do
        # builtin read, not `cat`: this loop visits every process of the host
        { read -r comm < "$p/comm"; } 2>/dev/null || continue
        pid=${p##*/}
        case "$comm" in
            php-fpm*|php-cgi*|lsphp*|frankenphp*) kind=bin ;;
            apache2|httpd|httpd.*|httpd-*)
                # only the Apache processes that actually loaded mod_php
                if [ -r "$p/maps" ] && grep -Eq '(libphp|mod_php)[^ ]*\.so' "$p/maps" 2>/dev/null; then kind=mod; else continue; fi ;;
            *) continue ;;
        esac
        if [ "$kind" = bin ]; then
            exe=$(readlink "$p/exe" 2>/dev/null) || exe=""
            case "$exe" in *" (deleted)") stale_list="$stale_list $pid($comm)"; n_stale=$((n_stale + 1)) ;; esac
        elif grep -Eq '(libphp|mod_php)[^ ]*\.so.*\(deleted\)' "$p/maps" 2>/dev/null; then
            stale_list="$stale_list $pid($comm)"; n_stale=$((n_stale + 1))
        fi
        if [ -r "$p/limits" ]; then
            lim=$(awk '/^Max (address space|data size)/ { if ($4 != "unlimited") print $1" "$2" "$3" = "$4 }' "$p/limits")
            if [ -n "$lim" ]; then
                rlimit_list="$rlimit_list
  ! pid $pid ($comm): $lim"
                n_rlimit=$((n_rlimit + 1))
            fi
        fi
    done
    if [ "$n_stale" -gt 0 ]; then
        STALE=$n_stale
        say "== Running processes"
        say "  ! $n_stale process(es) still run a PHP binary/library replaced on disk since they started:"
        for p in $stale_list; do
            shown=$((shown + 1))
            [ "$shown" -le 8 ] && say "      $p"
        done
        [ "$n_stale" -gt 8 ] && say "      ... and $((n_stale - 8)) more"
        say "    The vulnerable code is still in memory: RESTART (not reload) php-fpm / Apache / php-cgi / lsphp / frankenphp."
    fi
    if [ "$n_rlimit" -gt 0 ]; then
        say "== Resource limits"
        say "${rlimit_list#$'\n'}"
        say "    RLIMIT_AS / RLIMIT_DATA must not be used (they trigger CVE-2026-109618); use a cgroup limit instead."
    fi
    return 0
}
scan_processes

# ---------------------------------------------------------------- verdict
say ""
say "Reminder: these settings are NOT a fix. Update to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35."
case "$WORST" in
    0) verdict="PATCHED"; code=0 ;;
    1) verdict="MITIGATED (interim only, still unsafe - update PHP now)"; code=1 ;;
    2) verdict="UNKNOWN (EOL-VERIFY / UNKNOWN-BRANCH: a runtime could not be classified, confirm the official/vendor backport or upgrade)"; code=3 ;;
    3) verdict="EXPOSED"; code=2 ;;
    *) verdict="UNKNOWN (no PHP runtime found)"; code=3 ;;
esac
if [ "$STALE" -gt 0 ] && [ "$code" -ne 2 ]; then
    verdict="EXPOSED (restart required: $STALE running process(es) still use a PHP binary replaced on disk)"
    code=2
fi
echo "VERDICT: $verdict"
exit "$code"
