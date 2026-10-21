#!/usr/bin/env bash
# Hermetic tests for check-php2shell.sh: PHP runtimes, package managers and /etc
# are replaced by stubs, so no PHP installation is needed and the host state
# does not matter. Run: bash tests/run-tests.sh
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="${PHP2SHELL_SCRIPT:-$ROOT/check-php2shell.sh}"
TMP=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
OUT=""
RC=0

# ---------------------------------------------------------------- helpers
new_env() { # fresh stub environment in $E
    E="$TMP/env"
    rm -rf "$E"
    mkdir -p "$E"/{bin,sbin,etc,doc,proc,path}
    # package managers that own nothing unless a test says otherwise
    printf '#!/bin/sh\nexit 1\n' >"$E/path/dpkg"
    printf '#!/bin/sh\nexit 1\n' >"$E/path/rpm"
    chmod +x "$E/path/dpkg" "$E/path/rpm"
}

stub_cli() { # name version up mem feb post upl strict
    cat >"$E/bin/$1" <<EOF
#!/bin/sh
case "\$1" in
    -r) printf '%s' '$2|$3|$4|$5|$6|$7|$8' ;;
    -v) echo "PHP $2 (cli) (built: stub)" ;;
esac
EOF
    chmod +x "$E/bin/$1"
}

stub_cgi() { # name version up mem feb post upl strict
    cat >"$E/bin/$1" <<EOF
#!/bin/sh
cat >/dev/null
printf '%s' '$2|$3|$4|$5|$6|$7|$8'
EOF
    chmod +x "$E/bin/$1"
}

stub_v_only() { # name version-output-line (lsphp / frankenphp)
    printf '#!/bin/sh\necho "%s"\n' "$2" >"$E/bin/$1"
    chmod +x "$E/bin/$1"
}

# stub_fpm <name> <version> <php.ini up> <php.ini mem> <config dump body>
# The dump body uses pool-file syntax and is printed the way `php-fpm -tt` does.
stub_fpm() {
    local body
    body=$(printf '%s\n' "$5" | sed -E 's/^(\[.*\])$/[21-Oct-2026 10:00:00] NOTICE: \1/; t; s/^/[21-Oct-2026 10:00:00] NOTICE: \t/')
    cat >"$E/sbin/$1" <<EOF
#!/bin/sh
case "\$1" in
    -v) echo "PHP $2 (fpm-fcgi) (built: stub)" ;;
    -i) printf '%s\n' \
        'session.upload_progress.enabled => $3 => $3' \
        'memory_limit => $4 => $4' \
        'post_max_size => 8M => 8M' \
        'upload_max_filesize => 2M => 2M' ;;
    -tt) cat >&2 <<'DUMP'
[21-Oct-2026 10:00:00] NOTICE: [global]
[21-Oct-2026 10:00:00] NOTICE: 	daemonize = yes
$body
DUMP
        ;;
esac
EOF
    chmod +x "$E/sbin/$1"
}

stub_dpkg_owner() { # package name -> every file is owned by it
    # shellcheck disable=SC2016  # $1/$2 are for the generated stub, not for this shell
    printf '#!/bin/sh\n[ "$1" = "-S" ] && { echo "%s: $2"; exit 0; }\nexit 1\n' "$1" >"$E/path/dpkg"
    chmod +x "$E/path/dpkg"
}

changelog() { # package, text -> $E/doc/<package>/changelog.Debian.gz
    mkdir -p "$E/doc/$1"
    printf '%s\n' "$2" | gzip -c >"$E/doc/$1/changelog.Debian.gz"
}

SCRIPT_ARGS=()

# SIGPIPE is ignored on purpose: GitHub runners and many supervisors start their
# children that way, and then any pipeline whose reader exits early makes the
# writer print "write error: Broken pipe" on stderr. check() fails on that noise.
run() { # extra env assignments via "$@" are passed before the script
    OUT=$( (trap '' PIPE; exec env PHP2SHELL_BIN_DIRS="$E/bin" PHP2SHELL_SBIN_DIRS="$E/sbin" \
        PHP2SHELL_ETC="$E/etc" PHP2SHELL_DOC_DIR="$E/doc" PHP2SHELL_PROC="${PROC_OVERRIDE:-$E/proc}" \
        PATH="$E/path:$PATH" "$@" bash "$SCRIPT" ${SCRIPT_ARGS[@]+"${SCRIPT_ARGS[@]}"}) 2>&1 )
    RC=$?
}

check() { # name expected-rc pattern... (every pattern must appear in the output)
    local name=$1 want=$2 ok=1 pat
    shift 2
    [ "$RC" -eq "$want" ] || ok=0
    for pat in "$@"; do
        printf '%s' "$OUT" | grep -Eq -- "$pat" || ok=0
    done
    if printf '%s' "$OUT" | grep -Eq 'write error|Broken pipe'; then ok=0; name="$name [stderr noise: write error]"; fi
    if [ "$ok" -eq 1 ]; then
        PASS=$((PASS + 1))
        printf 'ok    %s\n' "$name"
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL  %s (rc=%s, wanted %s; patterns: %s)\n' "$name" "$RC" "$want" "$*"
        printf '%s\n' "$OUT" | sed 's/^/      | /'
    fi
}

check_not() { # name pattern: pattern must NOT appear
    if printf '%s' "$OUT" | grep -Eq -- "$2"; then
        FAIL=$((FAIL + 1)); printf 'FAIL  %s (unexpected: %s)\n' "$1" "$2"
        printf '%s\n' "$OUT" | sed 's/^/      | /'
    else
        PASS=$((PASS + 1)); printf 'ok    %s\n' "$1"
    fi
}

# ---------------------------------------------------------------- version logic (CLI)
new_env; stub_cli php8.3 8.3.36 1 128M n/a 8M 2M 0; run
check "fixed upstream release is PATCHED" 0 'PATCHED' 'VERDICT: PATCHED'

new_env; stub_cli php8.3 8.3.35 1 128M n/a 8M 2M 0; run
check "8.3.35 without settings is EXPOSED" 2 'EXPOSED' 'set session.upload_progress.enabled=0' 'set memory_limit=-1' 'VERDICT: EXPOSED'

new_env; stub_cli php8.3 8.3.35 0 -1 n/a 8M 2M 0; run
check "8.3.35 with official settings is MITIGATED (not safe)" 1 'MITIGATED' 'VERDICT: MITIGATED'

new_env; stub_cli php8.3 8.3.35 n/a -1 n/a 8M 2M 0; run
check "no session extension (n/a) counts as mitigated for that directive" 1 'MITIGATED'

new_env; stub_cli php8.5 8.5.11 0 -1 1 8M 2M 0; run
check "8.5 needs fatal_error_backtraces=0 to be MITIGATED" 2 'EXPOSED' 'fatal_error_backtraces=0'
new_env; stub_cli php8.5 8.5.11 0 -1 0 8M 2M 0; run
check "8.5 with fatal_error_backtraces=0 is MITIGATED" 1 'MITIGATED'

new_env; stub_cli php8.5 8.5.12RC1 1 128M 1 8M 2M 0; run
check "pre-release 8.5.12RC1 is not the fixed release" 2 'EXPOSED' 'pre-release'
new_env; stub_cli php8.3 8.3.36-dev 1 128M n/a 8M 2M 0; run
check "8.3.36-dev is not the fixed release" 2 'EXPOSED'
new_env; stub_cli php8.3 8.3.37RC1 1 128M n/a 8M 2M 0; run
check "pre-release of a LATER version is fine" 0 'PATCHED'
new_env; stub_cli php8.3 8.3.36-1+deb12u1 1 128M n/a 8M 2M 0; run
check "distro suffix after a fixed version is PATCHED" 0 'PATCHED'
new_env; stub_cli php8.2 8.2.100 1 128M n/a 8M 2M 0; run
check "version compare is numeric, not lexical (8.2.100 >= 8.2.35)" 0 'PATCHED'

new_env; stub_cli php8.6 8.6.0RC4 1 128M 1 8M 2M 0; run
check "unknown newer branch is UNKNOWN, not EXPOSED" 3 'UNKNOWN-BRANCH' 'VERDICT: UNKNOWN'
new_env; stub_cli php8.6 8.6.0 1 128M 1 8M 2M 0; run FIXED_8_6=8.6.0
check "FIXED_8_6 override classifies a newer branch" 0 'PATCHED'

new_env; stub_cli php7.4 7.4.33 1 128M n/a 8M 2M 0; run
check "end-of-life runtime is EOL-VERIFY / exit 3" 3 'EOL-VERIFY' 'VERDICT: UNKNOWN'
new_env; stub_cli php7.4 7.4.33 1 128M n/a 8M 2M 0; run PHP2SHELL_EOL_BACKPORTED=1
check "PHP2SHELL_EOL_BACKPORTED=1 counts EOL as PATCHED" 0 'PATCHED'
new_env; stub_cli php8.1 8.1.34 0 -1 n/a 8M 2M 0; run
check "EOL runtime with interim settings is MITIGATED" 1 'MITIGATED' 'end-of-life'

new_env; run
check "no runtime found is UNKNOWN" 3 'no PHP runtime found'

new_env; stub_cli php8.3 8.3.36 1 128M n/a 64M 2M 0; run
check "a PATCHED host is not nagged about post_max_size" 0 'PATCHED'
check_not "a PATCHED host prints no post_max_size warning" 'ceiling'
new_env; stub_cli php8.3 8.3.35 1 128M n/a 64M 70M 0; run
check "post_max_size / upload_max_filesize warnings" 2 'above the official 32M ceiling' 'must stay below post_max_size'

# ---------------------------------------------------------------- vendor backports
new_env; stub_cli php8.3 8.3.6 1 128M n/a 8M 2M 0
stub_dpkg_owner php8.3-cli
changelog php8.3-cli "php8.3 (8.3.6-0ubuntu0.24.04.13) noble-security; urgency=medium
  * SECURITY UPDATE: Remote RCE via state corruption issue
    - debian/patches/CVE-2026-109618_109619.patch: Avoid state corruption
    - CVE-2026-109618
    - CVE-2026-109619"
run
check "dpkg changelog listing both CVEs is a PATCHED vendor backport" 0 'PATCHED' 'vendor backport: the changelog of php8.3-cli'

new_env; stub_cli php8.3 8.3.6 1 128M n/a 8M 2M 0
stub_dpkg_owner php8.3-cli
changelog php8.3-cli "php8.3 (8.3.6-0ubuntu0.24.04.12) noble-security; urgency=medium
  * SECURITY UPDATE: something else
    - CVE-2026-92842"
run
check "dpkg changelog without the CVEs stays EXPOSED" 2 'EXPOSED'

new_env; stub_cli php8.3 8.3.6 1 128M n/a 8M 2M 0
stub_dpkg_owner php8.3-cli
changelog php8.3-cli "php8.3 (8.3.6-0ubuntu0.24.04.13) noble-security; urgency=medium
    - debian/patches/CVE-2026-109618_109619.patch: only the patch file name
    - CVE-2026-109618"
run
check "only ONE of the two CVE ids is not enough" 2 'EXPOSED'

new_env; stub_cli php7.4 7.4.33 1 128M n/a 8M 2M 0
stub_dpkg_owner php7.4-cli
changelog php7.4-cli "php7.4 (7.4.33-1ubuntu1~esm9) focal-security; urgency=medium
    - CVE-2026-109618
    - CVE-2026-109619"
run
check "vendor backport also resolves an EOL runtime" 0 'PATCHED' 'vendor backport'

new_env; stub_cli php8.2 8.2.20 1 128M n/a 8M 2M 0
cat >"$E/path/rpm" <<'EOF'
#!/bin/sh
case "$1" in
    -qf) echo "php-cli-8.2.20-1.el9" ;;
    -q)  printf '* Mon Oct 19 2026 Vendor <v@example.org> - 8.2.20-2\n- Fix CVE-2026-109618 and CVE-2026-109619\n' ;;
esac
EOF
chmod +x "$E/path/rpm"
run
check "rpm changelog listing both CVEs is a PATCHED vendor backport" 0 'PATCHED' 'vendor backport: the changelog of php-cli-8.2.20-1.el9'

# A Debian changelog is bigger than the 64 KiB pipe buffer, with the CVE ids at the top:
# `printf "$text" | grep -q` used to print "write error: Broken pipe" here.
new_env; stub_cli php8.3 8.3.6 1 128M n/a 8M 2M 0
stub_dpkg_owner php8.3-cli
mkdir -p "$E/doc/php8.3-cli"
{ printf '    - CVE-2026-109618\n    - CVE-2026-109619\n'
  yes 'php8.3 (8.3.6-0ubuntu0.24.04.1) noble-security; older entry, filler to exceed the pipe buffer' | head -n 3000
} | gzip -c >"$E/doc/php8.3-cli/changelog.Debian.gz"
SCRIPT_ARGS=(-q); run; SCRIPT_ARGS=()
check "large changelog (>64 KiB), SIGPIPE ignored: clean -q output" 0 '^VERDICT: PATCHED$'
run
check "large changelog (>64 KiB), SIGPIPE ignored: vendor backport detected" 0 'vendor backport'

# /usr/bin holds thousands of files: discovery must not fork per file (it did, 5 times: ~25 s)
new_env; stub_cli php8.3 8.3.36 1 128M n/a 8M 2M 0
for i in $(seq 1 2500); do : >"$E/bin/tool-$i"; done
chmod +x "$E"/bin/tool-*      # executable: the old code only forked for files that passed [ -x ]
T0=$SECONDS
run
T1=$((SECONDS - T0))
if [ "$T1" -le 8 ] && [ "$RC" -eq 0 ]; then
    PASS=$((PASS + 1)); echo "ok    2500 files in a bin dir are scanned quickly (${T1}s)"
else
    FAIL=$((FAIL + 1)); echo "FAIL  2500 files in a bin dir took ${T1}s (limit 8s), rc=$RC"
fi

# ---------------------------------------------------------------- PHP-FPM pools (php-fpm -tt)
new_env
stub_fpm php-fpm8.3 8.3.35 On 128M "[www]
php_admin_value[session.upload_progress.enabled] = 0
php_admin_value[memory_limit] = -1
pm.max_requests = 0
[legacy]
php_value[memory_limit] = 256M
pm.max_requests = 500
[userlevel]
php_value[session.upload_progress.enabled] = 0
php_value[memory_limit] = -1"
run
check "FPM: pool with php_admin_* is MITIGATED" 2 'pool=\[www\]' '\[MITIGATED\] fpm:[^ ]+ pool=\[www\]'
check "FPM: pool with only a bad php_value is EXPOSED" 2 '\[EXPOSED\] fpm:[^ ]+ pool=\[legacy\]'
check "FPM: php_value memory_limit is flagged as overridable" 2 'memory_limit is set with php_value'
check "FPM: pm.max_requests is reported when non-default" 2 'pm.max_requests=500'
check_not "FPM: default pm.max_requests=0 is not reported" 'pm.max_requests=0'

new_env
stub_fpm php-fpm8.3 8.3.36 On 128M "[www]
pm.max_requests = 0"
run
check "FPM: fixed version is PATCHED for every pool" 0 '\[PATCHED\] fpm:[^ ]+ pool=\[www\]'

new_env
cat >"$E/sbin/php-fpm8.3" <<'EOF'
#!/bin/sh
case "$1" in
    -v) echo "PHP 8.3.35 (fpm-fcgi)" ;;
    -i) echo 'memory_limit => 128M => 128M' ;;
    -tt) echo "[21-Oct-2026 10:00:00] ERROR: failed to load configuration file" >&2; exit 78 ;;
esac
EOF
chmod +x "$E/sbin/php-fpm8.3"
run
check "FPM: unparsable config falls back to php.ini values with a warning" 2 'php-fpm -tt failed' 'EXPOSED'

# ---------------------------------------------------------------- other SAPIs
new_env; stub_cgi php-cgi8.3 8.3.35 1 128M n/a 8M 2M 0; run
check "php-cgi is inspected" 2 '== php-cgi' '\[EXPOSED\] cgi:'

new_env; stub_v_only lsphp83 "PHP 8.3.35 (litespeed) (built: stub)"; run
check "lsphp: unpatched version is EXPOSED (version only)" 2 'lsapi:' 'version check only'
new_env; stub_v_only lsphp83 "PHP 8.3.36 (litespeed) (built: stub)"; run
check "lsphp: fixed version is PATCHED" 0 'PATCHED'

new_env; stub_v_only frankenphp "FrankenPHP v1.9.0 PHP 8.4.12 Caddy v2.10.0 h1:abc"; run
check "FrankenPHP version is parsed (8.4.12 < 8.4.27)" 2 'frankenphp:' 'PHP 8.4.12'

# ---------------------------------------------------------------- stale processes
new_env; stub_cli php8.3 8.3.36 1 128M n/a 8M 2M 0
mkdir -p "$TMP/run"
cp "$(command -v sleep)" "$TMP/run/php-fpm8.3"
"$TMP/run/php-fpm8.3" 60 &
STALE_PID=$!
sleep 0.3
rm -f "$TMP/run/php-fpm8.3"        # binary replaced on disk while the process runs
PROC_OVERRIDE=/proc run
unset PROC_OVERRIDE
kill "$STALE_PID" 2>/dev/null
check "running process on a replaced binary => EXPOSED, restart required" 2 'replaced on disk' 'RESTART' 'VERDICT: EXPOSED \(restart required'

new_env; stub_cli php8.3 8.3.36 1 128M n/a 8M 2M 0
mkdir -p "$E/proc/123"
echo "php-fpm8.3" >"$E/proc/123/comm"
printf 'Max address space         1073741824           1073741824           bytes\nMax data size             unlimited            unlimited            bytes\n' >"$E/proc/123/limits"
run
check "RLIMIT_AS on a running FPM process is reported" 0 'pid 123 \(php-fpm8.3\)' 'RLIMIT_AS'

# ---------------------------------------------------------------- CLI interface
new_env; stub_cli php8.3 8.3.36 1 128M n/a 8M 2M 0
SCRIPT_ARGS=(-q); run; SCRIPT_ARGS=()
check "-q prints only the verdict" 0 '^VERDICT: PATCHED$'
if [ "$(printf '%s\n' "$OUT" | wc -l)" -eq 1 ]; then
    PASS=$((PASS + 1)); echo "ok    -q output is a single line"
else
    FAIL=$((FAIL + 1)); echo "FAIL  -q output is a single line"; printf '%s\n' "$OUT" | sed 's/^/      | /'
fi

OUT=$(bash "$SCRIPT" --version 2>&1); RC=$?
check "--version" 0 '^check-php2shell.sh [0-9]+\.[0-9]+\.[0-9]+$'
OUT=$(bash "$SCRIPT" -h 2>&1); RC=$?
check "-h prints usage and exit codes" 0 'Usage:' 'Exit codes'
OUT=$(bash "$SCRIPT" --bogus 2>&1); RC=$?
check "unknown option exits 64" 64 'unknown option'

# ---------------------------------------------------------------- summary
echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
