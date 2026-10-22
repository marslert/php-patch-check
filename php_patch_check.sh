#!/usr/bin/env bash
#
# php_patch_check.sh
#
# Checks installed PHP packages against the minimum patched versions and
# confirms the CVE fixes appear in the package changelogs.
#
#   cPanel EasyApache4     ea-phpNN             (cPanel version table)
#   CloudLinux EasyApache4 ea-phpNN             (CloudLinux version table)
#   Plesk                  plesk-phpNN          (cPanel version table)
#   Debian / Ubuntu        changelog check only (no version table)
#
# Usage: bash php_patch_check.sh [--table auto|cpanel|cloudlinux]
#
# Run as root on the server. --table defaults to auto: CloudLinux if
# cloudlinux-release is installed, otherwise cPanel.

set -u

CVES="CVE-2026-109618 CVE-2026-109619"
ALL_MINORS="52 53 54 55 56 70 71 72 73 74 80 81 82 83 84 85"
TABLE=auto

CVE_PKGS=()   # packages whose changelog is searched for the CVEs

usage() { sed -n '2,16p' "$0"; }

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --table) TABLE=${2:-}; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; exit 2 ;;
    esac
  done
  case "$TABLE" in
    auto|cpanel|cloudlinux) ;;
    *) echo "Invalid --table value: $TABLE" >&2; exit 2 ;;
  esac
}

# Minimum patched version-release per PHP minor (cPanel EasyApache4)
min_cpanel() {
  case "$1" in
    74) echo 7.4.33-19 ;;
    80) echo 8.0.30-12 ;;
    81) echo 8.1.34-5 ;;
    82) echo 8.2.35 ;;
    83) echo 8.3.36 ;;
    84) echo 8.4.27 ;;
    85) echo 8.5.12 ;;
  esac
}

# Minimum patched version-release per PHP minor (CloudLinux EasyApache4)
min_cloudlinux() {
  case "$1" in
    52) echo 5.2.17-27 ;;
    53) echo 5.3.29-29 ;;
    54) echo 5.4.45-82 ;;
    55) echo 5.5.38-64 ;;
    56) echo 5.6.40-25 ;;
    70) echo 7.0.33-29 ;;
    71) echo 7.1.33-20 ;;
    72) echo 7.2.34-12 ;;
    73) echo 7.3.33-15 ;;
    74) echo 7.4.33-18 ;;
    80) echo 8.0.30-11 ;;
    81) echo 8.1.34-4 ;;
    82) echo 8.2.34-2 ;;
    83) echo 8.3.35-2 ;;
    84) echo 8.4.26-2 ;;
    85) echo 8.5.11-2 ;;
  esac
}

min_for() {
  if [ "$TABLE" = cloudlinux ]; then
    min_cloudlinux "$1"
  else
    min_cpanel "$1"
  fi
}

detect_table() {
  if rpm -q cloudlinux-release >/dev/null 2>&1; then
    echo cloudlinux
  else
    echo cpanel
  fi
}

# Split an EVR such as 7.4.33-19.1.cpanel.el8 into V=7.4.33 and R=19
split_evr() {
  case "$1" in
    *-*) V=${1%-*}; R=${1##*-} ;;
    *)   V=$1; R=0 ;;
  esac
  R=${R%%[!0-9]*}
  R=${R:-0}
}

# Returns 0 when installed version $1 is older than minimum $2
is_older() {
  local cur_v cur_r min_v min_r
  split_evr "$1"; cur_v=$V; cur_r=$R
  split_evr "$2"; min_v=$V; min_r=$R
  if [ "$cur_v" != "$min_v" ]; then
    [ "$(printf '%s\n%s\n' "$cur_v" "$min_v" | sort -V | head -n 1)" = "$cur_v" ]
  else
    [ "$cur_r" -lt "$min_r" ]
  fi
}

has_pkg() { rpm -q "$1" >/dev/null 2>&1; }

has_prefix() { rpm -qa --qf '%{NAME}\n' | grep -q "^$1"; }

installed_evr() { rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$1" | head -n 1; }

# $1 package to read the version from, $2 minimum version, $3 package whose changelog holds the CVE fixes,
# $4 "upstream" to compare only the PHP version (Plesk release numbers are not comparable with cPanel's)
check_pkg() {
  local pkg=$1 min=$2 cl_pkg=$3 mode=${4:-full} cur cmp_cur cmp_min
  if ! has_pkg "$pkg"; then
    echo "$pkg: not installed"
    return 1
  fi
  cur=$(installed_evr "$pkg")
  if [ "$mode" = upstream ]; then
    cmp_cur=${cur%%-*}; cmp_min=${min%%-*}
  else
    cmp_cur=$cur; cmp_min=$min
  fi
  if is_older "$cmp_cur" "$cmp_min"; then
    echo "$pkg: $cur - [ danger ]"
  else
    echo "$pkg: $cur - [ safe ]"
  fi
  CVE_PKGS+=("$cl_pkg")
}

# Version from each installed binary (php -v); CVEs from the ea-phpNN-php-cli changelog
check_ea4() {
  local php pkg m min ver
  for php in /opt/cpanel/ea-php*/root/usr/bin/php; do
    [ -x "$php" ] || continue
    pkg=$(printf '%s\n' "$php" | sed -E 's#.*/(ea-php[0-9]+)/root/usr/bin/php#\1#')
    m=${pkg#ea-php}
    ver=$("$php" -v | head -n 1 | awk '{print $2}')
    min=$(min_for "$m")
    if [ -z "$min" ]; then
      echo "$pkg: $ver - [ unknown: no minimum in table ]"
    elif is_older "$ver" "${min%%-*}"; then
      echo "$pkg: $ver - [ danger ]"
    else
      echo "$pkg: $ver - [ safe ]"
    fi
    CVE_PKGS+=("$pkg-php-cli")
  done
}

# Minor versions (e.g. 74 82 83) that Plesk reports as installed
plesk_minors() {
  plesk bin php_handler --list 2>/dev/null \
    | grep -oE 'php/[0-9]+\.[0-9]+|plesk-php[0-9]{2}|php[0-9]{2}' \
    | sed -E 's#^php/([0-9]+)\.([0-9]+)$#\1\2#; s#^plesk-php##; s#^php##' \
    | sort -u
}

check_plesk() {
  local m min pkg cur minors
  minors=$(plesk_minors)
  if [ -z "$minors" ]; then
    echo "plesk bin php_handler --list returned no PHP versions"
    return 1
  fi
  for m in $minors; do
    # the -cli package carries the changelog; the plesk-phpNN metapackage has none
    pkg="plesk-php$m-cli"
    has_pkg "$pkg" || pkg="plesk-php$m"
    if ! has_pkg "$pkg"; then
      echo "plesk-php$m: listed by php_handler but no package found"
      continue
    fi
    min=$(min_for "$m")
    if [ -z "$min" ]; then
      cur=$(installed_evr "$pkg")
      echo "$pkg: $cur - [ unknown: no minimum in table ]"
      CVE_PKGS+=("$pkg")
      continue
    fi
    check_pkg "$pkg" "$min" "$pkg" upstream
  done
  echo "(Plesk status compares the PHP version only, not the Plesk release; see the CVE check below)"
}

check_cves() {
  local pkg cve log
  for pkg in "${CVE_PKGS[@]}"; do
    log=$(rpm -q --changelog "$pkg" 2>/dev/null)
    if [ -z "$log" ]; then
      echo "$pkg: package has no changelog, cannot confirm CVEs"
      continue
    fi
    for cve in $CVES; do
      if printf '%s\n' "$log" | grep -qFw -- "$cve"; then
        echo "$pkg  $cve: found in changelog"
      else
        echo "$pkg  $cve: NOT found in changelog"
      fi
    done
  done
}

# Debian / Ubuntu: no version table, so only the changelog is checked
check_debian() {
  local pkg ver cve found=0
  while read -r pkg ver; do
    found=1
    echo "$pkg: $ver - [ unknown: no version table ]"
    for cve in $CVES; do
      if zcat -f "/usr/share/doc/$pkg"/changelog* 2>/dev/null | grep -qFw -- "$cve"; then
        echo "  $cve: found in changelog"
      else
        echo "  $cve: NOT found in changelog"
      fi
    done
  done < <(dpkg-query -W -f='${Package} ${Version}\n' 'php[0-9]*-cli' 2>/dev/null)
  [ $found -eq 1 ] || echo "no php*-cli packages found"
}

main() {
  parse_args "$@"
  [ "$TABLE" = auto ] && TABLE=$(detect_table)

  if command -v rpm >/dev/null 2>&1; then
    local ran=0
    if ls /opt/cpanel/ea-php*/root/usr/bin/php >/dev/null 2>&1; then
      echo; echo "== EasyApache4 (ea-php, $TABLE table; PHP version from php -v, release not compared) =="
      check_ea4
      ran=1
    fi
    if command -v plesk >/dev/null 2>&1; then
      echo; echo "== Plesk (from plesk bin php_handler --list, upstream PHP version only) =="
      check_plesk
      ran=1
    fi
    if [ $ran -eq 0 ]; then
      echo "No ea-php or plesk-php packages installed."
      exit 1
    fi
    if [ ${#CVE_PKGS[@]} -gt 0 ]; then
      echo; echo "== CVE changelog check ($CVES) =="
      check_cves
    fi
  elif command -v dpkg-query >/dev/null 2>&1; then
    echo; echo "== Debian / Ubuntu php packages =="
    check_debian
  else
    echo "Neither rpm nor dpkg found." >&2
    exit 1
  fi
}

main "$@"
