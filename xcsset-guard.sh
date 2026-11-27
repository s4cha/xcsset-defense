#!/bin/bash
#
# xcsset-guard.sh — detect and (optionally) clean XCSSET macOS malware artifacts.
#
#   * SCAN-ONLY by default. Nothing is changed unless you pass --clean.
#   * --clean MOVES files into a quarantine folder (with a manifest) instead of
#     deleting them, and asks before each item unless --yes is given.
#   * Never deletes legitimate software: e.g. com.google.* LaunchDaemons are only flagged
#     when the program they run is NOT signed by Google (Chrome's real updater is left alone).
#   * Covers XCSSET up to v40 (Unit 42, Jul 2026): hex/Base64-hidden Xcode payloads, Git history,
#     zipped projects, hijacked browsers, trojanized Telegram, hidden preference payloads, Dock
#     persistence, XProtect tampering, ~90 server domains + IPs (system log and live connections).
#   * Reports folders macOS privacy protection won't let it read (Desktop, Documents, Downloads,
#     iCloud Drive) instead of silently skipping them. Grant Full Disk Access to the app you run
#     it from (Terminal, or XCSSET Guard) for a complete scan.
#   * Runs on the stock macOS bash 3.2.
#
# Usage:
#   bash xcsset-guard.sh                     # scan only (no sudo needed, some checks limited)
#   sudo bash xcsset-guard.sh                # full scan
#   sudo bash xcsset-guard.sh --clean        # scan, then quarantine findings (asks each time)
#
# Options:
#   --clean          Quarantine/fix what the scan finds.
#   --yes            Don't ask before each fix (use with --clean).
#   --root DIR       Where to look for Git hooks and Xcode projects (default: your home folder).
#   --log-window W   How far back to search the system log for C2 domains: e.g. 30m, 2h, 1d
#                    (default 2h; 0 skips). Roughly 6–7 minutes per day searched.
#   --report FILE    Also write findings to FILE as tab-separated kind/path/reason (used by the app).
#   --apply FILE     Skip the scan; fix exactly the findings listed in FILE (same format), no prompts.
#   --user NAME      Whose home folder to check (default: you, or the user who ran sudo).
#   -h, --help       Show this help.
#
# Exit code: 0 = nothing found (or --apply done), 1 = findings, 2 = usage error.

set -u
# Trusted system tools first (matters under sudo / when launched from the app).
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin"

# ---------------------------------------------------------------- options
MODE=scan
ASSUME_YES=0
SCAN_ROOT=""
LOG_WINDOW=2h
REPORT_FILE=""
APPLY_FILE=""
USER_OVERRIDE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --clean) MODE=clean ;;
    --yes|-y) ASSUME_YES=1 ;;
    --root) shift; SCAN_ROOT="${1:-}" ;;
    --log-window) shift; LOG_WINDOW="${1:-2h}" ;;
    --report) shift; REPORT_FILE="${1:-}" ;;
    --apply) shift; APPLY_FILE="${1:-}"; MODE=apply ;;
    --user) shift; USER_OVERRIDE="${1:-}" ;;
    -h|--help) awk 'NR <= 2 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)"; exit 2 ;;
  esac
  shift
done
if [ "$LOG_WINDOW" != 0 ] && ! echo "$LOG_WINDOW" | grep -qE '^[0-9]+[mhd]$'; then
  echo "--log-window needs a value like 30m, 2h, 1d or 0"; exit 2
fi

# ---------------------------------------------------------------- who are we scanning for
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
if [ "$MODE" = apply ] && [ ! -f "$APPLY_FILE" ]; then echo "--apply: file not found: $APPLY_FILE"; exit 2; fi
if [ -n "$USER_OVERRIDE" ]; then
  id -u "$USER_OVERRIDE" >/dev/null 2>&1 || { echo "--user: no such user: $USER_OVERRIDE"; exit 2; }
  TARGET_USER="$USER_OVERRIDE"
elif [ "$IS_ROOT" -eq 1 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
  TARGET_USER="$SUDO_USER"
else
  TARGET_USER="$(id -un)"
fi
USER_HOME="$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[ -n "$USER_HOME" ] || USER_HOME="$HOME"
TARGET_UID="$(id -u "$TARGET_USER")"
[ -n "$SCAN_ROOT" ] || SCAN_ROOT="$USER_HOME"
if [ ! -d "$SCAN_ROOT" ]; then echo "--root: not a folder: $SCAN_ROOT"; exit 2; fi
SCAN_ROOT="${SCAN_ROOT%/}"

# Where to look for Git repos / Xcode projects / zips. iCloud Drive lives under ~/Library (which is
# skipped for speed), so it's added explicitly whenever the user's home folder is being scanned.
ICLOUD_DRIVE="$USER_HOME/Library/Mobile Documents/com~apple~CloudDocs"
SCAN_ROOTS=("$SCAN_ROOT")
SCAN_LABEL="$SCAN_ROOT"
case "$USER_HOME/" in
  "$SCAN_ROOT"/*)
    if [ -d "$ICLOUD_DRIVE" ]; then SCAN_ROOTS+=("$ICLOUD_DRIVE"); SCAN_LABEL="$SCAN_ROOT + iCloud Drive"; fi ;;
esac

# Folders protected by macOS privacy controls (TCC). Without permission, reading them fails
# silently, so they're checked up front and reported instead of quietly skipped.
PROTECTED_DIRS=("$USER_HOME/Desktop" "$USER_HOME/Documents" "$USER_HOME/Downloads" "$ICLOUD_DRIVE")
if [ -n "${XCSSET_GUARD_APP:-}" ]; then FDA_APP="XCSSET Guard"; else FDA_APP="the app you run this from (e.g. Terminal)"; fi

TS="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$USER_HOME/xcsset-guard-$TS.log"
QDIR="$USER_HOME/xcsset-quarantine/$TS"
exec > >(tee -a "$LOG_FILE") 2>&1

# ---------------------------------------------------------------- IOCs
# Sources: Trend Micro (2020), Microsoft (Mar + Sep 2025), Unit 42 "XCSSET v40" (Jul 2026).

# Fixed file paths dropped by XCSSET variants.
#   v40: /tmp/r = main loader, /tmp/p.app = AppleScript wrapper, ~/.tr / ~/.tr_map = stolen Telegram config
IOC_FILES="/tmp/l.app /tmp/b /tmp/.n /tmp/out.txt /tmp/.f /tmp/.i /tmp/.e /tmp/ancr /tmp/xmyyeqjx
/tmp/r /tmp/p.app $USER_HOME/.root $USER_HOME/.a $USER_HOME/.zshrc_aliases $USER_HOME/.tr $USER_HOME/.tr_map"

# Known malicious SHA-256 hashes (/tmp/b x2, /tmp/ancr, /tmp/xmyyeqjx, jey git-persistence module).
IOC_SHA256="d338dc9a75a14753f57399815b5d996a1c5e65aa4eb203222d8c85fb3d74b02f
5a212c5ce1e0f41e721ce0940afb381b694a2e32a6d19c1d2210f703636362df
12ea52c4089d100e679a2350f03e598b2f3feebfbbd2ed5631a2a7a20b07e826
f3bc158619b2aad17def966f0ac8dddc2107e4911a7c488d358d906f27ac2a2b
0fbd0e1995472f308cf1ac8229a02c277035404426769fa50947a72c95ad7d31"

# Apps the real macOS never installs in /Applications (real ones live in /System).
FAKE_APPS="Terminal Finder Reminders SimulatorTrampoline Notes"

# Apps XCSSET v40 hijacks or trojanizes; each must still be a genuine, properly signed app.
WATCHED_APPS="Google Chrome|Brave Browser|Microsoft Edge|Firefox|Opera|Yandex|Arc|Vivaldi|Telegram|Telegram Desktop|Telegram Lite"

# C2 domains reported for XCSSET (older reports + Microsoft Sep 2025 + Unit 42 v40). Deduplicated at runtime.
C2_DOMAINS="bulknames.ru castlenet.ru cdntor.ru suppro.co alinbox.co everestnote.com truckrental.cc
checkcdn.ru applecdn.ru figmacat.ru elemark.co cralev.me liveupdate.cc appmarket.co recentnews.cc
unisyscat.ru updcdnapple.ru videocdnapp.ru gironetcdn.ru
cdcache.ru flowcdn.ru elasticdns.ru rublenet.ru figmastars.ru bulksec.ru adobetrix.ru digichat.ru
diggimax.ru cdnroute.ru sigmanow.ru fixmates.ru mdscache.ru trinitysol.ru verifysign.ru digitalcdn.ru
windsecure.ru adobecdn.ru
accapple.ru adschecks.ru adsmobi.ru adsmorein.in adsmoreme.in amdcdn.ru amzndev.in amzndev.ru
amznprod.in appledisk.ru appledns.ru applehosts.ru appletime.in cdnamz.in cdnamz.ru cdnapple.in
cdnatapple.ru chromeads.ru cnmag.ru devnetaps.ru dnsapple.ru dnsrelays.ru explorecdn.ru fiddlejoy.ru
figmanets.in funchats.ru goalmate.ru googlenets.ru greencn.ru icloudsnet.ru imails.ru legalads.in
littleads.in littledns.ru maganet.ru mindelgate.ru netapsdev.ru netcdnads.in netcdnamz.ru netcdndev.in
netcorps.ru netsprot.in netsproto.in networkads.in rigacdn.in rigmajoys.in rigmanet.ru rigmanets.in
sahusuzuki.in stuffdns.in testjoys.ru timewebnet.in vigmanet.ru whitead.in whiteads.ru wincdn.ru"
C2_DOMAINS="$(echo $C2_DOMAINS | tr ' ' '\n' | sort -u | tr '\n' ' ')"

# C2 IP addresses (Unit 42 v40).
C2_IPS="91.108.106.229 95.142.35.34 95.142.35.206 95.142.37.159 151.243.109.188 178.208.92.129 178.208.92.168"

# v40 hides a Base64 payload in a per-host preferences domain under these keys.
PREF_KEYS='mpirv_eahpi_apm|ychax_muwch_ucy'

XPROTECT_MAX_AGE_DAYS=60
GOOGLE_TEAM_ID="EQHXZ8M8AV"

# Folders skipped when walking $SCAN_ROOT (huge and/or irrelevant).
PRUNE_NAMES="Library .Trash xcsset-quarantine node_modules Movies Music Pictures .cache .npm .cargo .rustup DerivedData"

# ---------------------------------------------------------------- helpers
FINDINGS=()          # "kind|path|reason"
INFO_COUNT=0

hdr()  { printf '\n== %s\n' "$1"; }
ok()   { printf '   ok  %s\n' "$1"; }
info() { printf '   --  %s\n' "$1"; INFO_COUNT=$((INFO_COUNT+1)); }
flag() { FINDINGS+=("$1|$2|$3"); printf '   !!  %s\n       %s\n' "$2" "$3"; }

sha256() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }
known_bad() { local h; h="$(sha256 "$1")"; [ -n "$h" ] && echo "$IOC_SHA256" | grep -qx "$h"; }

# True if a project.pbxproj's text has a build phase that decodes hidden code and runs it.
# v40 hides the download behind nested hex/Base64 layers, so `curl` is usually NOT visible.
pbx_suspicious() {
  local c="$1"
  # No requirement for a script build phase: v40 also hides the payload in a build setting and runs
  # it through a legacy "external build tool" target (buildArgumentsString = "-c \"${XXXX}\"").
  echo "$c" | grep -qE 'xxd[[:space:]]+-p[[:space:]]+-r|base64[[:space:]]+(-d|-D|--decode)' || return 1
  echo "$c" | grep -qE '\|[[:space:]]*(/bin/)?(ba|z)?sh([^a-zA-Z_]|$)' && return 0
  echo "$c" | grep -qE 'curl' && echo "$c" | grep -qF '>/dev/null 2>&1' && return 0
  return 1
}

# Prints a problem description if an app bundle is not a genuine, properly signed app; nothing if fine.
# $2 = "verify" also checks the code seal (fast for most apps, very slow for Xcode).
app_sig_problem() {
  local app="$1" exe info
  exe="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist" 2>/dev/null)"
  if [ -z "$exe" ] || [ ! -f "$app/Contents/MacOS/$exe" ]; then echo "its main program is missing"; return; fi
  if ! file -b "$app/Contents/MacOS/$exe" | grep -q 'Mach-O'; then
    echo "its main program is a script, not an app binary (launcher replaced: XCSSET v40 browser hijack)"; return
  fi
  info="$(codesign -dv --verbose=2 "$app" 2>&1)"
  if echo "$info" | grep -q 'Signature=adhoc'; then echo "ad hoc signed, with no developer identity (XCSSET re-signs fakes this way)"; return; fi
  if ! echo "$info" | grep -q '^Authority=Apple Root CA'; then echo "not signed with an Apple-issued developer certificate"; return; fi
  if [ "${2:-}" = verify ] && ! codesign --verify "$app" >/dev/null 2>&1; then
    echo "its code signature is broken (files were changed after signing)"
  fi
}

prune_expr() {   # builds: ( -name A -o -name B ... ) -prune
  local first=1 n
  printf '(\n'
  for n in $PRUNE_NAMES; do
    [ $first -eq 1 ] && first=0 || printf -- '-o\n'
    printf -- '-name\n%s\n' "$n"
  done
  printf ')\n-prune\n'
}
PRUNE_ARGS=(); while IFS= read -r a; do PRUNE_ARGS+=("$a"); done < <(prune_expr)

confirm() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  local ans
  read -r -p "   -> $1 [y/N] " ans </dev/tty || return 1
  [ "$ans" = y ] || [ "$ans" = Y ]
}

team_id_of() {   # prints the code-signing Team ID of a binary/app, or nothing
  codesign -dv "$1" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2}'
}

plist_program() {  # prints the program a launchd plist runs
  local p="$1" prog
  prog="$(/usr/libexec/PlistBuddy -c 'Print :Program' "$p" 2>/dev/null)"
  [ -n "$prog" ] || prog="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$p" 2>/dev/null)"
  printf '%s' "$prog"
}

quarantine() {   # move a path into $QDIR, preserving its full path; record in manifest
  local src="$1" dest="$QDIR$1"
  if [ ! -e "$src" ] && [ ! -L "$src" ]; then echo "       (already gone)"; return 0; fi
  if ! mkdir -p "$(dirname "$dest")" 2>/dev/null || ! mv "$src" "$dest" 2>/dev/null; then
    echo "       FAILED to move (try again with sudo): $src"; return 1
  fi
  find "$dest" -type f -exec chmod a-x {} + 2>/dev/null
  printf '%s\t%s\n' "$src" "$dest" >> "$QDIR/MANIFEST.tsv"
  echo "       moved to quarantine: $dest"
}

echo "xcsset-guard  $(date)"
echo "mode=$MODE  user=$TARGET_USER  home=$USER_HOME  root=$IS_ROOT  scan-root=$SCAN_ROOT"
[ "$IS_ROOT" -eq 0 ] && echo "(not running as root: system LaunchDaemons can be read but not cleaned)"

if [ "$MODE" = apply ]; then
  # Fix exactly what the caller (the app) selected from an earlier scan.
  ASSUME_YES=1
  while IFS="$(printf '\t')" read -r k p r; do
    case "$k" in proc|file|app|rc|launchd|hook|update|zip|pref|xprotect) FINDINGS+=("$k|$p|$r") ;; esac
  done < "$APPLY_FILE"
  echo "Applying ${#FINDINGS[@]} selected fix(es)."
  [ "${#FINDINGS[@]}" -eq 0 ] && exit 0
else

# ================================================================ 0. folder access
hdr "0. Folders the scan can read"
BLOCKED=0; INSCOPE=0
for d in "${PROTECTED_DIRS[@]}"; do
  [ -d "$d" ] || continue
  # Only matters if the folder is inside what we were asked to scan.
  inscope=0
  for r in "${SCAN_ROOTS[@]}"; do case "$d/" in "$r"/*) inscope=1;; esac; done
  [ "$inscope" -eq 1 ] || continue
  INSCOPE=$((INSCOPE+1))
  if ! ls "$d" >/dev/null 2>&1; then
    flag access "$d" "macOS privacy protection blocked reading this folder, so it was NOT scanned. Give Full Disk Access to $FDA_APP and scan again."
    BLOCKED=$((BLOCKED+1))
  fi
done
if [ "$INSCOPE" -eq 0 ]; then
  ok "no privacy-protected folders inside the scan folder"
elif [ "$BLOCKED" -eq 0 ]; then
  ok "all $INSCOPE privacy-protected folder(s) are readable"
fi

# ================================================================ 1. processes
hdr "1. Suspicious processes"
PROC_HITS=0
while IFS= read -r line; do
  pid="${line%% *}"; cmd="${line#* }"
  reason=""
  case "$cmd" in
    /Applications/Terminal.app/*|/Applications/Finder.app/*|/Applications/Reminders.app/*|\
    /Applications/SimulatorTrampoline.app/*|/Applications/Notes.app/*)
      reason="system app running from /Applications (real one lives in /System)";;
    *HackBrowserData*|*hack-browser-data*)
      reason="browser-data stealer used by XCSSET";;
    */tmp/*.app/*|/private/tmp/*.app/*)
      reason="app running from /tmp";;
    *"System Settings.app"*)
      case "$cmd" in /System/Applications/*) ;; *) reason="fake System Settings app";; esac;;
    /tmp/b|/tmp/b\ *|/tmp/r|/tmp/r\ *|/tmp/ancr*|/tmp/xmyyeqjx*|\
    /private/tmp/b|/private/tmp/b\ *|/private/tmp/r|/private/tmp/r\ *)
      reason="known XCSSET payload path";;
  esac
  if [ -z "$reason" ] && echo "$cmd" | grep -qE '(^|/)(chrome|firefox|opera|yandex|brave|edge|360|safari|browser)_remote( |$)'; then
    reason="XCSSET v40 browser-hijack backdoor"
  fi
  if [ -z "$reason" ] && echo "$cmd" | grep -qiE '(^|/)perl[0-9.]*( |$)' && echo "$cmd" | grep -qiE 'xprotect|xpdb'; then
    reason="Perl process touching XProtect's database (v40 locks it to block malware definition updates)"
  fi
  if [ -n "$reason" ]; then flag proc "$pid $cmd" "$reason"; PROC_HITS=$((PROC_HITS+1)); fi
  # A browser started with remote debugging but no separate profile = v40 hijack pattern.
  # (Automation tools such as Playwright/Puppeteer always pass --user-data-dir.)
  case "$cmd" in
    */Contents/MacOS/*--remote-debugging-port*)
      case "$cmd" in *Helper*|*--type=*) ;; *)
        if echo "$cmd" | grep -q -- '--user-data-dir'; then
          info "browser running with remote debugging (separate profile, likely a dev tool): ${cmd:0:140}"
        else
          flag browser "$pid $cmd" "browser running with remote debugging on your normal profile (XCSSET v40 uses this to inject code)"
          PROC_HITS=$((PROC_HITS+1))
        fi;;
      esac;;
  esac
done < <(ps -axo pid=,command= | sed 's/^ *//' | grep -v -- "$0")
# Anything (normally a Perl process) holding XProtect's database open.
if command -v lsof >/dev/null 2>&1; then
  while read -r pname ppid; do
    case "$pname" in perl*) flag proc "$ppid $(ps -p "$ppid" -o command= 2>/dev/null)" "Perl process holding XProtect's database open (v40 defense evasion)"; PROC_HITS=$((PROC_HITS+1));; esac
  done < <(lsof -nP +D /private/var/protected/xprotect 2>/dev/null | awk 'NR>1{print $1, $2}' | sort -u)
fi
[ "$PROC_HITS" -eq 0 ] && ok "none"
OSA="$(ps -axo pid=,command= | grep -E '(^|/)osascript( |$)' | grep -v grep)"
[ -n "$OSA" ] && info "osascript is running (usually legit, review): $(echo "$OSA" | head -3 | tr '\n' ';')"

# ================================================================ 2. dropped files
hdr "2. Known dropped files"
FILE_HITS=0
for f in $IOC_FILES /tmp/?.app /private/tmp/?.app; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  reason="known XCSSET artifact path"
  [ -f "$f" ] && known_bad "$f" && reason="KNOWN MALICIOUS FILE (hash match)"
  flag file "$f" "$reason"; FILE_HITS=$((FILE_HITS+1))
done
FCACHE="$USER_HOME/Library/Caches/com.apple.finder"
if [ -d "$FCACHE" ]; then
  while IFS= read -r -d '' x; do
    flag file "$x" "app or executable hidden in Finder's cache folder"; FILE_HITS=$((FILE_HITS+1))
  done < <(find "$FCACHE" \( -name '*.app' -prune -o -type f -perm +111 \) -print0 2>/dev/null)
fi
[ "$FILE_HITS" -eq 0 ] && ok "none"

# ================================================================ 3. fake apps
hdr "3. Fake system apps in /Applications"
APP_HITS=0
for a in $FAKE_APPS "System Settings"; do
  p="/Applications/$a.app"
  [ -e "$p" ] || continue
  tid="$(team_id_of "$p")"
  flag app "$p" "fake copy of a macOS system app (signer: ${tid:-unsigned})"; APP_HITS=$((APP_HITS+1))
done
[ "$APP_HITS" -eq 0 ] && ok "none"

# ================================================================ 4. hijacked / trojanized apps
hdr "4. Browsers, Telegram and Xcode are genuine"
SIG_HITS=0; SIG_CHECKED=""
OLDIFS="$IFS"; IFS='|'
for name in $WATCHED_APPS; do
  IFS="$OLDIFS"
  for base in /Applications "$USER_HOME/Applications"; do
    p="$base/$name.app"; [ -d "$p" ] || continue
    prob="$(app_sig_problem "$p" verify)"
    if [ -n "$prob" ]; then flag sig "$p" "$prob"; SIG_HITS=$((SIG_HITS+1)); else SIG_CHECKED="$SIG_CHECKED, $name"; fi
  done
  IFS='|'
done
IFS="$OLDIFS"
for p in /Applications/Xcode*.app; do
  [ -d "$p" ] || continue
  prob="$(app_sig_problem "$p")"   # no full seal check: takes ~15 s on Xcode
  if [ -n "$prob" ]; then flag sig "$p" "$prob"; SIG_HITS=$((SIG_HITS+1)); else SIG_CHECKED="$SIG_CHECKED, $(basename "$p" .app)"; fi
done
if [ "$SIG_HITS" -eq 0 ]; then
  if [ -n "$SIG_CHECKED" ]; then ok "genuine: ${SIG_CHECKED#, }"; else ok "none of these apps installed"; fi
fi

# ================================================================ 5. shell startup files
hdr "5. Shell startup files"
RC_HITS=0
RC_PATTERN='zshrc_aliases|curl[^|]*\|[[:space:]]*(ba|z)?sh|base64[[:space:]]+(-d|-D|--decode)|xxd[[:space:]]+-p[[:space:]]+-r|osascript[[:space:]]+-e'
for rc in .zshrc .zshenv .zprofile .zlogin .bash_profile .bashrc .profile; do
  f="$USER_HOME/$rc"; [ -f "$f" ] || continue
  m="$(grep -nE "$RC_PATTERN" "$f" 2>/dev/null)"
  [ -n "$m" ] || continue
  flag rc "$f" "suspicious line(s): $(echo "$m" | head -3 | tr '\n' ' ')"; RC_HITS=$((RC_HITS+1))
done
[ "$RC_HITS" -eq 0 ] && ok "none"

# ================================================================ 6. launchd persistence
hdr "6. LaunchDaemons / LaunchAgents"
LD_HITS=0
for dir in /Library/LaunchDaemons /Library/LaunchAgents "$USER_HOME/Library/LaunchAgents"; do
  [ -d "$dir" ] || continue
  while IFS= read -r -d '' pl; do
    prog="$(plist_program "$pl")"
    args="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments' "$pl" 2>/dev/null | tr '\n' ' ')"
    name="$(basename "$pl")"
    reason=""
    case "$prog" in
      /tmp/*|/private/tmp/*|/var/folders/*|/private/var/folders/*|"$USER_HOME"/.*)
        reason="runs a program from a temp or hidden folder: $prog";;
    esac
    if [ -z "$reason" ] && echo "$args" | grep -qE 'curl|base64|xxd|osascript|/\.root'; then
      reason="arguments download/decode code: $(echo "$args" | cut -c1-160)"
    fi
    if [ -z "$reason" ]; then
      case "$name" in com.google.*)
        if [ -z "$prog" ] || [ ! -e "$prog" ]; then
          reason="Google-named job whose program is missing: ${prog:-<none>}"
        elif [ "$(team_id_of "$prog")" != "$GOOGLE_TEAM_ID" ]; then
          reason="Google-named job NOT signed by Google: $prog"
        fi;;
      esac
    fi
    if [ -n "$reason" ]; then flag launchd "$pl" "$reason"; LD_HITS=$((LD_HITS+1)); fi
  done < <(find "$dir" -maxdepth 1 -name '*.plist' -print0 2>/dev/null)
done
[ "$LD_HITS" -eq 0 ] && ok "none"
if ls /Library/LaunchDaemons/com.google.GoogleUpdater* /Library/LaunchAgents/com.google.* \
      "$USER_HOME/Library/LaunchAgents/com.google."* >/dev/null 2>&1 \
   || [ -d "/Library/Application Support/Google/GoogleUpdater" ] \
   || [ -d "$USER_HOME/Library/Application Support/Google/GoogleUpdater" ]; then
  ok "Chrome's real updater is installed"
elif [ -d "/Applications/Google Chrome.app" ]; then
  info "Chrome is installed but its updater is missing (reinstall Chrome from google.com/chrome)"
fi

# ================================================================ 7. hidden preference payloads
hdr "7. Hidden payloads in preference files"
PREF_HITS=0
while IFS= read -r -d '' pf; do
  flag pref "$pf" "contains XCSSET v40's hidden Base64 payload keys"; PREF_HITS=$((PREF_HITS+1))
done < <(grep -rlE --null --include='*.plist' "$PREF_KEYS" "$USER_HOME/Library/Preferences" /Library/Preferences 2>/dev/null)
[ "$PREF_HITS" -eq 0 ] && ok "none"

# ================================================================ 8. Dock
hdr "8. Dock icons"
DOCK_HITS=0
DOCK="$USER_HOME/Library/Preferences/com.apple.dock.plist"
if [ -f "$DOCK" ]; then
  while IFS= read -r url; do
    p="${url#file://}"; p="${p%/}"; p="$(printf '%b' "${p//\%/\\x}")"
    case "$p" in
      /Applications/*|/System/Applications/*|/System/Library/CoreServices/*|/System/Cryptexes/*|\
      /System/Volumes/Preboot/Cryptexes/*|"$USER_HOME"/Applications/*) ;;
      *) flag dock "$p" "Dock icon opens something outside the Applications folders (XCSSET swaps Dock icons for fake apps)"
         DOCK_HITS=$((DOCK_HITS+1));;
    esac
  done < <(/usr/libexec/PlistBuddy -c 'Print :persistent-apps' "$DOCK" 2>/dev/null | grep -a '_CFURLString = ' | sed 's/.*_CFURLString = //')
fi
[ "$DOCK_HITS" -eq 0 ] && ok "none"

# ================================================================ 9. git hooks
hdr "9. Git hooks under $SCAN_LABEL"
HOOK_HITS=0
check_hook() {
  local h="$1"
  case "$h" in *.sample) return;; esac
  if known_bad "$h"; then
    flag hook "$h" "KNOWN MALICIOUS FILE (hash match: XCSSET git persistence)"; HOOK_HITS=$((HOOK_HITS+1))
  elif grep -qE 'curl|xxd|base64|osascript' "$h" 2>/dev/null; then
    flag hook "$h" "hook downloads/decodes code"; HOOK_HITS=$((HOOK_HITS+1))
  fi
}
while IFS= read -r -d '' h; do check_hook "$h"; done \
  < <(find "${SCAN_ROOTS[@]}" "${PRUNE_ARGS[@]}" -o -type f -path '*/.git/hooks/*' -print0 2>/dev/null)
# A global hooks folder applies to every repo.
HP="$(git config --file "$USER_HOME/.gitconfig" core.hooksPath 2>/dev/null)"
if [ -n "$HP" ]; then
  case "$HP" in "~/"*) HP="$USER_HOME/${HP#\~/}";; esac
  if [ "$HP" = /dev/null ]; then
    ok "Git hooks are switched off for every repo (core.hooksPath=/dev/null), so infected hooks can't run"
  else
    info "global Git hooks folder is set: $HP"
  fi
  [ -d "$HP" ] && while IFS= read -r -d '' h; do check_hook "$h"; done < <(find "$HP" -type f -print0 2>/dev/null)
fi
[ "$HOOK_HITS" -eq 0 ] && ok "none"

# ================================================================ 10. Xcode projects
hdr "10. Xcode projects under $SCAN_LABEL"
PBX_HITS=0
while IFS= read -r -d '' p; do
  if pbx_suspicious "$(cat "$p" 2>/dev/null)"; then
    flag pbx "$p" "build phase decodes hidden code and runs it (revert from git or a clean copy)"
    PBX_HITS=$((PBX_HITS+1))
  fi
done < <(find "${SCAN_ROOTS[@]}" "${PRUNE_ARGS[@]}" -o -type f -name project.pbxproj -print0 2>/dev/null)
[ "$PBX_HITS" -eq 0 ] && ok "none"

# ================================================================ 10b. Git history of Xcode projects
# An infected project that was committed (and maybe pushed) comes back on the next checkout or clone.
hdr "10b. Git history (all branches) of repos under $SCAN_LABEL"
HIST_HITS=0; HIST_REPOS=0
while IFS= read -r -d '' g; do
  r="$(dirname "$g")"; HIST_REPOS=$((HIST_REPOS+1))
  commits="$(git -C "$r" log --all --format='%h' -G 'xxd -p -r|base64 (-d|-D|--decode)' -- '*.pbxproj' 2>/dev/null)"
  [ -n "$commits" ] || continue
  for c in $commits; do
    bad=""
    for f in $(git -C "$r" show --name-only --format= "$c" -- '*.pbxproj' 2>/dev/null); do
      if pbx_suspicious "$(git -C "$r" show "$c:$f" 2>/dev/null)"; then bad="$f"; break; fi
    done
    [ -n "$bad" ] || continue
    where="$(git -C "$r" branch -a --contains "$c" 2>/dev/null | sed 's/^[* ]*//' | head -5 | tr '\n' ' ')"
    flag githist "$r @ $c" "infected Xcode project committed ($(git -C "$r" show -s --format='%ad' --date=short "$c")) in $bad; on branches: ${where:-none}"
    HIST_HITS=$((HIST_HITS+1)); break
  done
done < <(find "${SCAN_ROOTS[@]}" "${PRUNE_ARGS[@]}" -o -type d -name .git -print0 2>/dev/null)
[ "$HIST_HITS" -eq 0 ] && ok "none ($HIST_REPOS repos checked)"

# ================================================================ 11. zipped Xcode projects
hdr "11. Zipped Xcode projects under $SCAN_LABEL"
ZIP_HITS=0; ZIP_SEEN=0
while IFS= read -r -d '' z; do
  case "$z" in */go/pkg/mod/*|*/.gradle/*|*/.m2/*) continue;; esac
  members="$(unzip -Z1 "$z" 2>/dev/null | grep -E '(^|/)project\.pbxproj$')"
  [ -n "$members" ] || continue
  ZIP_SEEN=$((ZIP_SEEN+1))
  while IFS= read -r m; do
    if pbx_suspicious "$(unzip -p "$z" "$m" 2>/dev/null)"; then
      flag zip "$z" "contains an infected Xcode project: $m"; ZIP_HITS=$((ZIP_HITS+1)); break
    fi
  done <<< "$members"
done < <(find "${SCAN_ROOTS[@]}" "${PRUNE_ARGS[@]}" -o -type f -iname '*.zip' -size -500M ! -flags +dataless -print0 2>/dev/null)
[ "$ZIP_HITS" -eq 0 ] && ok "none ($ZIP_SEEN zip(s) with Xcode projects checked)"

# ================================================================ 12. macOS protections
hdr "12. macOS security updates and XProtect"
SU_HITS=0
for key in AutomaticCheckEnabled CriticalUpdateInstall ConfigDataInstall AllowRapidSecurityResponses; do
  v="$(defaults read /Library/Preferences/com.apple.SoftwareUpdate "$key" 2>/dev/null)"
  if [ "$v" = 0 ]; then
    flag update "$key" "turned off (XCSSET switches security updates off; re-enable unless you did this on purpose)"; SU_HITS=$((SU_HITS+1))
  fi
done
[ "$SU_HITS" -eq 0 ] && ok "security updates enabled"
if command -v xprotect >/dev/null 2>&1; then
  XPV="$(xprotect version 2>/dev/null)"
  XPVER="$(echo "$XPV" | sed -n 's/^Version: \([0-9]*\).*/\1/p')"
  XPDATE="$(echo "$XPV" | sed -n 's/.*Installed: \([0-9-]*\).*/\1/p')"
  if [ -n "$XPDATE" ]; then
    XPAGE=$(( ( $(date +%s) - $(date -j -f %Y-%m-%d "$XPDATE" +%s 2>/dev/null || date +%s) ) / 86400 ))
    if [ "$XPAGE" -gt "$XPROTECT_MAX_AGE_DAYS" ]; then
      flag xprotect "XProtect" "malware definitions are $XPAGE days old (version $XPVER); XCSSET blocks their updates"
    else
      ok "XProtect definitions updated $XPAGE day(s) ago (version $XPVER)"
    fi
  fi
fi

# ================================================================ 13. live connections
hdr "13. Programs connected to the internet right now"
NET_HITS=0
NET="$(netstat -an -p tcp 2>/dev/null; netstat -an -p udp 2>/dev/null)"
for ip in $C2_IPS; do
  if echo "$NET" | grep -qF " $ip."; then
    who="$(lsof -nP -i "@$ip" 2>/dev/null | awk 'NR>1{print $1" (pid "$2")"}' | sort -u | tr '\n' ' ')"
    flag c2 "$ip" "connected to a known XCSSET server right now ${who:+by $who}"; NET_HITS=$((NET_HITS+1))
  fi
done

# Snapshot of every open internet connection: "pid<TAB>remote-ip" (local/LAN addresses skipped).
CONNS="$(lsof -nP -iTCP -sTCP:ESTABLISHED -F pn 2>/dev/null | awk '
  /^p/ { pid = substr($0, 2) }
  /^n/ { n = substr($0, 2); i = index(n, "->"); if (!i) next
         r = substr(n, i + 2)
         if (r ~ /^\[/) { sub(/^\[/, "", r); sub(/\]:[0-9]+$/, "", r) } else { sub(/:[0-9]+$/, "", r) }
         if (r ~ /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) next
         if (r ~ /^(::1$|fe80:|fd|fc)/) next
         print pid "\t" r }' | sort -u)"

if [ -z "$CONNS" ]; then
  ok "no open internet connections visible"
else
  # Reverse-DNS each remote address once (in parallel, 1 s timeout) to spot .ru / .by / .su servers.
  RDNS="$(echo "$CONNS" | cut -f2 | sort -u | xargs -P 16 -I{} sh -c \
           'n=$(dig +short +time=1 +tries=1 -x "{}" 2>/dev/null | head -1); [ -n "$n" ] && printf "%s\t%s\n" "{}" "${n%.}"' \
           2>/dev/null)"
  # Dev-tool homes where unsigned / ad hoc builds are normal (Homebrew, nvm, cargo, Xcode builds…).
  # Only well-known package-manager / toolchain install folders. Project folders are deliberately
  # NOT listed: that's where infected Xcode projects live.
  DEV_PATHS="/opt/homebrew/|/usr/local/|$USER_HOME/\.(nvm|cargo|rustup|platformio|local|bun|deno|pyenv|rbenv|volta|sdkman|vscode|cursor|docker|npm|espressif)/|$USER_HOME/go/bin/"
  SIG_CACHE=""; ONLINE=""; UNSIGNED_DEV=""
  while IFS="$(printf '\t')" read -r pid ip; do
    exe="$(ps -p "$pid" -o comm= 2>/dev/null)"; [ -n "$exe" ] || continue
    name="$(basename "$exe")"
    ONLINE="$ONLINE
$name"
    host="$(echo "$RDNS" | awk -F'\t' -v ip="$ip" '$1==ip{print $2; exit}')"
    # 1) Server in Russia / Belarus by name, or a known XCSSET domain.
    if [ -n "$host" ]; then
      if echo "$host" | grep -qiE '\.(ru|by|su|xn--p1ai)$'; then
        flag net "$name → $host ($ip)" "$exe (pid $pid) is connected to a server in Russia/Belarus"; NET_HITS=$((NET_HITS+1))
      elif echo " $C2_DOMAINS " | tr ' ' '\n' | grep -qixF "$(echo "$host" | awk -F. '{print $(NF-1)"."$NF}')"; then
        flag c2 "$name → $host ($ip)" "$exe (pid $pid) is connected to a known XCSSET server"; NET_HITS=$((NET_HITS+1))
      fi
    fi
    # 2) Unsigned / ad hoc program online (XCSSET signs its fakes ad hoc). Checked once per program.
    case "$SIG_CACHE" in *"|$exe|"*) continue;; esac
    SIG_CACHE="$SIG_CACHE|$exe|"
    [ -f "$exe" ] || continue
    sig="$(codesign -dv "$exe" 2>&1)"
    if echo "$sig" | grep -qE 'Signature=adhoc|not signed at all'; then
      kindsig="ad hoc signed"; echo "$sig" | grep -q 'not signed at all' && kindsig="unsigned"
      if echo "$exe" | grep -qE "$DEV_PATHS"; then
        UNSIGNED_DEV="$UNSIGNED_DEV, $name"
      else
        flag net "$name (pid $pid)" "$kindsig program online from $exe ($ip${host:+ = $host})"; NET_HITS=$((NET_HITS+1))
      fi
    fi
  done <<< "$CONNS"
  NPROG="$(echo "$ONLINE" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')"
  [ "$NET_HITS" -eq 0 ] && ok "$NPROG program(s) online, none unsigned or talking to Russian/Belarusian servers"
  info "online now: $(echo "$ONLINE" | sed '/^$/d' | sort | uniq -c | sort -rn | awk '{print $2}' | head -15 | tr '\n' ' ')"
  [ -n "$UNSIGNED_DEV" ] && info "unsigned developer tools online (normal for Homebrew/your own builds): ${UNSIGNED_DEV#, }"
  [ "$IS_ROOT" -eq 0 ] && info "only your own programs are visible; run with sudo to see system ones too"
fi

# ================================================================ 14. C2 network activity in the log
hdr "14. System log (last $LOG_WINDOW) for XCSSET servers"
if [ "$LOG_WINDOW" = 0 ]; then
  info "skipped (--log-window 0)"
else
  pred=""
  for d in $C2_DOMAINS $C2_IPS; do
    [ -n "$pred" ] && pred="$pred OR "
    pred="${pred}eventMessage CONTAINS[c] \"$d\""
  done
  # Exclude the `log` tool itself: it logs its own arguments, which contain every domain.
  pred="($pred) AND NOT (process == \"log\")"
  hits="$(log show --style compact --last "$LOG_WINDOW" --predicate "$pred" 2>/dev/null | grep -v '^Timestamp' | grep -v '^Filtering')"
  if [ -n "$hits" ]; then
    flag c2 "unified log" "$(echo "$hits" | wc -l | tr -d ' ') line(s) mention XCSSET servers, e.g. $(echo "$hits" | head -2 | tr '\n' ' ')"
  else
    ok "no matches ($(echo $C2_DOMAINS | wc -w | tr -d ' ') domains, $(echo $C2_IPS | wc -w | tr -d ' ') IPs)"
  fi
fi

# ================================================================ 15. Defender (info)
if command -v mdatp >/dev/null 2>&1; then
  hdr "15. Microsoft Defender"
  info "threat history: $(mdatp threat list 2>/dev/null | grep -c '^Id:') detection(s); in quarantine: $(mdatp threat quarantine list 2>/dev/null | grep -c '^Id:')"
fi

# ================================================================ summary
hdr "Summary"
echo "   ${#FINDINGS[@]} finding(s), $INFO_COUNT note(s). Log: $LOG_FILE"

if [ -n "$REPORT_FILE" ]; then
  : > "$REPORT_FILE"
  for entry in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
    k="${entry%%|*}"; rest="${entry#*|}"; p="${rest%%|*}"; r="${rest#*|}"
    printf '%s\t%s\t%s\n' "$k" "$p" "$(printf '%s' "$r" | tr '\t\n' '  ')" >> "$REPORT_FILE"
  done
fi

if [ "${BLOCKED:-0}" -gt 0 ]; then
  echo "   SCAN INCOMPLETE: $BLOCKED protected folder(s) could not be read (see section 0)."
  echo "   Give Full Disk Access to $FDA_APP: System Settings > Privacy & Security > Full Disk Access."
fi
if [ "${#FINDINGS[@]}" -eq 0 ]; then
  echo "   Nothing found."
  exit 0
fi
if [ "$MODE" != clean ]; then
  [ "${#FINDINGS[@]}" -gt "${BLOCKED:-0}" ] && echo "   Re-run with: sudo bash $0 --clean   to quarantine/fix these."
  exit 1
fi

fi  # end of scan (skipped with --apply)

# ================================================================ clean
hdr "Cleaning (quarantine folder: $QDIR)"
mkdir -p "$QDIR"
for entry in "${FINDINGS[@]}"; do
  kind="${entry%%|*}"; rest="${entry#*|}"; path="${rest%%|*}"
  echo
  echo "   [$kind] $path"
  case "$kind" in
    proc)
      pid="${path%% *}"; was="${path#* }"
      # Only kill if that PID still runs the same command (PIDs get reused).
      now="$(ps -p "$pid" -o command= 2>/dev/null)"
      if [ "$now" != "$was" ]; then
        echo "       process $pid is gone or changed; skipped"
      else
        confirm "kill process $pid?" && { kill -TERM "$pid" 2>/dev/null; sleep 1; kill -KILL "$pid" 2>/dev/null; echo "       killed $pid"; }
      fi ;;
    file|app|hook|zip)
      confirm "move to quarantine?" && quarantine "$path" ;;
    pref)
      if confirm "move this preference file to quarantine?"; then
        quarantine "$path"
        # cfprefsd caches preferences in memory; restart it so the payload is really gone.
        if [ "$IS_ROOT" -eq 1 ]; then killall cfprefsd 2>/dev/null; else killall -u "$TARGET_USER" cfprefsd 2>/dev/null; fi
      fi ;;
    xprotect)
      if [ "$IS_ROOT" -eq 1 ]; then
        confirm "download the latest XProtect definitions?" && { xprotect update 2>&1 | tail -3 | sed 's/^/       /'; }
      else
        echo "       needs sudo: sudo xprotect update"
      fi ;;
    sig)   echo "       Not touched automatically: delete this app and reinstall it from the developer's official site (or the App Store)." ;;
    browser) echo "       Not touched automatically: quit this browser, then reinstall it from the official site and change saved passwords." ;;
    access) echo "       Not scanned: give Full Disk Access to $FDA_APP (System Settings > Privacy & Security > Full Disk Access), then scan again." ;;
    githist) echo "       Not touched automatically: delete or rewrite the listed branches (locally and on the remote) so nobody checks this commit out again." ;;
    dock)  echo "       Not touched automatically: drag this icon out of the Dock, and delete what it points to if you don't recognize it." ;;
    rc)
      echo "       Lines sourcing ~/.zshrc_aliases will be removed; other flagged lines need a manual look."
      if confirm "back up and edit $path?"; then
        mkdir -p "$QDIR$(dirname "$path")"
        cp -p "$path" "$QDIR$path" && printf '%s\t%s\t(backup)\n' "$path" "$QDIR$path" >> "$QDIR/MANIFEST.tsv"
        sed -i '' '/zshrc_aliases/d' "$path" && echo "       backed up to $QDIR$path and cleaned"
      fi ;;
    launchd)
      if confirm "unload and quarantine?"; then
        case "$path" in
          /Library/LaunchDaemons/*) launchctl bootout system "$path" 2>/dev/null ;;
          /Library/LaunchAgents/*|"$USER_HOME"/Library/LaunchAgents/*)
            launchctl bootout "gui/$TARGET_UID" "$path" 2>/dev/null ;;
        esac
        quarantine "$path"
      fi ;;
    update)
      if [ "$IS_ROOT" -eq 1 ]; then
        confirm "turn $path back on?" && defaults write /Library/Preferences/com.apple.SoftwareUpdate "$path" -bool true && echo "       re-enabled"
      else
        echo "       needs sudo to re-enable"
      fi ;;
    pbx) echo "       Not touched automatically: revert this file with git or restore a clean copy." ;;
    c2)  echo "       Review the lines above: quit the program named, block the server, or restore from a clean backup." ;;
  esac
done

[ "$IS_ROOT" -eq 1 ] && chown -R "$TARGET_USER" "$USER_HOME/xcsset-quarantine" "$LOG_FILE" 2>/dev/null
echo
echo "   Done. Quarantined items + MANIFEST.tsv: $QDIR"
echo "   To restore one: mv <quarantine path> <original path> (see MANIFEST.tsv)."
echo "   Then: reboot, change passwords saved in your browsers, and update macOS, Xcode and Chrome."
[ "$MODE" = apply ] && exit 0
exit 1
