# xcset-defence

Find and clean up leftovers of **XCSSET**, the macOS malware that spreads through Xcode projects, on your own Mac.

It comes as a **shell script** (`xcsset-guard.sh`) and a small **Mac app** (XCSSET Guard) that runs the same script with a simple interface.

> **Scanning changes nothing.** Fixes only happen when you ask for them, and files are **moved to a quarantine folder, never deleted**, so every fix can be undone.

## What it checks

Covers XCSSET versions up to **v40** (Unit 42, July 2026).

| # | Check | What it looks for |
|---|---|---|
| 0 | Folder access | Desktop, Documents, Downloads and iCloud Drive are readable. If macOS privacy protection blocks one, it's **reported as "not scanned"** instead of silently skipped (see [Full Disk Access](#full-disk-access)) |
| 1 | Processes | Fake Terminal/Finder/Reminders/System Settings, apps running from `/tmp`, HackBrowserData, v40 browser backdoors (`chrome_remote`…), browsers started with remote debugging on your normal profile, Perl locking XProtect's database |
| 2 | Dropped files | Known payload paths (`/tmp/b`, `/tmp/r`, `/tmp/p.app`, `~/.root`, `~/.tr`…) and known malicious SHA-256 hashes |
| 3 | Fake apps | Copies of system apps placed in `/Applications` |
| 4 | Tampered apps | Chrome, Brave, Edge, Firefox, Opera, Arc, Vivaldi, Telegram and Xcode must be real, properly signed binaries (catches replaced launchers and ad hoc–signed fakes) |
| 5 | Shell startup files | `~/.zshrc` & co. sourcing `~/.zshrc_aliases`, or piping downloads/decoded data into a shell |
| 6 | Launch daemons/agents | Jobs running from temp or hidden folders, jobs that download/decode code, and `com.google.*` jobs **not** signed by Google (Chrome's real updater is left alone) |
| 7 | Preference files | v40's hidden Base64 payload keys |
| 8 | Dock | Icons that open something outside the Applications folders |
| 9 | Git hooks | Hooks that download or decode code, including a global `core.hooksPath`. Checks 9–11 cover your home folder **and iCloud Drive** (cloud-only zips are skipped rather than downloaded) |
| 10 | Xcode projects | Build phases or build settings that decode hidden code (hex/Base64, nested) and run it |
| 10b | Git history | Infected Xcode projects committed on **any branch**, so they don't come back on the next checkout or clone |
| 11 | Zipped projects | Infected Xcode projects inside `.zip` files |
| 12 | macOS protections | Security updates and Rapid Security Responses switched off; outdated XProtect definitions |
| 13 | Live connections | Programs online right now: unsigned/ad hoc programs (outside package-manager folders such as Homebrew, nvm or cargo), connections to known XCSSET servers or to `.ru`/`.by`/`.su` servers |
| 14 | System log | Mentions of ~90 known XCSSET server domains and IPs |
| 15 | Microsoft Defender | Detection summary, if Defender is installed |

## Usage

### Command line

```bash
# Scan only (nothing is changed)
bash xcsset-guard.sh

# Full scan, including system processes and other users' connections
sudo bash xcsset-guard.sh

# Scan, then fix what it finds (asks before each item)
sudo bash xcsset-guard.sh --clean
```

| Option | Meaning |
|---|---|
| `--clean` | Fix findings after the scan (asks each time) |
| `--yes` | Don't ask before each fix (with `--clean`) |
| `--root DIR` | Where to look for Git repos and Xcode projects (default: your home folder) |
| `--log-window W` | How far back to search the system log: `30m`, `2h`, `1d`, or `0` to skip (default `2h`; about 6–7 minutes per day) |
| `--user NAME` | Scan another account's home folder (needs `sudo`) |
| `--report FILE` | Also write findings as tab-separated `kind / path / reason` |
| `--apply FILE` | Skip the scan and fix exactly the findings listed in `FILE` (used by the app) |

Exit code: `0` nothing found, `1` findings, `2` usage error. Every run writes a log to `~/xcsset-guard-<date-time>.log`.

### Mac app

```bash
./build-app.sh
open "build/XCSSET Guard.app"
```

Builds with the Swift compiler from the Xcode Command Line Tools. **No Xcode project is involved**, so there is nothing for XCSSET to infect. Drag the app into `/Applications` to keep it.

- **Scan** runs as you, with no password.
- Tick what you want fixed, then click **Fix Selected**. macOS asks for your password once, and only the ticked items are changed.
- Findings marked **Fix manually** (tampered apps, infected Git history, Xcode projects, network) need your judgement. The app explains what to do.

## Full Disk Access

macOS protects **Desktop, Documents, Downloads and iCloud Drive**. Without permission, programs simply can't see inside them, and those are common places for downloaded or zipped Xcode projects.

The scan checks this first (check 0). If a folder is blocked, it's listed as **"not scanned"**, the summary says **SCAN INCOMPLETE**, and the app won't show "No threats found".

To scan everything, open **System Settings → Privacy & Security → Full Disk Access** and turn it on for:

- **XCSSET Guard**, if you use the app. The app has a button that opens this setting.
- **Terminal** (or iTerm, your IDE…), if you run the script from the command line. `sudo` does **not** bypass this protection.

Locally built apps are only ad hoc signed, so after rebuilding XCSSET Guard you may need to switch its Full Disk Access off and on again.

## How fixes work

| Finding | Fix |
|---|---|
| Files, fake apps, hooks, zips, preference files | Moved to `~/xcsset-quarantine/<date-time>/` under their original path, with a `MANIFEST.tsv` for restoring |
| Launch daemons/agents | Unloaded, then quarantined |
| Shell startup files | Backed up to quarantine, then the `zshrc_aliases` line is removed (other flagged lines are left for you to review) |
| Processes | Stopped, only if the same process is still running |
| Security update settings / XProtect | Turned back on / updated |

To restore something: `mv <quarantine path> <original path>` (see `MANIFEST.tsv`).

## Requirements

- macOS 14 or later (Apple silicon or Intel)
- The stock `/bin/bash` (3.2) is enough
- To build the app: Xcode Command Line Tools (`xcode-select --install`)

## Limitations

- **Tested on one Mac so far** (Apple silicon, current macOS). Some fixes (unloading launch daemons, stopping processes, editing shell files) have only been tested against simulated infections. Bug reports from other setups are welcome.
- **It's a scanner, not real-time protection.** For live alerts and blocking of outgoing connections, also use a firewall like [LuLu](https://objective-see.org/products/lulu.html).
- Detection is based on published indicators. A new XCSSET variant may change file names, servers or encoding.
- Without `sudo`, it only sees your own processes and connections.
- Russian/Belarusian servers are spotted by their DNS name only, not by IP geolocation.
- A clean scan is strong evidence, not proof. The only way to be certain is erasing and reinstalling macOS, then restoring only documents and code (scanned first).

## After a cleanup

1. Restart your Mac.
2. Change passwords that were saved in your browsers (XCSSET steals browser data), starting with email, Apple Account and GitHub.
3. Delete or rewrite any infected branches the Git-history check found, locally **and** on the remote.
4. Consider `git config --global core.hooksPath /dev/null` if you don't use Git hooks.
5. Make a fresh, encrypted backup.

## Sources

- Palo Alto Networks Unit 42: [The Xcode Assassin Returns: XCSSET v40](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/) (July 2026)
- Microsoft Threat Intelligence: [XCSSET evolves again](https://www.microsoft.com/en-us/security/blog/2025/09/25/xcsset-evolves-again-analyzing-the-latest-updates-to-xcssets-inventory/) (September 2025)

## Disclaimer

Provided as-is, without warranty. It is a best-effort tool for checking your own Mac. Review findings before fixing them, and keep a backup.

## License

[MIT](LICENSE)
