# GL.iNet Backdoor Notes (`ulogd` / `monitord` / `ujaild`)

While checking my GL.iNet router (`GL-MT2500, firmware 4.7.13 release2) for signs of the 11/20/2026 GoodCloud incident, I found a separate backdoor that had been on the device since **December 19, 2025**.

This repo contains my findings, hashes, and IoCs. No live malware binaries are uploaded here.

## Files & Persistence

Al.l three files share the exact same timestamp (`2025-12-19 17:07:07 -0400`):

| Path | What it is | Infected MD5 | Clean `/rom` MD5 |
| :--- | :--- | :--- | :--- |
| `/bin/ulogd` | Stage 1 Lua 5.1 bytecode (33,722 bytes) | `c40f33344d6f686f9912e2047ea7a0c9` | *(dropped)* |
| `/etc/init.d/urandom_seed` | Boot script modified to launch `monitord` | `29c049b6a1b327c7abe1fa1f463190d1` | `c45ab53884ef7e63cf847372c66bb5e8` |
| `/lib/upgrade/keep.d/netifd` | Upgrade persistence ("Keep Settings") | `c96742483c0f1365c3136687c2596218` | `92e4b23ef569d8fbbe6f86bf42013782` |

To survive firmware updates when "Keep Settings" is enabled, the attacker added both paths to `/lib/upgrade/keep.d/netifd`:

```text
/etc/udhcpc.user.d/
/bin/ulogd
/etc/init.d/urandom_seed
```

Checking `/overlay/upper` for other changes on `2025-12-19` showed:
- `17:07:18 -0400` (+11s after drop): `/overlay/upper/etc/config/wireguard_server`
- `18:18:08 -0400` (+1h 11m): `/overlay/upper/etc/shadow-` and `/overlay/upper/etc/passwd-`

Other users on the [GL.iNet forum thread](https://forum.gl-inet.com/t/found-other-malware-while-looking-for-11-20-evidence/73097) later confirmed the exact same 11-second gap on `wireguard_server`, pointing to an automated installer.

## Running Processes

Both stages ran as `root` from deleted binaries:
- `monitord` (Stage 1): `/proc/7617/exe -> /usr/bin/monitord (deleted)` — renamed copy of `/usr/bin/lua` (`MD5: 5f1fce4ec4939d64d09873cb437150eb`).
- `ujaild` (Stage 2): `/proc/11671/exe -> /tmp/ujaild (deleted)` — memory-resident binary (`MD5: caeb9cffeda5fcbb4d7088bd173e5074`).

## Stage 1 Behavior (`/bin/ulogd` v2.1)

From decompiling the Lua 5.1 bytecode:
- Reports `version=v2.1` and a hardcoded ID (`83c86287508c3f6e930c6284389ca06c67606d33`).
- Restarts system logs (`/etc/init.d/log restart`) and sleeps 300s if uptime is under 600s.
- Collects uptime, open `/dev/pts` sessions, parent PID, ELF endianness (via `/bin/ls`), MAC addresses, DDNS, model, firmware version, and `/etc/glversion`.
- XOR-encrypts and hex-encodes the beacon, then sends it via HTTP POST to obfuscated C2 URLs.
- Parses JSON responses (`url`, `sleep`, `key`, `args`, `quit`, `name`) to fetch, decrypt, and unpack Stage 2 into `/tmp/<name>`, symlinks it to `/usr/sbin/<name>`, runs it in the background, sleeps 1s, and deletes both files with `rm -f`.

## C2 Domains (WHOIS)

Both lookalike AdGuard domains were registered on **2025-12-08** (11 days before my infection) for 2 years across different registrars, using the same Cloudflare nameservers:
- `adguardns[.]org` (Name.com) — WHOIS updated `2026-08-12`
- `adguardns[.]com` (NameCheap)
- Nameservers: `sreeni.ns.cloudflare.com`, `thaddeus.ns.cloudflare.com`

## Quick Check (SSH)

```sh
cmp /etc/init.d/urandom_seed /rom/etc/init.d/urandom_seed
cmp /lib/upgrade/keep.d/netifd /rom/lib/upgrade/keep.d/netifd
ls -la /bin/ulogd /usr/bin/monitord
ps w | grep -E '[m]onitord|[u]jaild'
```

## Reference
- Original forum report (Post #19): https://forum.gl-inet.com/t/found-other-malware-while-looking-for-11-20-evidence/73097/19
