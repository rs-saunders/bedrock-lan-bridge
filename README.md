# Bedrock LAN Bridge

_A lightweight LAN-beacon broadcaster + UDP proxy that makes any remote Minecraft Bedrock server appear as a local LAN world — including on Nintendo Switch._

---

## 🎮 What is Bedrock LAN Bridge?

Bedrock LAN Bridge is a tiny Go application that:

1. **Broadcasts a LAN beacon** on your local network, making a remote Bedrock server appear as a local LAN world.
2. **Proxies all Bedrock UDP traffic** between your device (e.g., Switch) and a remote Bedrock server.
3. Allows Bedrock Edition clients — **especially Nintendo Switch**, which cannot add custom servers — to join remote servers as if they were on your local Wi-Fi.

This works with **any** remote Bedrock server:

- Public server
- AMP-managed server
- Servers reachable via Tailscale / Zerotier / WireGuard
- Private servers behind CGNAT
- Home servers
- Servers on another LAN

The remote server does **not** need to broadcast a beacon.

---

## 🧠 Why does this exist?

Minecraft Bedrock Edition discovers LAN servers by listening for **UDP broadcast beacons** on port **19132**.

The Nintendo Switch client:

- Cannot enter custom server IPs
- Only joins LAN games
- Only connects to port 19132 on the LAN

So normally it cannot join remote servers at all.

**Bedrock LAN Bridge solves this** by:

✔ Spoofing a LAN beacon  
✔ Proxying traffic to the real server  
✔ Making the Switch think the remote server is local

---

## 🌐 Typical Use Cases

- Play on a **remote Bedrock server from a Nintendo Switch**
- Expose a Tailscale/Zerotier/WireGuard-only server to local LAN
- Allow kids to easily join a server without typing IPs
- Use an old Android phone as a **dedicated LAN bridge**
- Join a friend’s home server without messing with firewalls
- Make cloud-hosted Bedrock servers appear as LAN worlds

---

## 🛠 Features

- Works with **any remote Bedrock server**
- Full LAN beacon spoofing
- Lightweight UDP proxy
- Configurable via `config.json`
- Optional MOTD override
- Easy to run on cheap hardware (Android phone, Pi, old laptop)
- Cross-platform:
  - Android (Termux)
  - Linux
  - Windows
  - macOS
  - Raspberry Pi

---

## 🖥️ Installation (Windows / Linux / macOS)

Build the binary:

```bash
go build -o bedrock-lan-bridge
```

For Android ARM64 cross-compilation:

```bash
GOOS=linux GOARCH=arm64 go build -o bedrock-lan-bridge
```

Copy `config.example.json` as `config.json`, set the correct values, then run: 


```bash
./bedrock-lan-bridge -config config.json
```

---

## ⚠ Windows note

If you play Minecraft on the same Windows machine as the bridge,
you may need a port redirect from 19132 → your proxy port.

If running on a separate device → no redirect is needed.

### PowerShell Execution Policy

Windows blocks PowerShell scripts by default with *PSSecurityException: running scripts is disabled*.
Either run the script through a one-off command:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\bedrock-lan-bridge-nat.ps1 enable
```

…or permanently relax the policy for your user (recommended):

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

After applying one of the above you can invoke the script normally (e.g. `.\bedrock-lan-bridge-nat.ps1 enable`).

> **Note:** UDP entries in `netsh interface portproxy` only work on Windows 11 24H2 (build 26100+) and newer Insider builds.  
> Older Windows releases cannot redirect UDP this way, so the NAT helper fails with *The parameter is incorrect*.  
> In that case run the bridge on a machine where port 19132 is free and set `localProxyPort` to 19132, or perform the redirect on Linux/macOS instead.

---

## 🧪 Testing

On your Nintendo Switch:

1. Open Minecraft
1. Go to Friends → LAN Games
1. You should see your remote server listed
1. Tap it to join
1. Gameplay is proxied through your device to the remote server

---

## 🧩 Configuration Options

| Key                      | Description                               |
| ------------------------ | ----------------------------------------- |
| `remoteServerIp`         | IP or domain of the remote Bedrock server |
| `remoteServerPort`       | Usually 19132                             |
| `localProxyIp`           | Usually `0.0.0.0`                         |
| `localProxyPort`         | Local UDP port the bridge listens on      |
| `broadcastPort`          | Bedrock LAN port (19132)                  |
| `broadcastIntervalMs`    | Beacon interval (default 1000ms)          |
| `broadcastInterface`     | `auto`, interface name, or IPv4 to bind beacon source |
| `logLevel`               | `info` / `debug`                          |
| `beaconServerNameOverride` | Optional custom server name/MOTD        |
| `beaconEditionOverride`          | Override edition string in LAN beacon (`MCPE`) |
| `beaconProtocolVersionOverride`  | Override protocol version advertised      |
| `beaconGameVersionOverride`      | Override version string in beacon         |
| `beaconLevelNameOverride`        | Custom world/level name shown             |
| `beaconGameModeOverride`         | Game mode string (`Survival`)             |
| `beaconServerGuidOverride`       | GUID used for beacon (decimal or `0x` value) |
| `beaconMaxPlayersOverride`       | Max players fallback when remote ping fails |
| `beaconIpv6PortOverride`         | IPv6 port advertised (defaults to proxy port) |

Missing values fall back to defaults.

The bridge automatically picks the first non-virtual, non-loopback interface with a private IPv4 address when `broadcastInterface` is set to `auto`. You can override it with an interface name or by specifying the exact IPv4 you want to bind to. For example:

```json
{
  "broadcastInterface": "192.168.0.131",
  "broadcastPort": 19132,
  "broadcastIntervalMs": 3000
}
```

---

## 🧱 Limitations

- Works only for Bedrock Edition
- Only one server can be broadcast at a time (Switch limitation)
- LAN discovery works only on the same subnet
