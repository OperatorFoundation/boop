# boop

A simple UDP notification tool for Tailscale/Headscale networks.

## Features

- 🔊 Send and receive audio notifications across your network
- 🌐 IPv4 and IPv6 support
- 🔍 mDNS service discovery
- 🎯 Tailscale/Headscale integration with automatic hostname and username resolution
- 🎨 Beautiful terminal output with Catppuccin Mocha color scheme
- 📡 Fallback Tailscale resolution when MagicDNS isn't available

## Installation

### From source

```bash
go install github.com/OperatorFoundation/boop@latest
```

### Building locally

```bash
git clone https://github.com/OperatorFoundation/boop.git
cd boop
go build
```

### Cross-compiling

For Raspberry Pi:
```bash
GOOS=linux GOARCH=arm64 go build -o boop-linux-arm64
```

## Usage

### Listen for boops

```bash
boop --listen
```

This will:
- Listen on UDP port 9999 (IPv4 and IPv6)
- Advertise via mDNS using your Tailscale machine name
- Play a sound and display a notification when boops are received

### Send a boop

```bash
# Send to an IP address
boop 100.64.0.106

# Send to a hostname (via DNS or Tailscale resolution)
boop myserver

# Send to yourself
boop me

# Send with a message
boop username@myserver "Hello there!"
```

The tool will automatically:
- Try DNS resolution first
- Fall back to Tailscale status lookup if DNS fails
- Resolve short machine names to full Tailscale IPs
- Display usernames and machine names in a clean format

## How it works

### Tailscale Integration

`boop` queries `tailscale status --json` to:
- Get your Tailscale machine name for mDNS advertising
- Map IP addresses to machine names and usernames when receiving boops
- Resolve machine names to IPs when MagicDNS isn't available

It works with both official Tailscale and Headscale installations.

### Sound playback

- **macOS**: Uses `sox` (`play` command) to synthesize a nice boop sound, falling back to system sounds
- **Linux**: Tries `paplay` (PulseAudio) or `aplay` (ALSA) with system notification sounds, falling back to terminal bell

### Colors

The Catppuccin Mocha color palette: https://catppuccin.com

## Requirements

- Go 1.21 or later
- Tailscale or Headscale client (optional, for hostname resolution)
- Audio support:
  - macOS: `sox` (optional, for nice boop sound) or built-in `afplay`
  - Linux: `paplay` or `aplay`

## Port

Default port: 9999 UDP

Make sure this port is open on your firewall if needed.

## License

MIT
