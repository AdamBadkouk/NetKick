# NetKick - ARP Spoofer & Network Blocker

A powerful network tool built with C# and .NET 10 that allows you to scan your local network, discover devices, and block/unblock internet access for specific devices using ARP spoofing.

![Warning](https://img.shields.io/badge/⚠️-Educational%20Purpose%20Only-red)

## ⚠️ Disclaimer

**This tool is for educational and authorized testing purposes only.** Using this tool on networks you don't own or without explicit permission is illegal. The author is not responsible for any misuse.

## Features

- **Network Scanning**: Discover all devices on your local network using ARP requests
- **Device Listing**: View all discovered devices with IP, MAC address, and hostname
- **Block Devices**: Block internet access for specific devices using ARP spoofing
- **Unblock Devices**: Restore internet access by sending correct ARP packets
- **Status Monitoring**: View currently blocked devices and spoofing statistics
- **Logging**: Track all operations with timestamped logs
- **Beautiful CLI**: Interactive console UI with Spectre.Console

## Requirements

- Windows 10/11
- .NET 10 SDK
- [Npcap](https://npcap.com) (install with WinPcap compatibility mode)
- Administrator privileges

## Installation

1. Install [Npcap](https://npcap.com/dist/npcap-1.79.exe)
   - During installation, check "Install Npcap in WinPcap API-compatible Mode"

2. Clone or download this repository

3. Build the project:
   ```bash
   cd NetKick
   dotnet build -c Release
   ```

4. Run as Administrator:
   ```bash
   dotnet run
   ```

## Usage

1. **Launch the application** as Administrator
2. **Select your network interface** from the list
3. **Wait for the network scan** to complete
4. Use the menu to:
   - View all discovered devices
   - Block a device (select from available devices)
   - Unblock a blocked device
   - Rescan the network
   - View logs

## How It Works

### ARP Spoofing

ARP (Address Resolution Protocol) is used to map IP addresses to MAC addresses on a local network. This tool exploits the stateless nature of ARP:

1. **Block**: Sends fake ARP replies to the target device, claiming to be the gateway. The target then sends all internet-bound traffic to our machine, which is dropped (not forwarded).

2. **Unblock**: Sends legitimate ARP replies with the correct gateway MAC address to restore normal network operation.

### Architecture

```
NetKick/
├── NetKick/
│   ├── Models/
│   │   ├── NetworkDevice.cs       # Represents a discovered device
│   │   └── NetworkInterfaceInfo.cs # Network interface configuration
│   ├── Services/
│   │   ├── ArpService.cs          # ARP packet handling and scanning
│   │   ├── BlockingService.cs     # Device blocking/unblocking logic
│   │   └── NetworkService.cs      # Interface discovery
│   ├── Program.cs                 # Main entry point and UI
│   ├── app.manifest               # Admin privileges manifest
│   └── NetKick.csproj             # Project file
├── .gitignore
├── LICENSE
└── README.md
```

## NuGet Packages

| Package | Version | Description |
|---------|---------|-------------|
| [SharpPcap](https://github.com/dotpcap/sharppcap) | 6.3.1 | Packet capture library |
| [PacketDotNet](https://github.com/dotpcap/packetnet) | 1.4.8 | Packet construction/parsing |
| [Spectre.Console](https://spectreconsole.net/) | 0.54.0 | Beautiful console UI |

## Building

```bash
# Debug build
dotnet build

# Release build
dotnet build -c Release

# Publish self-contained
dotnet publish -c Release -r win-x64 --self-contained
```

## Troubleshooting

### "Npcap is not installed"
- Download and install Npcap from https://npcap.com
- Make sure to check "Install Npcap in WinPcap API-compatible Mode"

### "No suitable network interfaces found"
- Make sure you have an active network connection
- The interface must have an IPv4 address and gateway configured

### "Gateway not found"
- Ensure your default gateway is reachable
- Try manually pinging the gateway first

### Blocked device still has internet
- Some devices may have static ARP entries
- The target device might be using a VPN
- Try increasing the spoofing frequency

## License

MIT License - Use at your own risk.

## Contributing

Contributions are welcome! Please ensure any network tools are used responsibly and ethically.

