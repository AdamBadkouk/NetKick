using NetKick.Models;
using NetKick.Services;
using SharpPcap.LibPcap;
using Spectre.Console;
using System.Net.NetworkInformation; // added for PhysicalAddress

namespace NetKick;

public class Program
{
    private static ArpService? _arpService;
    private static BlockingService? _blockingService;
    private static NetworkInterfaceInfo? _selectedInterface;
    private static NetworkDevice? _gateway;
    private static readonly List<string> _logMessages = new();
    private static readonly object _logLock = new();

    public static async Task Main(string[] args)
    {
        Console.Title = "NetKick - ARP Spoofer";

        PrintBanner();

        // Check for admin privileges
        if (!IsAdministrator())
        {
            AnsiConsole.MarkupLine("[red]⚠ This application requires Administrator privileges![/]");
            AnsiConsole.MarkupLine("[yellow]Please restart as Administrator.[/]");
            Console.ReadKey();
            return;
        }

        // Check for Npcap
        if (!NetworkService.IsNpcapInstalled())
        {
            AnsiConsole.MarkupLine("[red]⚠ Npcap is not installed or not accessible![/]");
            AnsiConsole.MarkupLine("[yellow]Please install Npcap from: https://npcap.com[/]");
            Console.ReadKey();
            return;
        }

        try
        {
            await RunAsync();
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
            Console.ReadKey();
        }
        finally
        {
            await CleanupAsync();
        }
    }

    private static async Task RunAsync()
    {
        // Select network interface
        var selectedDevice = SelectNetworkInterface();
        if (selectedDevice == null) return;

        _selectedInterface = selectedDevice.Value.Info;
        _arpService = new ArpService(selectedDevice.Value.Device, _selectedInterface);
        _arpService.LogMessage += (_, msg) => AddLog(msg);
        _arpService.DeviceDiscovered += (_, d) => AddLog($"Discovered: {d.IpAddress} -> {d.MacAddressString}");

        AnsiConsole.MarkupLine($"\n[green]Selected:[/] {_selectedInterface.Description}");
        AnsiConsole.MarkupLine($"[blue]IP:[/] {_selectedInterface.IpAddress}");
        AnsiConsole.MarkupLine($"[blue]MAC:[/] {_selectedInterface.MacAddressString}");
        AnsiConsole.MarkupLine($"[blue]Gateway:[/] {_selectedInterface.GatewayAddress}");
        AnsiConsole.MarkupLine($"[blue]Network:[/] {_selectedInterface.NetworkAddress}/{_selectedInterface.PrefixLength}");

        // Scan network
        AnsiConsole.WriteLine();
        await ScanNetworkAsync();

        // Find gateway in discovered devices
        _gateway = _arpService.DiscoveredDevices.Values.FirstOrDefault(d => d.IsGateway);

        if (_gateway == null)
        {
            AnsiConsole.MarkupLine("[yellow]Gateway not found in scan. Sending direct ARP request...[/]");

            // Send a few ARP requests to the gateway to increase chance of discovery
            for (int i = 0; i < 3; i++)
            {
                _arpService.SendArpRequest(_selectedInterface.GatewayAddress);
                await Task.Delay(150);
            }

            _gateway = _arpService.DiscoveredDevices.Values.FirstOrDefault(d => d.IsGateway);
        }

        if (_gateway == null)
        {
            AnsiConsole.MarkupLine("[red]Could not find gateway. Cannot proceed with blocking.[/]");
            return;
        }

        // Initialize blocking service
        _blockingService = new BlockingService(_arpService, _gateway);
        _blockingService.LogMessage += (_, msg) => AddLog(msg);
        _blockingService.Start();

        // Main menu loop
        await MainMenuLoopAsync();
    }

    private static (LibPcapLiveDevice Device, NetworkInterfaceInfo Info)? SelectNetworkInterface()
    {
        var interfaces = NetworkService.GetAvailableInterfaces();

        if (interfaces.Count == 0)
        {
            AnsiConsole.MarkupLine("[red]No suitable network interfaces found![/]");
            return null;
        }

        var choices = interfaces.Select(i =>
            $"{i.Info.Description} ({i.Info.IpAddress}/{i.Info.PrefixLength})").ToList();

        var selected = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("\n[yellow]Select Network Interface:[/]")
                .PageSize(10)
                .AddChoices(choices));

        var index = choices.IndexOf(selected);
        return interfaces[index];
    }

    private static async Task ScanNetworkAsync()
    {
        if (_arpService == null) return;

        await AnsiConsole.Progress()
            .Columns(
                new TaskDescriptionColumn(),
                new ProgressBarColumn(),
                new PercentageColumn(),
                new SpinnerColumn())
            .StartAsync(async ctx =>
            {
                var task = ctx.AddTask("[green]Scanning network...[/]");
                var progress = new Progress<int>(percent => task.Value = percent);

                using var cts = new CancellationTokenSource();
                await _arpService.ScanNetworkAsync(progress, cts.Token);

                task.Value = 100;
            });

        DisplayDevices();
    }

    private static async Task MainMenuLoopAsync()
    {
        while (true)
        {
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("\n[yellow]Main Menu:[/]")
                    .PageSize(10)
                    .AddChoices(
                        "View Devices",
                        "Block Device",
                        "Unblock Device",
                        "View Blocked Devices",
                        "Rescan Network",
                        "View Logs",
                        "Exit"));

            switch (choice)
            {
                case "View Devices":
                    DisplayDevices();
                    break;
                case "Block Device":
                    await BlockDeviceMenuAsync();
                    break;
                case "Unblock Device":
                    await UnblockDeviceMenuAsync();
                    break;
                case "View Blocked Devices":
                    DisplayBlockedDevices();
                    break;
                case "Rescan Network":
                    await ScanNetworkAsync();
                    break;
                case "View Logs":
                    DisplayLogs();
                    break;
                case "Exit":
                    return;
            }
        }
    }

    private static void DisplayDevices()
    {
        if (_arpService == null) return;

        // Start with discovered devices
        var devices = _arpService.DiscoveredDevices.Values.ToList();

        // Ensure gateway and local interface are present in the list for display
        if (_selectedInterface != null)
        {
            var gwIp = _selectedInterface.GatewayAddress;
            if (gwIp != null && !devices.Any(d => d.IpAddress.Equals(gwIp)))
            {
                devices.Add(new NetworkDevice
                {
                    IpAddress = gwIp,
                    MacAddress = PhysicalAddress.None,
                    Hostname = null,
                    IsGateway = true
                });
            }

            var localIp = _selectedInterface.IpAddress;
            if (!devices.Any(d => d.IpAddress.Equals(localIp)))
            {
                devices.Add(new NetworkDevice
                {
                    IpAddress = localIp,
                    MacAddress = _selectedInterface.MacAddress,
                    Hostname = Environment.MachineName,
                    IsGateway = false
                });
            }
        }

        // Order devices: Gateway first, Host second, then rest by IP
        var ordered = devices
            .OrderByDescending(d => d.IsGateway)
            .ThenByDescending(d => _selectedInterface != null && d.IpAddress.Equals(_selectedInterface.IpAddress))
            .ThenBy(d => d.IpAddress.GetAddressBytes()[3])
            .ToList();

        var table = new Table()
            .Border(TableBorder.Rounded)
            .Title("[blue]Network Devices[/]")
            .AddColumn("[yellow]#[/]")
            .AddColumn("[yellow]IP Address[/]")
            .AddColumn("[yellow]MAC Address[/]")
            .AddColumn("[yellow]Hostname[/]")
            .AddColumn("[yellow]Role[/]")
            .AddColumn("[yellow]Status[/]");

        int index = 1;
        foreach (var device in ordered)
        {
            // Determine role label: Gateway, Host, or Device. If both, show both.
            var roles = new List<string>();
            if (device.IsGateway) roles.Add("[cyan]Gateway[/]");
            if (_selectedInterface != null && device.IpAddress.Equals(_selectedInterface.IpAddress)) roles.Add("[green]Host[/]");

            var role = roles.Count > 0 ? string.Join(" / ", roles) : "Device";

            // Determine status
            string status;
            if (device.IsBlocked)
                status = "[red]Blocked[/]";
            else
                status = "[green]Online[/]";

            var macBytes = device.MacAddress?.GetAddressBytes() ?? Array.Empty<byte>();
            var macStr = macBytes.Length > 0 ? device.MacAddressString : "-";

            table.AddRow(
                index.ToString(),
                device.IpAddress.ToString(),
                macStr,
                device.Hostname ?? "-",
                role,
                status);

            index++;
        }

        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine($"\n[blue]Total devices:[/] {ordered.Count}");
    }

    private static async Task BlockDeviceMenuAsync()
    {
        if (_arpService == null || _blockingService == null) return;

        var devices = _arpService.DiscoveredDevices.Values
            .Where(d => !d.IsGateway && !d.IsBlocked)
            .OrderBy(d => d.IpAddress, new IpAddressComparer())
            .ToList();

        if (devices.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No devices available to block.[/]");
            return;
        }

        var choices = devices.Select(d =>
            $"{d.IpAddress,-15} | {d.MacAddressString} | {d.Hostname ?? "Unknown"}").ToList();
        choices.Add("← Back");

        var selected = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[yellow]Select device to block:[/]")
                .PageSize(15)
                .AddChoices(choices));

        if (selected == "← Back") return;

        var index = choices.IndexOf(selected);
        var device = devices[index];

        _blockingService.BlockDevice(device);
        AnsiConsole.MarkupLine($"[red]Blocked:[/] {device.IpAddress}");

        await Task.Delay(500); // Let spoof packets send
    }

    private static async Task UnblockDeviceMenuAsync()
    {
        if (_blockingService == null) return;

        var blocked = _blockingService.BlockedDevices.Values.ToList();

        if (blocked.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No blocked devices.[/]");
            return;
        }

        var deviceChoices = blocked.Select(b =>
            $"{b.Device.IpAddress,-15} | {b.Device.MacAddressString} | Blocked at {b.BlockedAt:HH:mm:ss}").ToList();

        var choices = new List<string>(deviceChoices) { "← Back" };
        var selected = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[yellow]Select device to unblock:[/]")
                .PageSize(15)
                .AddChoices(choices));

        if (selected == "← Back") return;

        var index = deviceChoices.IndexOf(selected);
        if (index < 0 || index >= blocked.Count)
        {
            AnsiConsole.MarkupLine("[red]Invalid selection.[/]");
            return;
        }

        var device = blocked[index].Device;

        try
        {
            await _blockingService.UnblockDeviceAsync(device);
            AnsiConsole.MarkupLine($"[green]Unblocked:[/] {device.IpAddress}");
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error unblocking device:[/] {ex.Message}");
        }
    }

    private static void DisplayBlockedDevices()
    {
        if (_blockingService == null) return;

        var blocked = _blockingService.BlockedDevices.Values
            .OrderBy(b => b.Device.IpAddress, new IpAddressComparer())
            .ToList();

        if (blocked.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No blocked devices.[/]");
            return;
        }

        var table = new Table()
            .Border(TableBorder.Rounded)
            .Title("[red]Blocked Devices[/]")
            .AddColumn("[yellow]IP Address[/]")
            .AddColumn("[yellow]MAC Address[/]")
            .AddColumn("[yellow]Hostname[/]")
            .AddColumn("[yellow]Blocked At[/]")
            .AddColumn("[yellow]Packets Sent[/]");

        foreach (var info in blocked)
        {
            table.AddRow(
                info.Device.IpAddress.ToString(),
                info.Device.MacAddressString,
                info.Device.Hostname ?? "-",
                info.BlockedAt.ToString("HH:mm:ss"),
                info.PacketsSent.ToString());
        }

        AnsiConsole.Write(table);
    }

    private static void DisplayLogs()
    {
        lock (_logLock)
        {
            if (_logMessages.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]No logs yet.[/]");
                return;
            }

            var panel = new Panel(string.Join("\n", _logMessages.TakeLast(20)))
                .Header("[blue]Recent Logs[/]")
                .Border(BoxBorder.Rounded);

            AnsiConsole.Write(panel);
        }
    }

    private static void AddLog(string message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        lock (_logLock)
        {
            _logMessages.Add($"[grey]{timestamp}[/] {message}");

            // Keep only last 100 messages
            if (_logMessages.Count > 100)
                _logMessages.RemoveAt(0);
        }
    }

    private static async Task CleanupAsync()
    {
        AnsiConsole.MarkupLine("\n[yellow]Cleaning up...[/]");

        if (_blockingService != null)
        {
            await _blockingService.StopAsync();
            _blockingService.Dispose();
        }

        _arpService?.Dispose();

        AnsiConsole.MarkupLine("[green]Cleanup complete. Goodbye![/]");
    }

    private static void PrintBanner()
    {
        AnsiConsole.Write(
            new FigletText("NetKick")
                .LeftJustified()
                .Color(Color.Cyan1));

        AnsiConsole.MarkupLine("[grey]ARP Spoofer & Network Blocker[/]");
        AnsiConsole.MarkupLine("[grey]═══════════════════════════════════════════════════════════[/]");
        AnsiConsole.MarkupLine("[red]⚠ WARNING: Only use on networks you own or have permission to test![/]");
        AnsiConsole.MarkupLine("[grey]═══════════════════════════════════════════════════════════[/]\n");
    }

    private static bool IsAdministrator()
    {
        if (OperatingSystem.IsWindows())
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        return Environment.UserName == "root";
    }
}

public class IpAddressComparer : IComparer<System.Net.IPAddress>
{
    public int Compare(System.Net.IPAddress? x, System.Net.IPAddress? y)
    {
        if (x == null && y == null) return 0;
        if (x == null) return -1;
        if (y == null) return 1;

        var xBytes = x.GetAddressBytes();
        var yBytes = y.GetAddressBytes();

        for (int i = 0; i < Math.Min(xBytes.Length, yBytes.Length); i++)
        {
            int result = xBytes[i].CompareTo(yBytes[i]);
            if (result != 0) return result;
        }

        return xBytes.Length.CompareTo(yBytes.Length);
    }
}
