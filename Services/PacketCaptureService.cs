using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using FirewallApp.Models;

namespace FirewallApp.Services;

public sealed record NetworkInterfaceDto(string Name, string Description, string IpAddress, string Status);

public sealed class PacketCaptureService : IDisposable
{
    private readonly FirewallEngine _engine;
    private CancellationTokenSource? _cts;
    private Task? _captureTask;
    private Socket? _rawSocket;

    public bool IsCapturing { get; private set; }
    public string ActiveInterface { get; private set; } = "Simulator";
    public string StatusMessage { get; private set; } = "Остановлен (готов к захвату или симуляции)";

    public PacketCaptureService(FirewallEngine engine)
    {
        _engine = engine;
    }

    public List<NetworkInterfaceDto> GetInterfaces()
    {
        var list = new List<NetworkInterfaceDto>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            var props = ni.GetIPProperties();
            var ipv4 = props.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
            if (ipv4 is null) continue;

            list.Add(new NetworkInterfaceDto(
                ni.Name,
                ni.Description,
                ipv4.Address.ToString(),
                ni.OperationalStatus.ToString()));
        }
        return list;
    }

    public (bool Started, string Mode, string Message) StartCapture(string ipAddress)
    {
        StopCapture();
        _cts = new CancellationTokenSource();

        if (OperatingSystem.IsWindows() && IPAddress.TryParse(ipAddress, out var bindIp))
        {
            try
            {
                var sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                sock.Bind(new IPEndPoint(bindIp, 0));
                sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                byte[] inValue = [1, 0, 0, 0];
                byte[] outValue = new byte[4];
                sock.IOControl(IOControlCode.ReceiveAll, inValue, outValue);

                _rawSocket = sock;
                IsCapturing = true;
                ActiveInterface = ipAddress;
                StatusMessage = $"Live Raw Socket захват активен на {ipAddress}";
                _captureTask = Task.Run(() => RunRawCaptureLoop(sock, ipAddress, _cts.Token));
                return (true, "live", StatusMessage);
            }
            catch (Exception ex)
            {
                // Non-admin fallback: run background simulation stream
                IsCapturing = true;
                ActiveInterface = $"{ipAddress} (Simulation Fallback)";
                StatusMessage = $"Raw Socket требует прав Администратора ({ex.Message}). Включен режим симуляции трафика.";
                _captureTask = Task.Run(() => RunSimulationLoop(_cts.Token));
                return (true, "simulation", StatusMessage);
            }
        }

        IsCapturing = true;
        ActiveInterface = "Simulator";
        StatusMessage = "Запущен поток симуляции сетевых пакетов";
        _captureTask = Task.Run(() => RunSimulationLoop(_cts.Token));
        return (true, "simulation", StatusMessage);
    }

    public void StopCapture()
    {
        _cts?.Cancel();
        try { _rawSocket?.Close(); } catch { }
        _rawSocket?.Dispose();
        _rawSocket = null;
        IsCapturing = false;
        StatusMessage = "Захват остановлен";
    }

    public List<FirewallEvent> SimulateScenario(string scenario)
    {
        var results = new List<FirewallEvent>();
        switch (scenario.ToLowerInvariant())
        {
            case "syn-flood":
                for (int i = 0; i < 35; i++)
                {
                    var raw = PacketParser.BuildIPv4Packet(
                        TrafficProtocol.TCP, "203.0.113.55", "192.168.1.10",
                        40000 + i, 80, new TcpFlags(Syn: true, Ack: false, Fin: false, Rst: false));
                    if (PacketParser.TryParseIPv4(raw, "Simulator", out var pkt) && pkt is not null)
                        results.Add(_engine.Evaluate(pkt));
                }
                break;

            case "ping-flood":
                for (int i = 0; i < 30; i++)
                {
                    var raw = PacketParser.BuildIPv4Packet(
                        TrafficProtocol.ICMP, "198.51.100.77", "192.168.1.10",
                        icmpType: 8, icmpCode: 0);
                    if (PacketParser.TryParseIPv4(raw, "Simulator", out var pkt) && pkt is not null)
                        results.Add(_engine.Evaluate(pkt));
                }
                break;

            default:
                var samples = new[]
                {
                    PacketParser.BuildIPv4Packet(TrafficProtocol.TCP, "192.168.1.15", "93.184.216.34", 51422, 443, new TcpFlags(true, false, false, false)),
                    PacketParser.BuildIPv4Packet(TrafficProtocol.TCP, "93.184.216.34", "192.168.1.15", 443, 51422, new TcpFlags(true, true, false, false)),
                    PacketParser.BuildIPv4Packet(TrafficProtocol.UDP, "192.168.1.15", "8.8.8.8", 54100, 53),
                    PacketParser.BuildIPv4Packet(TrafficProtocol.TCP, "192.168.1.25", "192.168.1.10", 60122, 23, new TcpFlags(true, false, false, false)),
                    PacketParser.BuildIPv4Packet(TrafficProtocol.TCP, "10.99.4.12", "192.168.1.10", 49152, 80, new TcpFlags(true, false, false, false)),
                    PacketParser.BuildIPv4Packet(TrafficProtocol.TCP, "172.16.0.9", "192.168.1.10", 52010, 445, new TcpFlags(true, false, false, false)),
                    PacketParser.BuildIPv4Packet(TrafficProtocol.ICMP, "192.168.1.1", "192.168.1.10", icmpType: 8, icmpCode: 0)
                };
                foreach (var raw in samples)
                {
                    if (PacketParser.TryParseIPv4(raw, "Simulator", out var pkt) && pkt is not null)
                        results.Add(_engine.Evaluate(pkt));
                }
                break;
        }
        return results;
    }

    private void RunRawCaptureLoop(Socket sock, string iface, CancellationToken ct)
    {
        var buffer = new byte[65535];
        while (!ct.IsCancellationRequested)
        {
            try
            {
                int received = sock.Receive(buffer);
                if (received > 0 && PacketParser.TryParseIPv4(buffer.AsSpan(0, received), iface, out var pkt) && pkt is not null)
                {
                    _engine.Evaluate(pkt);
                }
            }
            catch when (ct.IsCancellationRequested)
            {
                break;
            }
            catch
            {
                // Ignore malformed or truncated packets
            }
        }
    }

    private async Task RunSimulationLoop(CancellationToken ct)
    {
        var rng = Random.Shared;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                int pick = rng.Next(5);
                byte[] raw = pick switch
                {
                    0 => PacketParser.BuildIPv4Packet(TrafficProtocol.TCP, "192.168.1.20", "142.250.74.14", rng.Next(49152, 65000), 443, new TcpFlags(false, true, false, false)),
                    1 => PacketParser.BuildIPv4Packet(TrafficProtocol.UDP, "192.168.1.20", "1.1.1.1", rng.Next(49152, 65000), 53),
                    2 => PacketParser.BuildIPv4Packet(TrafficProtocol.TCP, "185.220.101.4", "192.168.1.10", rng.Next(30000, 60000), 23, new TcpFlags(true, false, false, false)),
                    3 => PacketParser.BuildIPv4Packet(TrafficProtocol.TCP, "10.99.12.8", "192.168.1.10", rng.Next(30000, 60000), 80, new TcpFlags(true, false, false, false)),
                    _ => PacketParser.BuildIPv4Packet(TrafficProtocol.ICMP, "192.168.1.1", "192.168.1.10", icmpType: 8, icmpCode: 0)
                };

                if (PacketParser.TryParseIPv4(raw, "Simulator", out var pkt) && pkt is not null)
                    _engine.Evaluate(pkt);

                await Task.Delay(750, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public void Dispose()
    {
        StopCapture();
    }
}
