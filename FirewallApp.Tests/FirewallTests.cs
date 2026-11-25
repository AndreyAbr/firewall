using FirewallApp.Models;
using FirewallApp.Services;
using Xunit;

namespace FirewallApp.Tests;

public class FirewallTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "FirewallTests_" + Guid.NewGuid().ToString("N"));

    public FirewallTests() => Directory.CreateDirectory(_tempDir);

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    private FirewallEngine CreateEngine() =>
        new(Path.Combine(_tempDir, "rules.json"), Path.Combine(_tempDir, "firewall.log"));

    [Fact]
    public void PacketParser_ParsesTcpUdpIcmpCorrectly()
    {
        var tcpBytes = PacketParser.BuildIPv4Packet(
            TrafficProtocol.TCP, "192.168.1.10", "10.0.0.5", 51000, 443,
            new TcpFlags(Syn: true, Ack: false, Fin: false, Rst: false), payloadBytes: 24);
        Assert.True(PacketParser.TryParseIPv4(tcpBytes, "eth0", out var tcp));
        Assert.Equal(TrafficProtocol.TCP, tcp!.Protocol);
        Assert.Equal("192.168.1.10", tcp.SourceIp);
        Assert.Equal("10.0.0.5", tcp.DestinationIp);
        Assert.Equal(51000, tcp.SourcePort);
        Assert.Equal(443, tcp.DestinationPort);
        Assert.True(tcp.TcpFlags.Syn);
        Assert.False(tcp.TcpFlags.Ack);

        var udpBytes = PacketParser.BuildIPv4Packet(TrafficProtocol.UDP, "192.168.1.2", "8.8.8.8", 40000, 53);
        Assert.True(PacketParser.TryParseIPv4(udpBytes, "eth0", out var udp));
        Assert.Equal(TrafficProtocol.UDP, udp!.Protocol);
        Assert.Equal(53, udp.DestinationPort);

        var icmpBytes = PacketParser.BuildIPv4Packet(TrafficProtocol.ICMP, "192.168.1.1", "192.168.1.2", icmpType: 8, icmpCode: 0);
        Assert.True(PacketParser.TryParseIPv4(icmpBytes, "eth0", out var icmp));
        Assert.Equal(TrafficProtocol.ICMP, icmp!.Protocol);
        Assert.Equal((byte)8, icmp.IcmpType);
    }

    [Fact]
    public void FirewallEngine_EvaluatesCidrPortRangesAndPriorities()
    {
        using var fw = CreateEngine();
        fw.SaveRule(new FirewallRule
        {
            Id = "allow-high",
            Priority = 5,
            Name = "Allow VIP in subnet",
            Action = RuleAction.Allow,
            Protocol = "TCP",
            SourceIp = "10.99.1.5",
            DestinationPort = "8000-8080"
        });

        var vipPacket = new PacketInfo
        {
            Protocol = TrafficProtocol.TCP,
            SourceIp = "10.99.1.5",
            DestinationIp = "192.168.1.10",
            SourcePort = 50000,
            DestinationPort = 8050,
            TcpFlags = new TcpFlags(true, false, false, false)
        };
        Assert.Equal(RuleAction.Allow, fw.Evaluate(vipPacket).Action);

        var blockedSubnetPacket = new PacketInfo
        {
            Protocol = TrafficProtocol.TCP,
            SourceIp = "10.99.2.15",
            DestinationIp = "192.168.1.10",
            SourcePort = 50001,
            DestinationPort = 80,
            TcpFlags = new TcpFlags(true, false, false, false)
        };
        Assert.Equal(RuleAction.Deny, fw.Evaluate(blockedSubnetPacket).Action);

        var telnetPacket = new PacketInfo
        {
            Protocol = TrafficProtocol.TCP,
            SourceIp = "192.168.1.20",
            DestinationIp = "192.168.1.10",
            SourcePort = 50002,
            DestinationPort = 23
        };
        Assert.Equal(RuleAction.Deny, fw.Evaluate(telnetPacket).Action);
        Assert.True(File.Exists(Path.Combine(_tempDir, "firewall.log")));
    }

    [Fact]
    public void FirewallEngine_StatefulInspection_AllowsReturnTraffic()
    {
        using var fw = CreateEngine();
        fw.SetDefaultPolicy(RuleAction.Deny);

        var outbound = new PacketInfo
        {
            Protocol = TrafficProtocol.TCP,
            SourceIp = "192.168.1.50",
            DestinationIp = "93.184.216.34",
            SourcePort = 55000,
            DestinationPort = 443,
            TcpFlags = new TcpFlags(true, false, false, false)
        };
        Assert.Equal(RuleAction.Allow, fw.Evaluate(outbound).Action);

        var inboundReply = new PacketInfo
        {
            Protocol = TrafficProtocol.TCP,
            SourceIp = "93.184.216.34",
            DestinationIp = "192.168.1.50",
            SourcePort = 443,
            DestinationPort = 55000,
            TcpFlags = new TcpFlags(true, true, false, false)
        };
        var replyResult = fw.Evaluate(inboundReply);
        Assert.Equal(RuleAction.Allow, replyResult.Action);
        Assert.Contains("Stateful", replyResult.Reason);
    }

    [Fact]
    public void FirewallEngine_DetectsSynFloodAndPingFlood()
    {
        using var fw = CreateEngine();
        var now = DateTime.UtcNow;

        FirewallEvent? lastSyn = null;
        for (int i = 0; i < 30; i++)
        {
            lastSyn = fw.Evaluate(new PacketInfo
            {
                Timestamp = now.AddMilliseconds(i * 5),
                Protocol = TrafficProtocol.TCP,
                SourceIp = "203.0.113.10",
                DestinationIp = "192.168.1.1",
                SourcePort = 30000 + i,
                DestinationPort = 80,
                TcpFlags = new TcpFlags(true, false, false, false)
            });
        }
        Assert.Equal(RuleAction.Deny, lastSyn!.Action);
        Assert.Contains("SYN-flood", lastSyn.Reason);

        FirewallEvent? lastPing = null;
        for (int i = 0; i < 25; i++)
        {
            lastPing = fw.Evaluate(new PacketInfo
            {
                Timestamp = now.AddMilliseconds(i * 5),
                Protocol = TrafficProtocol.ICMP,
                SourceIp = "198.51.100.20",
                DestinationIp = "192.168.1.1",
                IcmpType = 8,
                IcmpCode = 0
            });
        }
        Assert.Equal(RuleAction.Deny, lastPing!.Action);
        Assert.Contains("Ping-flood", lastPing.Reason);
    }
}
