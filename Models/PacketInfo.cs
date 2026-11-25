namespace FirewallApp.Models;

public enum TrafficProtocol
{
    Any = 0,
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    Other = 255
}

public sealed record TcpFlags(bool Syn, bool Ack, bool Fin, bool Rst)
{
    public static readonly TcpFlags None = new(false, false, false, false);

    public override string ToString()
    {
        var flags = new List<string>(4);
        if (Syn) flags.Add("SYN");
        if (Ack) flags.Add("ACK");
        if (Fin) flags.Add("FIN");
        if (Rst) flags.Add("RST");
        return flags.Count == 0 ? "-" : string.Join(",", flags);
    }
}

public sealed class PacketInfo
{
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public TrafficProtocol Protocol { get; init; }
    public string SourceIp { get; init; } = "0.0.0.0";
    public string DestinationIp { get; init; } = "0.0.0.0";
    public int SourcePort { get; init; }
    public int DestinationPort { get; init; }
    public TcpFlags TcpFlags { get; init; } = TcpFlags.None;
    public byte IcmpType { get; init; }
    public byte IcmpCode { get; init; }
    public int PayloadLength { get; init; }
    public string InterfaceName { get; init; } = "Simulator";
}
