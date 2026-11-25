namespace FirewallApp.Models;

public enum RuleAction
{
    Allow,
    Deny
}

public sealed class FirewallRule
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public int Priority { get; set; } = 100;
    public string Name { get; set; } = "Rule";
    public RuleAction Action { get; set; } = RuleAction.Deny;
    public string Protocol { get; set; } = "ANY"; // ANY, TCP, UDP, ICMP
    public string SourceIp { get; set; } = "*";   // *, exact IP, or CIDR 192.168.1.0/24
    public string DestinationIp { get; set; } = "*";
    public string SourcePort { get; set; } = "*"; // *, exact port, or range 8000-8080
    public string DestinationPort { get; set; } = "*";
    public bool Enabled { get; set; } = true;
}

public sealed class FirewallEvent
{
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public RuleAction Action { get; init; }
    public string Protocol { get; init; } = string.Empty;
    public string SourceIp { get; init; } = string.Empty;
    public int SourcePort { get; init; }
    public string DestinationIp { get; init; } = string.Empty;
    public int DestinationPort { get; init; }
    public string Flags { get; init; } = "-";
    public string Reason { get; init; } = string.Empty;
    public string InterfaceName { get; init; } = string.Empty;
    public int Length { get; init; }
}

public sealed class FirewallConfigFile
{
    public RuleAction DefaultPolicy { get; set; } = RuleAction.Allow;
    public int SynFloodThresholdPerSec { get; set; } = 25;
    public int PingFloodThresholdPerSec { get; set; } = 20;
    public List<FirewallRule> Rules { get; set; } = [];
}
