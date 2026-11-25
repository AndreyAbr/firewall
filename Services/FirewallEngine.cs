using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using FirewallApp.Models;

namespace FirewallApp.Services;

public sealed class FirewallStats
{
    public long TotalPackets { get; set; }
    public long AllowedPackets { get; set; }
    public long DeniedPackets { get; set; }
    public long TcpPackets { get; set; }
    public long UdpPackets { get; set; }
    public long IcmpPackets { get; set; }
    public long FloodBlocks { get; set; }
    public int ActiveConnections { get; set; }
    public int RuleCount { get; set; }
}

public sealed class FirewallEngine : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string _rulesPath;
    private readonly string _logPath;
    private readonly object _configLock = new();
    private readonly object _logLock = new();
    private readonly Queue<FirewallEvent> _recentEvents = new();
    private readonly ConcurrentDictionary<string, DateTime> _establishedTcp = new();
    private readonly ConcurrentDictionary<string, Queue<DateTime>> _synRate = new();
    private readonly ConcurrentDictionary<string, Queue<DateTime>> _icmpRate = new();
    private FileSystemWatcher? _watcher;

    private FirewallConfigFile _config = new();
    private long _totalPackets;
    private long _allowedPackets;
    private long _deniedPackets;
    private long _tcpPackets;
    private long _udpPackets;
    private long _icmpPackets;
    private long _floodBlocks;

    public FirewallEngine(string rulesPath, string logPath)
    {
        _rulesPath = rulesPath;
        _logPath = logPath;
        LoadRules();
        StartHotReloadWatcher();
    }

    public RuleAction DefaultPolicy
    {
        get { lock (_configLock) return _config.DefaultPolicy; }
    }

    public FirewallConfigFile GetConfigSnapshot()
    {
        lock (_configLock)
        {
            return new FirewallConfigFile
            {
                DefaultPolicy = _config.DefaultPolicy,
                SynFloodThresholdPerSec = _config.SynFloodThresholdPerSec,
                PingFloodThresholdPerSec = _config.PingFloodThresholdPerSec,
                Rules = _config.Rules.OrderBy(r => r.Priority).ToList()
            };
        }
    }

    public void LoadRules()
    {
        lock (_configLock)
        {
            if (!File.Exists(_rulesPath))
            {
                _config = CreateDefaultConfig();
                SaveRulesLocked();
                return;
            }

            var json = File.ReadAllText(_rulesPath);
            var loaded = JsonSerializer.Deserialize<FirewallConfigFile>(json, JsonOptions);
            _config = loaded ?? CreateDefaultConfig();
        }
    }

    public void SaveRule(FirewallRule rule)
    {
        lock (_configLock)
        {
            if (string.IsNullOrWhiteSpace(rule.Id))
                rule.Id = Guid.NewGuid().ToString("N")[..8];

            var idx = _config.Rules.FindIndex(r => r.Id == rule.Id);
            if (idx >= 0)
                _config.Rules[idx] = rule;
            else
                _config.Rules.Add(rule);

            SaveRulesLocked();
        }
    }

    public bool DeleteRule(string id)
    {
        lock (_configLock)
        {
            int removed = _config.Rules.RemoveAll(r => r.Id == id);
            if (removed > 0)
            {
                SaveRulesLocked();
                return true;
            }
            return false;
        }
    }

    public bool ToggleRule(string id)
    {
        lock (_configLock)
        {
            var rule = _config.Rules.FirstOrDefault(r => r.Id == id);
            if (rule is null) return false;
            rule.Enabled = !rule.Enabled;
            SaveRulesLocked();
            return true;
        }
    }

    public void SetDefaultPolicy(RuleAction policy)
    {
        lock (_configLock)
        {
            _config.DefaultPolicy = policy;
            SaveRulesLocked();
        }
    }

    public FirewallEvent Evaluate(PacketInfo packet)
    {
        Interlocked.Increment(ref _totalPackets);
        switch (packet.Protocol)
        {
            case TrafficProtocol.TCP: Interlocked.Increment(ref _tcpPackets); break;
            case TrafficProtocol.UDP: Interlocked.Increment(ref _udpPackets); break;
            case TrafficProtocol.ICMP: Interlocked.Increment(ref _icmpPackets); break;
        }

        FirewallConfigFile cfg;
        lock (_configLock)
        {
            cfg = _config;
        }

        RuleAction action;
        string reason;

        if (packet.Protocol == TrafficProtocol.TCP && packet.TcpFlags.Syn && !packet.TcpFlags.Ack &&
            IsRateExceeded(_synRate, packet.SourceIp, packet.Timestamp, cfg.SynFloodThresholdPerSec))
        {
            action = RuleAction.Deny;
            reason = $"SYN-flood protection (>{cfg.SynFloodThresholdPerSec}/s from {packet.SourceIp})";
            Interlocked.Increment(ref _floodBlocks);
        }
        else if (packet.Protocol == TrafficProtocol.ICMP && packet.IcmpType == 8 &&
                 IsRateExceeded(_icmpRate, packet.SourceIp, packet.Timestamp, cfg.PingFloodThresholdPerSec))
        {
            action = RuleAction.Deny;
            reason = $"Ping-flood protection (>{cfg.PingFloodThresholdPerSec}/s from {packet.SourceIp})";
            Interlocked.Increment(ref _floodBlocks);
        }
        else if (IsStatefulReturnAllowed(packet))
        {
            action = RuleAction.Allow;
            reason = "Stateful TCP session";
        }
        else
        {
            var matched = cfg.Rules
                .Where(r => r.Enabled)
                .OrderBy(r => r.Priority)
                .FirstOrDefault(r => MatchesRule(r, packet));

            if (matched is not null)
            {
                action = matched.Action;
                reason = $"Rule [{matched.Priority}] {matched.Name}";
            }
            else
            {
                action = cfg.DefaultPolicy;
                reason = $"Default policy ({cfg.DefaultPolicy})";
            }
        }

        if (action == RuleAction.Allow)
        {
            Interlocked.Increment(ref _allowedPackets);
            TrackTcpConnection(packet);
        }
        else
        {
            Interlocked.Increment(ref _deniedPackets);
        }

        var ev = new FirewallEvent
        {
            Timestamp = packet.Timestamp,
            Action = action,
            Protocol = packet.Protocol.ToString(),
            SourceIp = packet.SourceIp,
            SourcePort = packet.SourcePort,
            DestinationIp = packet.DestinationIp,
            DestinationPort = packet.DestinationPort,
            Flags = packet.Protocol == TrafficProtocol.TCP
                ? packet.TcpFlags.ToString()
                : (packet.Protocol == TrafficProtocol.ICMP ? $"type={packet.IcmpType}" : "-"),
            Reason = reason,
            InterfaceName = packet.InterfaceName,
            Length = packet.PayloadLength
        };

        RecordEvent(ev);
        return ev;
    }

    public List<FirewallEvent> GetRecentEvents(int maxCount = 150)
    {
        lock (_logLock)
        {
            return _recentEvents.Reverse().Take(maxCount).ToList();
        }
    }

    public FirewallStats GetStats()
    {
        PruneOldConnections();
        int rulesCount;
        lock (_configLock) rulesCount = _config.Rules.Count;

        return new FirewallStats
        {
            TotalPackets = Interlocked.Read(ref _totalPackets),
            AllowedPackets = Interlocked.Read(ref _allowedPackets),
            DeniedPackets = Interlocked.Read(ref _deniedPackets),
            TcpPackets = Interlocked.Read(ref _tcpPackets),
            UdpPackets = Interlocked.Read(ref _udpPackets),
            IcmpPackets = Interlocked.Read(ref _icmpPackets),
            FloodBlocks = Interlocked.Read(ref _floodBlocks),
            ActiveConnections = _establishedTcp.Count,
            RuleCount = rulesCount
        };
    }

    private bool IsStatefulReturnAllowed(PacketInfo p)
    {
        if (p.Protocol != TrafficProtocol.TCP) return false;
        if (!p.TcpFlags.Ack || p.TcpFlags.Syn)
        {
            // Also allow SYN-ACK only if forward SYN was recorded
            if (!(p.TcpFlags.Syn && p.TcpFlags.Ack))
                return false;
        }

        var reverseKey = $"{p.DestinationIp}:{p.DestinationPort}->{p.SourceIp}:{p.SourcePort}";
        if (_establishedTcp.TryGetValue(reverseKey, out var seenAt) &&
            (p.Timestamp - seenAt) < TimeSpan.FromMinutes(2))
        {
            _establishedTcp[reverseKey] = p.Timestamp;
            return true;
        }
        return false;
    }

    private void TrackTcpConnection(PacketInfo p)
    {
        if (p.Protocol != TrafficProtocol.TCP) return;
        var key = $"{p.SourceIp}:{p.SourcePort}->{p.DestinationIp}:{p.DestinationPort}";
        if (p.TcpFlags.Fin || p.TcpFlags.Rst)
        {
            _establishedTcp.TryRemove(key, out _);
            return;
        }
        _establishedTcp[key] = p.Timestamp;
    }

    private void PruneOldConnections()
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-2);
        foreach (var kv in _establishedTcp)
        {
            if (kv.Value < cutoff)
                _establishedTcp.TryRemove(kv.Key, out _);
        }
    }

    private static bool IsRateExceeded(
        ConcurrentDictionary<string, Queue<DateTime>> tracker,
        string ip,
        DateTime now,
        int thresholdPerSec)
    {
        if (thresholdPerSec <= 0) return false;
        var q = tracker.GetOrAdd(ip, _ => new Queue<DateTime>());
        lock (q)
        {
            q.Enqueue(now);
            while (q.Count > 0 && (now - q.Peek()).TotalSeconds > 1.0)
                q.Dequeue();
            return q.Count > thresholdPerSec;
        }
    }

    public static bool MatchesRule(FirewallRule rule, PacketInfo packet)
    {
        if (!string.Equals(rule.Protocol, "ANY", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(rule.Protocol, packet.Protocol.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!MatchesIp(rule.SourceIp, packet.SourceIp)) return false;
        if (!MatchesIp(rule.DestinationIp, packet.DestinationIp)) return false;

        if (packet.Protocol is TrafficProtocol.TCP or TrafficProtocol.UDP)
        {
            if (!MatchesPort(rule.SourcePort, packet.SourcePort)) return false;
            if (!MatchesPort(rule.DestinationPort, packet.DestinationPort)) return false;
        }
        else
        {
            if (!IsWildcard(rule.SourcePort) || !IsWildcard(rule.DestinationPort))
                return false;
        }

        return true;
    }

    public static bool MatchesIp(string pattern, string ipText)
    {
        if (IsWildcard(pattern)) return true;
        if (!IPAddress.TryParse(ipText, out var addr)) return false;

        int slash = pattern.IndexOf('/');
        if (slash < 0)
        {
            return IPAddress.TryParse(pattern.Trim(), out var target) && addr.Equals(target);
        }

        var netPart = pattern[..slash].Trim();
        if (!IPAddress.TryParse(netPart, out var network) ||
            !int.TryParse(pattern[(slash + 1)..], out int prefixLen) ||
            prefixLen < 0 || prefixLen > 32)
        {
            return false;
        }

        uint mask = prefixLen == 0 ? 0 : uint.MaxValue << (32 - prefixLen);
        uint ipVal = BinaryPrimitives.ReadUInt32BigEndian(addr.GetAddressBytes());
        uint netVal = BinaryPrimitives.ReadUInt32BigEndian(network.GetAddressBytes());
        return (ipVal & mask) == (netVal & mask);
    }

    public static bool MatchesPort(string pattern, int port)
    {
        if (IsWildcard(pattern)) return true;
        int dash = pattern.IndexOf('-');
        if (dash > 0)
        {
            if (int.TryParse(pattern[..dash], out int start) &&
                int.TryParse(pattern[(dash + 1)..], out int end))
            {
                return port >= start && port <= end;
            }
            return false;
        }

        return int.TryParse(pattern.Trim(), out int exact) && port == exact;
    }

    private static bool IsWildcard(string s) => string.IsNullOrWhiteSpace(s) || s.Trim() == "*";

    private void RecordEvent(FirewallEvent ev)
    {
        lock (_logLock)
        {
            _recentEvents.Enqueue(ev);
            while (_recentEvents.Count > 500)
                _recentEvents.Dequeue();

            try
            {
                var dir = Path.GetDirectoryName(_logPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                var line = $"{ev.Timestamp:O} | {ev.Action,-5} | {ev.Protocol,-4} | {ev.SourceIp}:{ev.SourcePort} -> {ev.DestinationIp}:{ev.DestinationPort} | flags={ev.Flags} | {ev.Reason}{Environment.NewLine}";
                File.AppendAllText(_logPath, line);
            }
            catch
            {
                // Ignore disk write issues during evaluation
            }
        }
    }

    private void SaveRulesLocked()
    {
        var dir = Path.GetDirectoryName(_rulesPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(_rulesPath, JsonSerializer.Serialize(_config, JsonOptions));
    }

    private void StartHotReloadWatcher()
    {
        try
        {
            var dir = Path.GetDirectoryName(_rulesPath);
            var file = Path.GetFileName(_rulesPath);
            if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(file) || !Directory.Exists(dir))
                return;

            _watcher = new FileSystemWatcher(dir, file)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size
            };
            _watcher.Changed += (_, _) =>
            {
                try
                {
                    Thread.Sleep(50);
                    LoadRules();
                }
                catch
                {
                    // Ignore transient file lock on save
                }
            };
            _watcher.EnableRaisingEvents = true;
        }
        catch
        {
            // Hot reload is optional
        }
    }

    private static FirewallConfigFile CreateDefaultConfig() => new()
    {
        DefaultPolicy = RuleAction.Allow,
        SynFloodThresholdPerSec = 25,
        PingFloodThresholdPerSec = 20,
        Rules =
        [
            new FirewallRule { Id = "r-telnet", Priority = 10, Name = "Block Telnet (23)", Action = RuleAction.Deny, Protocol = "TCP", DestinationPort = "23" },
            new FirewallRule { Id = "r-smb", Priority = 20, Name = "Block SMB (445)", Action = RuleAction.Deny, Protocol = "TCP", DestinationPort = "445" },
            new FirewallRule { Id = "r-subnet", Priority = 30, Name = "Block Untrusted Subnet", Action = RuleAction.Deny, Protocol = "ANY", SourceIp = "10.99.0.0/16" },
            new FirewallRule { Id = "r-https", Priority = 40, Name = "Allow HTTPS (443)", Action = RuleAction.Allow, Protocol = "TCP", DestinationPort = "443" },
            new FirewallRule { Id = "r-http", Priority = 50, Name = "Allow HTTP (80)", Action = RuleAction.Allow, Protocol = "TCP", DestinationPort = "80" },
            new FirewallRule { Id = "r-dns", Priority = 60, Name = "Allow DNS (53)", Action = RuleAction.Allow, Protocol = "UDP", DestinationPort = "53" }
        ]
    };

    public void Dispose()
    {
        _watcher?.Dispose();
    }
}
