using System.Text.Json.Serialization;
using FirewallApp.Models;
using FirewallApp.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

var contentRoot = builder.Environment.ContentRootPath;
var rulesPath = Path.Combine(contentRoot, "rules.json");
var logPath = Path.Combine(contentRoot, "firewall.log");

var engine = new FirewallEngine(rulesPath, logPath);
var capture = new PacketCaptureService(engine);

builder.Services.AddSingleton(engine);
builder.Services.AddSingleton(capture);

var app = builder.Build();
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/status", (PacketCaptureService cap, FirewallEngine fw) => Results.Ok(new
{
    cap.IsCapturing,
    cap.ActiveInterface,
    cap.StatusMessage,
    DefaultPolicy = fw.DefaultPolicy.ToString(),
    Stats = fw.GetStats()
}));

app.MapGet("/api/interfaces", (PacketCaptureService cap) => Results.Ok(cap.GetInterfaces()));

app.MapPost("/api/capture/start", (CaptureStartRequest req, PacketCaptureService cap) =>
{
    var res = cap.StartCapture(req.IpAddress ?? "127.0.0.1");
    return Results.Ok(new { res.Started, res.Mode, res.Message });
});

app.MapPost("/api/capture/stop", (PacketCaptureService cap) =>
{
    cap.StopCapture();
    return Results.Ok(new { stopped = true, cap.StatusMessage });
});

app.MapPost("/api/simulate/burst", (SimulateRequest req, PacketCaptureService cap) =>
{
    var events = cap.SimulateScenario(req.Scenario ?? "normal");
    return Results.Ok(new { count = events.Count, events });
});

app.MapPost("/api/evaluate", (CustomPacketRequest req, FirewallEngine fw) =>
{
    var proto = Enum.TryParse<TrafficProtocol>(req.Protocol, true, out var parsed)
        ? parsed
        : TrafficProtocol.TCP;
    var raw = PacketParser.BuildIPv4Packet(
        proto,
        req.SourceIp ?? "192.168.1.50",
        req.DestinationIp ?? "192.168.1.10",
        req.SourcePort,
        req.DestinationPort,
        new TcpFlags(req.Syn, req.Ack, false, false));
    PacketParser.TryParseIPv4(raw, "ManualTest", out var packet);
    var ev = fw.Evaluate(packet!);
    return Results.Ok(ev);
});

app.MapGet("/api/rules", (FirewallEngine fw) => Results.Ok(fw.GetConfigSnapshot()));

app.MapPost("/api/rules", (FirewallRule rule, FirewallEngine fw) =>
{
    fw.SaveRule(rule);
    return Results.Ok(rule);
});

app.MapPost("/api/rules/{id}/toggle", (string id, FirewallEngine fw) =>
    fw.ToggleRule(id) ? Results.Ok() : Results.NotFound());

app.MapDelete("/api/rules/{id}", (string id, FirewallEngine fw) =>
    fw.DeleteRule(id) ? Results.Ok() : Results.NotFound());

app.MapPost("/api/rules/reload", (FirewallEngine fw) =>
{
    fw.LoadRules();
    return Results.Ok(fw.GetConfigSnapshot());
});

app.MapPost("/api/policy/{policy}", (string policy, FirewallEngine fw) =>
{
    if (!Enum.TryParse<RuleAction>(policy, true, out var parsed))
        return Results.BadRequest("Invalid policy");
    fw.SetDefaultPolicy(parsed);
    return Results.Ok(new { DefaultPolicy = parsed.ToString() });
});

app.MapGet("/api/logs", (FirewallEngine fw) => Results.Ok(fw.GetRecentEvents(150)));
app.MapGet("/api/stats", (FirewallEngine fw) => Results.Ok(fw.GetStats()));

app.Run();

public sealed record CaptureStartRequest(string? IpAddress);
public sealed record SimulateRequest(string? Scenario);
public sealed record CustomPacketRequest(string? Protocol, string? SourceIp, string? DestinationIp, int SourcePort, int DestinationPort, bool Syn, bool Ack);
