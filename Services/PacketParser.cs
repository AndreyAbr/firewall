using System.Buffers.Binary;
using System.Net;
using FirewallApp.Models;

namespace FirewallApp.Services;

public static class PacketParser
{
    public static bool TryParseIPv4(ReadOnlySpan<byte> buffer, string interfaceName, out PacketInfo? packet)
    {
        packet = null;
        if (buffer.Length < 20)
            return false;

        int version = (buffer[0] >> 4) & 0x0F;
        if (version != 4)
            return false;

        int ihlBytes = (buffer[0] & 0x0F) * 4;
        if (ihlBytes < 20 || buffer.Length < ihlBytes)
            return false;

        int totalLength = BinaryPrimitives.ReadUInt16BigEndian(buffer[2..4]);
        if (totalLength < ihlBytes)
            totalLength = buffer.Length;

        byte protoByte = buffer[9];
        var protocol = protoByte switch
        {
            1 => TrafficProtocol.ICMP,
            6 => TrafficProtocol.TCP,
            17 => TrafficProtocol.UDP,
            _ => TrafficProtocol.Other
        };

        var srcIp = new IPAddress(buffer[12..16]).ToString();
        var dstIp = new IPAddress(buffer[16..20]).ToString();

        int srcPort = 0;
        int dstPort = 0;
        var tcpFlags = TcpFlags.None;
        byte icmpType = 0;
        byte icmpCode = 0;
        int payloadOffset = ihlBytes;

        var l4 = buffer[ihlBytes..];
        if (protocol == TrafficProtocol.TCP && l4.Length >= 20)
        {
            srcPort = BinaryPrimitives.ReadUInt16BigEndian(l4[0..2]);
            dstPort = BinaryPrimitives.ReadUInt16BigEndian(l4[2..4]);
            byte flags = l4[13];
            tcpFlags = new TcpFlags(
                Syn: (flags & 0x02) != 0,
                Ack: (flags & 0x10) != 0,
                Fin: (flags & 0x01) != 0,
                Rst: (flags & 0x04) != 0);
            int dataOffset = ((l4[12] >> 4) & 0x0F) * 4;
            payloadOffset = ihlBytes + Math.Max(20, dataOffset);
        }
        else if (protocol == TrafficProtocol.UDP && l4.Length >= 8)
        {
            srcPort = BinaryPrimitives.ReadUInt16BigEndian(l4[0..2]);
            dstPort = BinaryPrimitives.ReadUInt16BigEndian(l4[2..4]);
            payloadOffset = ihlBytes + 8;
        }
        else if (protocol == TrafficProtocol.ICMP && l4.Length >= 4)
        {
            icmpType = l4[0];
            icmpCode = l4[1];
            payloadOffset = ihlBytes + 8;
        }

        int payloadLen = Math.Max(0, Math.Min(buffer.Length, totalLength) - payloadOffset);

        packet = new PacketInfo
        {
            Timestamp = DateTime.UtcNow,
            Protocol = protocol,
            SourceIp = srcIp,
            DestinationIp = dstIp,
            SourcePort = srcPort,
            DestinationPort = dstPort,
            TcpFlags = tcpFlags,
            IcmpType = icmpType,
            IcmpCode = icmpCode,
            PayloadLength = payloadLen,
            InterfaceName = interfaceName
        };
        return true;
    }

    public static byte[] BuildIPv4Packet(
        TrafficProtocol protocol,
        string srcIp,
        string dstIp,
        int srcPort = 0,
        int dstPort = 0,
        TcpFlags? tcpFlags = null,
        byte icmpType = 8,
        byte icmpCode = 0,
        int payloadBytes = 32)
    {
        int l4Len = protocol switch
        {
            TrafficProtocol.TCP => 20,
            TrafficProtocol.UDP => 8,
            TrafficProtocol.ICMP => 8,
            _ => 0
        };
        int totalLen = 20 + l4Len + Math.Max(0, payloadBytes);
        var buf = new byte[totalLen];

        buf[0] = 0x45; // IPv4, IHL = 5 (20 bytes)
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(2, 2), (ushort)totalLen);
        buf[8] = 64; // TTL
        buf[9] = (byte)protocol;
        IPAddress.Parse(srcIp).TryWriteBytes(buf.AsSpan(12, 4), out _);
        IPAddress.Parse(dstIp).TryWriteBytes(buf.AsSpan(16, 4), out _);

        if (protocol == TrafficProtocol.TCP)
        {
            var l4 = buf.AsSpan(20, 20);
            BinaryPrimitives.WriteUInt16BigEndian(l4[0..2], (ushort)srcPort);
            BinaryPrimitives.WriteUInt16BigEndian(l4[2..4], (ushort)dstPort);
            l4[12] = 0x50; // Data offset 5 (20 bytes)
            byte f = 0;
            if (tcpFlags is not null)
            {
                if (tcpFlags.Fin) f |= 0x01;
                if (tcpFlags.Syn) f |= 0x02;
                if (tcpFlags.Rst) f |= 0x04;
                if (tcpFlags.Ack) f |= 0x10;
            }
            l4[13] = f;
        }
        else if (protocol == TrafficProtocol.UDP)
        {
            var l4 = buf.AsSpan(20, 8);
            BinaryPrimitives.WriteUInt16BigEndian(l4[0..2], (ushort)srcPort);
            BinaryPrimitives.WriteUInt16BigEndian(l4[2..4], (ushort)dstPort);
            BinaryPrimitives.WriteUInt16BigEndian(l4[4..6], (ushort)(8 + payloadBytes));
        }
        else if (protocol == TrafficProtocol.ICMP)
        {
            var l4 = buf.AsSpan(20, 8);
            l4[0] = icmpType;
            l4[1] = icmpCode;
        }

        return buf;
    }
}
