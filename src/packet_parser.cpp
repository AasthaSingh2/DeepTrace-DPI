#include "packet_parser.h"

#include <iomanip>
#include <sstream>

namespace DeepTrace {

std::uint16_t PacketParser::ReadBigEndian16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[0]) << 8) |
        static_cast<std::uint16_t>(data[1]));
}

std::uint32_t PacketParser::ReadBigEndian32(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) |
           static_cast<std::uint32_t>(data[3]);
}

std::string PacketParser::FormatMacAddress(const std::uint8_t mac[6]) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (int index = 0; index < 6; ++index) {
        if (index > 0) {
            stream << ':';
        }
        stream << std::setw(2) << static_cast<int>(mac[index]);
    }
    return stream.str();
}

std::string PacketParser::FormatIPv4Address(std::uint32_t address) {
    std::ostringstream stream;
    stream << ((address >> 24) & 0xff) << '.'
           << ((address >> 16) & 0xff) << '.'
           << ((address >> 8) & 0xff) << '.'
           << (address & 0xff);
    return stream.str();
}

std::string PacketParser::FormatTcpFlags(std::uint8_t flags) {
    std::ostringstream stream;
    bool first = true;

    const struct {
        std::uint8_t mask;
        const char* name;
    } flag_table[] = {
        {0x01, "FIN"},
        {0x02, "SYN"},
        {0x04, "RST"},
        {0x08, "PSH"},
        {0x10, "ACK"},
        {0x20, "URG"},
        {0x40, "ECE"},
        {0x80, "CWR"},
    };

    for (const auto& entry : flag_table) {
        if ((flags & entry.mask) != 0) {
            if (!first) {
                stream << ',';
            }
            stream << entry.name;
            first = false;
        }
    }

    if (first) {
        stream << "NONE";
    }

    return stream.str();
}

ParsedPacket PacketParser::Parse(const std::uint8_t* data, std::size_t length, bool& malformed) const {
    ParsedPacket parsed_packet;
    malformed = false;

    if (data == nullptr || length < kEthernetHeaderLength) {
        malformed = true;
        parsed_packet.summary = "Malformed packet: insufficient bytes for Ethernet header";
        return parsed_packet;
    }

    EthernetHeader ethernet_header{};
    for (int index = 0; index < 6; ++index) {
        ethernet_header.destination[index] = data[index];
        ethernet_header.source[index] = data[index + 6];
    }
    ethernet_header.ether_type = ReadBigEndian16(data + 12);
    parsed_packet.ethernet = ethernet_header;

    std::ostringstream summary;
    summary << "Ethernet " << FormatMacAddress(ethernet_header.source)
            << " -> " << FormatMacAddress(ethernet_header.destination)
            << " type=0x" << std::hex << std::setw(4) << std::setfill('0')
            << ethernet_header.ether_type << std::dec;

    if (ethernet_header.ether_type != 0x0800) {
        parsed_packet.summary = summary.str() + " non-IPv4";
        return parsed_packet;
    }

    parsed_packet.is_ipv4 = true;

    if (length < kEthernetHeaderLength + kMinimumIPv4HeaderLength) {
        malformed = true;
        parsed_packet.summary = "Malformed packet: insufficient bytes for IPv4 header";
        return parsed_packet;
    }

    const std::uint8_t* ipv4_data = data + kEthernetHeaderLength;
    IPv4Header ipv4_header{};
    ipv4_header.version = static_cast<std::uint8_t>((ipv4_data[0] >> 4) & 0x0f);
    ipv4_header.ihl = static_cast<std::uint8_t>(ipv4_data[0] & 0x0f);
    ipv4_header.tos = ipv4_data[1];
    ipv4_header.total_length = ReadBigEndian16(ipv4_data + 2);
    ipv4_header.identification = ReadBigEndian16(ipv4_data + 4);
    ipv4_header.flags_fragment_offset = ReadBigEndian16(ipv4_data + 6);
    ipv4_header.ttl = ipv4_data[8];
    ipv4_header.protocol = ipv4_data[9];
    ipv4_header.header_checksum = ReadBigEndian16(ipv4_data + 10);
    ipv4_header.source_ip = ReadBigEndian32(ipv4_data + 12);
    ipv4_header.destination_ip = ReadBigEndian32(ipv4_data + 16);

    if (ipv4_header.version != 4) {
        malformed = true;
        parsed_packet.summary = "Malformed packet: invalid IPv4 version";
        return parsed_packet;
    }

    const std::size_t ipv4_header_length = static_cast<std::size_t>(ipv4_header.ihl) * 4;
    if (ipv4_header_length < kMinimumIPv4HeaderLength ||
        length < kEthernetHeaderLength + ipv4_header_length) {
        malformed = true;
        parsed_packet.summary = "Malformed packet: invalid IPv4 header length";
        return parsed_packet;
    }

    if (ipv4_header.total_length < ipv4_header_length) {
        malformed = true;
        parsed_packet.summary = "Malformed packet: IPv4 total length smaller than header length";
        return parsed_packet;
    }

    parsed_packet.ipv4 = ipv4_header;

    summary.str("");
    summary.clear();
    summary << "IPv4 " << FormatIPv4Address(ipv4_header.source_ip)
            << " -> " << FormatIPv4Address(ipv4_header.destination_ip)
            << " ttl=" << static_cast<unsigned int>(ipv4_header.ttl)
            << " len=" << ipv4_header.total_length;

    const std::size_t transport_offset = kEthernetHeaderLength + ipv4_header_length;
    parsed_packet.transport_offset = transport_offset;

    const std::size_t available_ipv4_bytes = length - kEthernetHeaderLength;
    const std::size_t ipv4_bytes_in_frame =
        (ipv4_header.total_length <= available_ipv4_bytes) ? ipv4_header.total_length : available_ipv4_bytes;
    const std::size_t ipv4_end_offset = kEthernetHeaderLength + ipv4_bytes_in_frame;

    if (ipv4_header.protocol == 6) {
        parsed_packet.is_tcp = true;
        if (length < transport_offset + kMinimumTcpHeaderLength) {
            malformed = true;
            parsed_packet.summary = "Malformed packet: insufficient bytes for TCP header";
            return parsed_packet;
        }

        const std::uint8_t* tcp_data = data + transport_offset;
        TcpHeader tcp_header{};
        tcp_header.source_port = ReadBigEndian16(tcp_data);
        tcp_header.destination_port = ReadBigEndian16(tcp_data + 2);
        tcp_header.sequence_number = ReadBigEndian32(tcp_data + 4);
        tcp_header.acknowledgment_number = ReadBigEndian32(tcp_data + 8);
        tcp_header.data_offset = static_cast<std::uint8_t>((tcp_data[12] >> 4) & 0x0f);
        tcp_header.flags = tcp_data[13];
        tcp_header.window_size = ReadBigEndian16(tcp_data + 14);
        tcp_header.checksum = ReadBigEndian16(tcp_data + 16);
        tcp_header.urgent_pointer = ReadBigEndian16(tcp_data + 18);

        const std::size_t tcp_header_length = static_cast<std::size_t>(tcp_header.data_offset) * 4;
        if (tcp_header_length < kMinimumTcpHeaderLength ||
            length < transport_offset + tcp_header_length) {
            malformed = true;
            parsed_packet.summary = "Malformed packet: invalid TCP header length";
            return parsed_packet;
        }

        if (transport_offset + tcp_header_length > ipv4_end_offset) {
            malformed = true;
            parsed_packet.summary = "Malformed packet: TCP header exceeds IPv4 payload length";
            return parsed_packet;
        }

        parsed_packet.tcp = tcp_header;
        parsed_packet.payload_offset = transport_offset + tcp_header_length;
        parsed_packet.payload_length = ipv4_end_offset - parsed_packet.payload_offset;
        summary << " TCP " << tcp_header.source_port << " -> " << tcp_header.destination_port
                << " flags=[" << FormatTcpFlags(tcp_header.flags) << "]";
        parsed_packet.summary = summary.str();
        return parsed_packet;
    }

    if (ipv4_header.protocol == 17) {
        parsed_packet.is_udp = true;
        if (length < transport_offset + kUdpHeaderLength) {
            malformed = true;
            parsed_packet.summary = "Malformed packet: insufficient bytes for UDP header";
            return parsed_packet;
        }

        const std::uint8_t* udp_data = data + transport_offset;
        UdpHeader udp_header{};
        udp_header.source_port = ReadBigEndian16(udp_data);
        udp_header.destination_port = ReadBigEndian16(udp_data + 2);
        udp_header.length = ReadBigEndian16(udp_data + 4);
        udp_header.checksum = ReadBigEndian16(udp_data + 6);

        if (udp_header.length < kUdpHeaderLength ||
            transport_offset + udp_header.length > ipv4_end_offset) {
            malformed = true;
            parsed_packet.summary = "Malformed packet: invalid UDP length";
            return parsed_packet;
        }

        parsed_packet.udp = udp_header;
        parsed_packet.payload_offset = transport_offset + kUdpHeaderLength;
        parsed_packet.payload_length = udp_header.length - kUdpHeaderLength;
        summary << " UDP " << udp_header.source_port << " -> " << udp_header.destination_port
                << " len=" << udp_header.length;
        parsed_packet.summary = summary.str();
        return parsed_packet;
    }

    summary << " proto=" << static_cast<unsigned int>(ipv4_header.protocol);
    parsed_packet.summary = summary.str();
    return parsed_packet;
}

}  // namespace DeepTrace
