#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace DeepTrace {

enum class LinkType : std::uint32_t {
    Ethernet = 1
};

struct PcapGlobalHeader {
    std::uint32_t magic_number = 0;
    std::uint16_t version_major = 0;
    std::uint16_t version_minor = 0;
    std::int32_t thiszone = 0;
    std::uint32_t sigfigs = 0;
    std::uint32_t snaplen = 0;
    std::uint32_t network = 0;
};

struct PcapPacketHeader {
    std::uint32_t ts_sec = 0;
    std::uint32_t ts_usec = 0;
    std::uint32_t incl_len = 0;
    std::uint32_t orig_len = 0;
};

struct RawPacket {
    PcapPacketHeader header;
    std::vector<std::uint8_t> data;
};

struct EthernetHeader {
    std::uint8_t destination[6]{};
    std::uint8_t source[6]{};
    std::uint16_t ether_type = 0;
};

struct IPv4Header {
    std::uint8_t version = 0;
    std::uint8_t ihl = 0;
    std::uint8_t tos = 0;
    std::uint16_t total_length = 0;
    std::uint16_t identification = 0;
    std::uint16_t flags_fragment_offset = 0;
    std::uint8_t ttl = 0;
    std::uint8_t protocol = 0;
    std::uint16_t header_checksum = 0;
    std::uint32_t source_ip = 0;
    std::uint32_t destination_ip = 0;
};

struct TcpHeader {
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    std::uint32_t sequence_number = 0;
    std::uint32_t acknowledgment_number = 0;
    std::uint8_t data_offset = 0;
    std::uint8_t flags = 0;
    std::uint16_t window_size = 0;
    std::uint16_t checksum = 0;
    std::uint16_t urgent_pointer = 0;
};

struct UdpHeader {
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    std::uint16_t length = 0;
    std::uint16_t checksum = 0;
};

enum class AppType {
    Unknown,
    HTTP,
    HTTPS,
    Facebook,
    Instagram,
    Google,
    X,
    YouTube,
    GitHub,
    TikTok,
    Netflix,
    WhatsApp,
    OpenAI
};

struct AppMetadata {
    bool is_tls_client_hello = false;
    bool is_http_request = false;
    bool is_dns_query = false;
    std::string sni;
    std::string http_host;
    std::string dns_query;
    std::string detected_domain;
    AppType app_type = AppType::Unknown;
};

struct FiveTuple {
    std::uint32_t endpoint_a_ip = 0;
    std::uint32_t endpoint_b_ip = 0;
    std::uint16_t endpoint_a_port = 0;
    std::uint16_t endpoint_b_port = 0;
    std::uint8_t protocol = 0;

    bool operator==(const FiveTuple& other) const {
        return endpoint_a_ip == other.endpoint_a_ip &&
               endpoint_b_ip == other.endpoint_b_ip &&
               endpoint_a_port == other.endpoint_a_port &&
               endpoint_b_port == other.endpoint_b_port &&
               protocol == other.protocol;
    }
};

struct FiveTupleHash {
    std::size_t operator()(const FiveTuple& tuple) const noexcept {
        std::size_t hash = static_cast<std::size_t>(tuple.endpoint_a_ip);
        hash ^= static_cast<std::size_t>(tuple.endpoint_b_ip) + 0x9e3779b9u + (hash << 6) + (hash >> 2);
        hash ^= static_cast<std::size_t>(tuple.endpoint_a_port) + 0x9e3779b9u + (hash << 6) + (hash >> 2);
        hash ^= static_cast<std::size_t>(tuple.endpoint_b_port) + 0x9e3779b9u + (hash << 6) + (hash >> 2);
        hash ^= static_cast<std::size_t>(tuple.protocol) + 0x9e3779b9u + (hash << 6) + (hash >> 2);
        return hash;
    }
};

struct Flow {
    FiveTuple key;
    std::size_t packets_seen = 0;
    std::size_t bytes_seen = 0;
    bool classified = false;
    bool blocked = false;
    bool is_tls_client_hello = false;
    bool is_http_request = false;
    bool is_dns_query = false;
    std::string sni;
    std::string http_host;
    std::string dns_query;
    std::string detected_domain;
    std::string block_reason;
    AppType app_type = AppType::Unknown;
};

struct ParsedPacket {
    bool is_ipv4 = false;
    bool is_tcp = false;
    bool is_udp = false;
    std::size_t transport_offset = 0;
    std::size_t payload_offset = 0;
    std::size_t payload_length = 0;
    std::string summary;
    std::optional<EthernetHeader> ethernet;
    std::optional<IPv4Header> ipv4;
    std::optional<TcpHeader> tcp;
    std::optional<UdpHeader> udp;
};

struct RunStats {
    std::size_t packets_seen = 0;
    std::size_t bytes_processed = 0;
    std::size_t packets_parsed = 0;
    std::size_t malformed_packets = 0;
    std::size_t non_ipv4_packets = 0;
    std::size_t tcp_packets = 0;
    std::size_t udp_packets = 0;
    std::size_t other_ipv4_packets = 0;
    std::size_t flows_seen = 0;
    std::size_t classified_flows = 0;
    double processing_time_seconds = 0.0;
};

}  // namespace DeepTrace
