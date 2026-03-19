#include "dns_parser.h"

#include <string>

#include "sni_extractor.h"

namespace DeepTrace {

namespace {

constexpr std::size_t kDnsHeaderLength = 12;
constexpr std::uint16_t kDnsResponseFlag = 0x8000;
constexpr std::uint16_t kDnsQuestionClassInternet = 1;

}  // namespace

AppMetadata DnsParser::Inspect(const std::uint8_t* packet_data,
                               std::size_t packet_length,
                               const ParsedPacket& parsed_packet) const {
    AppMetadata metadata;

    if (!parsed_packet.is_udp || !parsed_packet.udp.has_value() ||
        parsed_packet.payload_length == 0 || packet_data == nullptr ||
        parsed_packet.payload_offset > packet_length ||
        parsed_packet.payload_offset + parsed_packet.payload_length > packet_length) {
        return metadata;
    }

    const std::uint16_t source_port = parsed_packet.udp->source_port;
    const std::uint16_t destination_port = parsed_packet.udp->destination_port;
    if (source_port != 53 && destination_port != 53) {
        return metadata;
    }

    const std::uint8_t* payload = packet_data + parsed_packet.payload_offset;
    const std::size_t payload_length = parsed_packet.payload_length;

    if (!ExtractQueryName(payload, payload_length, metadata.dns_query)) {
        return metadata;
    }

    metadata.is_dns_query = true;
    metadata.dns_query = SniExtractor::NormalizeDomain(metadata.dns_query);
    metadata.detected_domain = metadata.dns_query;
    metadata.app_type = SniExtractor::ClassifyDomain(metadata.detected_domain);
    return metadata;
}

bool DnsParser::ExtractQueryName(const std::uint8_t* payload,
                                 std::size_t payload_length,
                                 std::string& query_name) {
    query_name.clear();

    if (payload == nullptr || payload_length < kDnsHeaderLength) {
        return false;
    }

    const std::uint16_t flags = ReadBigEndian16(payload + 2);
    const std::uint16_t question_count = ReadBigEndian16(payload + 4);
    if ((flags & kDnsResponseFlag) != 0 || question_count == 0) {
        return false;
    }

    std::size_t offset = kDnsHeaderLength;
    std::string name;

    while (offset < payload_length) {
        const std::uint8_t label_length = payload[offset];
        ++offset;

        if (label_length == 0) {
            break;
        }

        // DNS compression pointers are not valid in question names here, so reject them safely.
        if ((label_length & 0xc0) != 0) {
            return false;
        }

        if (label_length > 63 || offset + label_length > payload_length) {
            return false;
        }

        if (!name.empty()) {
            name += '.';
        }

        name.append(reinterpret_cast<const char*>(payload + offset), label_length);
        offset += label_length;
    }

    if (offset + 4 > payload_length || name.empty()) {
        return false;
    }

    const std::uint16_t query_type = ReadBigEndian16(payload + offset);
    const std::uint16_t query_class = ReadBigEndian16(payload + offset + 2);
    if (query_class != kDnsQuestionClassInternet || query_type == 0) {
        return false;
    }

    query_name = name;
    return true;
}

std::uint16_t DnsParser::ReadBigEndian16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[0]) << 8) |
        static_cast<std::uint16_t>(data[1]));
}

}  // namespace DeepTrace
