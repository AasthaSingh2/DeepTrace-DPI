#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"

namespace {

using DeepTrace::AppMetadata;
using DeepTrace::AppType;
using DeepTrace::PacketParser;
using DeepTrace::ParsedPacket;
using DeepTrace::SniExtractor;

std::vector<std::uint8_t> BuildEthernetIpv4TcpPacket(const std::vector<std::uint8_t>& payload,
                                                     std::uint16_t source_port,
                                                     std::uint16_t destination_port) {
    const std::size_t ethernet_header_length = 14;
    const std::size_t ipv4_header_length = 20;
    const std::size_t tcp_header_length = 20;
    const std::size_t packet_length =
        ethernet_header_length + ipv4_header_length + tcp_header_length + payload.size();

    std::vector<std::uint8_t> packet(packet_length, 0);

    packet[0] = 0x00; packet[1] = 0x11; packet[2] = 0x22;
    packet[3] = 0x33; packet[4] = 0x44; packet[5] = 0x55;
    packet[6] = 0x66; packet[7] = 0x77; packet[8] = 0x88;
    packet[9] = 0x99; packet[10] = 0xaa; packet[11] = 0xbb;
    packet[12] = 0x08; packet[13] = 0x00;

    const std::size_t ipv4_offset = ethernet_header_length;
    packet[ipv4_offset + 0] = 0x45;
    packet[ipv4_offset + 2] = static_cast<std::uint8_t>((ipv4_header_length + tcp_header_length + payload.size()) >> 8);
    packet[ipv4_offset + 3] = static_cast<std::uint8_t>((ipv4_header_length + tcp_header_length + payload.size()) & 0xff);
    packet[ipv4_offset + 8] = 64;
    packet[ipv4_offset + 9] = 6;
    packet[ipv4_offset + 12] = 192;
    packet[ipv4_offset + 13] = 168;
    packet[ipv4_offset + 14] = 1;
    packet[ipv4_offset + 15] = 100;
    packet[ipv4_offset + 16] = 142;
    packet[ipv4_offset + 17] = 250;
    packet[ipv4_offset + 18] = 185;
    packet[ipv4_offset + 19] = 206;

    const std::size_t tcp_offset = ethernet_header_length + ipv4_header_length;
    packet[tcp_offset + 0] = static_cast<std::uint8_t>(source_port >> 8);
    packet[tcp_offset + 1] = static_cast<std::uint8_t>(source_port & 0xff);
    packet[tcp_offset + 2] = static_cast<std::uint8_t>(destination_port >> 8);
    packet[tcp_offset + 3] = static_cast<std::uint8_t>(destination_port & 0xff);
    packet[tcp_offset + 12] = 0x50;
    packet[tcp_offset + 13] = 0x18;

    const std::size_t payload_offset = tcp_offset + tcp_header_length;
    for (std::size_t index = 0; index < payload.size(); ++index) {
        packet[payload_offset + index] = payload[index];
    }

    return packet;
}

void Expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string FindSamplePcapPath() {
    const std::filesystem::path candidates[] = {
        std::filesystem::path("data") / "test_dpi.pcap",
        std::filesystem::path("..") / "data" / "test_dpi.pcap",
        std::filesystem::path("..") / ".." / "data" / "test_dpi.pcap",
    };

    for (const auto& candidate : candidates) {
        if (std::filesystem::exists(candidate)) {
            return candidate.string();
        }
    }

    throw std::runtime_error("sni test: could not locate data/test_dpi.pcap");
}

void ParserSmokeTest() {
    PacketParser parser;
    bool malformed = false;
    const std::vector<std::uint8_t> payload = {
        'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n',
        'H', 'o', 's', 't', ':', ' ', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', '\r', '\n', '\r', '\n'
    };
    const std::vector<std::uint8_t> packet = BuildEthernetIpv4TcpPacket(payload, 54321, 80);

    const ParsedPacket parsed = parser.Parse(packet.data(), packet.size(), malformed);

    Expect(!malformed, "parser smoke test: packet should parse");
    Expect(parsed.is_ipv4, "parser smoke test: expected IPv4");
    Expect(parsed.is_tcp, "parser smoke test: expected TCP");
    Expect(parsed.payload_length == payload.size(), "parser smoke test: unexpected payload length");
    Expect(parsed.summary.find("IPv4 192.168.1.100 -> 142.250.185.206") != std::string::npos,
           "parser smoke test: summary missing IPv4 addresses");
}

void DomainClassificationTest() {
    Expect(SniExtractor::ClassifyDomain("www.google.com") == AppType::Google,
           "classification test: google should map to Google");
    Expect(SniExtractor::ClassifyDomain("api.twitter.com") == AppType::X,
           "classification test: twitter should map to X");
    Expect(SniExtractor::ClassifyDomain("github.com") == AppType::GitHub,
           "classification test: github should map to GitHub");
    Expect(SniExtractor::ClassifyDomain("", true, false) == AppType::HTTPS,
           "classification test: tls fallback should map to HTTPS");
}

void SniExtractionTest() {
    DeepTrace::PcapReader reader;
    PacketParser parser;
    SniExtractor extractor;
    std::string error_message;
    const std::string sample_pcap = FindSamplePcapPath();
    Expect(reader.Open(sample_pcap, error_message), "sni test: failed to open sample PCAP");

    DeepTrace::RawPacket packet;
    while (reader.ReadNextPacket(packet, error_message)) {
        bool malformed = false;
        const ParsedPacket parsed = parser.Parse(packet.data.data(), packet.data.size(), malformed);
        if (malformed) {
            continue;
        }

        const AppMetadata metadata = extractor.Inspect(packet.data.data(), packet.data.size(), parsed);
        if (metadata.sni == "www.youtube.com") {
            Expect(metadata.app_type == AppType::YouTube, "sni test: expected YouTube classification");
            return;
        }
    }

    Expect(error_message.empty(), "sni test: failed while reading sample PCAP");
    throw std::runtime_error("sni test: did not find expected youtube SNI");
}

}  // namespace

int main() {
    try {
        ParserSmokeTest();
        DomainClassificationTest();
        SniExtractionTest();
        std::cout << "All tests passed.\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "Test failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
