#include "sni_extractor.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace DeepTrace {

namespace {

constexpr std::size_t kTlsRecordHeaderLength = 5;
constexpr std::size_t kTlsHandshakeHeaderLength = 4;
constexpr std::size_t kTlsClientHelloFixedLength = 34;
constexpr std::size_t kTlsExtensionHeaderLength = 4;
constexpr std::size_t kTlsServerNameListHeaderLength = 2;
constexpr std::size_t kTlsServerNameHeaderLength = 3;
constexpr std::uint8_t kTlsHandshakeTypeClientHello = 0x01;
constexpr std::uint16_t kTlsExtensionTypeServerName = 0x0000;

constexpr const char* kHttpMethods[] = {
    "GET ",
    "POST ",
    "HEAD ",
    "PUT ",
    "DELETE ",
    "OPTIONS ",
    "CONNECT ",
    "TRACE ",
    "PATCH "
};

std::uint16_t ReadBigEndian16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(data[0]) << 8) |
        static_cast<std::uint16_t>(data[1]));
}

std::uint32_t ReadBigEndian24(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 16) |
           (static_cast<std::uint32_t>(data[1]) << 8) |
           static_cast<std::uint32_t>(data[2]);
}

bool StartsWithHttpMethod(const std::uint8_t* payload, std::size_t payload_length) {
    for (const char* method : kHttpMethods) {
        const std::size_t method_length = std::strlen(method);
        if (payload_length >= method_length &&
            std::memcmp(payload, method, method_length) == 0) {
            return true;
        }
    }

    return false;
}

}  // namespace

AppMetadata SniExtractor::Inspect(const std::uint8_t* packet_data,
                                  std::size_t packet_length,
                                  const ParsedPacket& parsed_packet) const {
    AppMetadata metadata;

    if (!parsed_packet.is_tcp || parsed_packet.payload_length == 0 ||
        packet_data == nullptr || parsed_packet.payload_offset > packet_length ||
        parsed_packet.payload_offset + parsed_packet.payload_length > packet_length) {
        return metadata;
    }

    const std::uint8_t* payload = packet_data + parsed_packet.payload_offset;
    const std::size_t payload_length = parsed_packet.payload_length;

    metadata.is_tls_client_hello = ExtractTlsSni(payload, payload_length, metadata.sni);
    metadata.is_http_request = ExtractHttpHost(payload, payload_length, metadata.http_host);
    metadata.sni = NormalizeDomain(metadata.sni);
    metadata.http_host = NormalizeDomain(metadata.http_host);

    metadata.detected_domain = !metadata.sni.empty() ? metadata.sni : metadata.http_host;
    metadata.app_type = ClassifyDomain(metadata.detected_domain,
                                       metadata.is_tls_client_hello,
                                       metadata.is_http_request);
    return metadata;
}

std::string SniExtractor::AppTypeToString(AppType app_type) {
    switch (app_type) {
        case AppType::HTTP:
            return "HTTP";
        case AppType::HTTPS:
            return "HTTPS";
        case AppType::Facebook:
            return "Facebook";
        case AppType::Instagram:
            return "Instagram";
        case AppType::Google:
            return "Google";
        case AppType::X:
            return "X";
        case AppType::YouTube:
            return "YouTube";
        case AppType::GitHub:
            return "GitHub";
        case AppType::TikTok:
            return "TikTok";
        case AppType::Netflix:
            return "Netflix";
        case AppType::WhatsApp:
            return "WhatsApp";
        case AppType::OpenAI:
            return "OpenAI";
        case AppType::Unknown:
        default:
            return "Unknown";
    }
}

AppType SniExtractor::ClassifyDomain(const std::string& domain,
                                     bool is_tls_client_hello,
                                     bool is_http_request) {
    return MapDomainToApp(domain, is_tls_client_hello, is_http_request);
}

bool SniExtractor::ExtractTlsSni(const std::uint8_t* payload,
                                 std::size_t payload_length,
                                 std::string& sni) {
    sni.clear();

    if (payload == nullptr || payload_length < kTlsRecordHeaderLength) {
        return false;
    }

    if (payload[0] != 0x16) {
        return false;
    }

    const std::uint16_t record_length = ReadBigEndian16(payload + 3);
    if (record_length == 0 || kTlsRecordHeaderLength + record_length > payload_length) {
        return false;
    }

    const std::uint8_t* handshake = payload + kTlsRecordHeaderLength;
    const std::size_t handshake_length = record_length;

    if (handshake_length < kTlsHandshakeHeaderLength ||
        handshake[0] != kTlsHandshakeTypeClientHello) {
        return false;
    }

    const std::uint32_t client_hello_length = ReadBigEndian24(handshake + 1);
    if (client_hello_length + kTlsHandshakeHeaderLength > handshake_length) {
        return false;
    }

    std::size_t offset = kTlsHandshakeHeaderLength;
    if (offset + kTlsClientHelloFixedLength > handshake_length) {
        return false;
    }

    offset += 2;
    offset += 32;

    const std::uint8_t session_id_length = handshake[offset];
    ++offset;
    if (offset + session_id_length > handshake_length) {
        return false;
    }
    offset += session_id_length;

    if (offset + 2 > handshake_length) {
        return false;
    }
    const std::uint16_t cipher_suites_length = ReadBigEndian16(handshake + offset);
    offset += 2;
    if (offset + cipher_suites_length > handshake_length) {
        return false;
    }
    offset += cipher_suites_length;

    if (offset + 1 > handshake_length) {
        return false;
    }
    const std::uint8_t compression_methods_length = handshake[offset];
    ++offset;
    if (offset + compression_methods_length > handshake_length) {
        return false;
    }
    offset += compression_methods_length;

    if (offset + 2 > handshake_length) {
        return false;
    }
    const std::uint16_t extensions_length = ReadBigEndian16(handshake + offset);
    offset += 2;
    if (offset + extensions_length > handshake_length) {
        return false;
    }

    const std::size_t extensions_end = offset + extensions_length;
    while (offset + kTlsExtensionHeaderLength <= extensions_end) {
        const std::uint16_t extension_type = ReadBigEndian16(handshake + offset);
        const std::uint16_t extension_length = ReadBigEndian16(handshake + offset + 2);
        offset += kTlsExtensionHeaderLength;

        if (offset + extension_length > extensions_end) {
            return false;
        }

        if (extension_type == kTlsExtensionTypeServerName) {
            if (extension_length < kTlsServerNameListHeaderLength) {
                return false;
            }

            std::size_t name_offset = offset;
            const std::uint16_t server_name_list_length = ReadBigEndian16(handshake + name_offset);
            name_offset += kTlsServerNameListHeaderLength;

            if (name_offset + server_name_list_length > offset + extension_length) {
                return false;
            }

            const std::size_t name_list_end = name_offset + server_name_list_length;
            while (name_offset + kTlsServerNameHeaderLength <= name_list_end) {
                const std::uint8_t name_type = handshake[name_offset];
                const std::uint16_t name_length = ReadBigEndian16(handshake + name_offset + 1);
                name_offset += kTlsServerNameHeaderLength;

                if (name_offset + name_length > name_list_end) {
                    return false;
                }

                if (name_type == 0 && name_length > 0) {
                    sni.assign(reinterpret_cast<const char*>(handshake + name_offset), name_length);
                    return true;
                }

                name_offset += name_length;
            }

            return true;
        }

        offset += extension_length;
    }

    return true;
}

bool SniExtractor::ExtractHttpHost(const std::uint8_t* payload,
                                   std::size_t payload_length,
                                   std::string& host) {
    host.clear();

    if (payload == nullptr || payload_length < 8 || !StartsWithHttpMethod(payload, payload_length)) {
        return false;
    }

    const std::string request(reinterpret_cast<const char*>(payload), payload_length);
    const std::size_t header_end = request.find("\r\n\r\n");
    const std::size_t alt_header_end = request.find("\n\n");

    std::size_t end = std::string::npos;
    if (header_end != std::string::npos) {
        end = header_end;
    } else if (alt_header_end != std::string::npos) {
        end = alt_header_end;
    } else {
        end = request.size();
    }

    std::size_t line_start = request.find('\n');
    while (line_start != std::string::npos && line_start < end) {
        ++line_start;
        std::size_t line_end = request.find('\n', line_start);
        if (line_end == std::string::npos || line_end > end) {
            line_end = end;
        }

        std::string line = request.substr(line_start, line_end - line_start);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.size() >= 5 &&
            (line[0] == 'H' || line[0] == 'h') &&
            (line[1] == 'O' || line[1] == 'o') &&
            (line[2] == 'S' || line[2] == 's') &&
            (line[3] == 'T' || line[3] == 't') &&
            line[4] == ':') {
            const std::string raw_host = TrimCopy(line.substr(5));
            host = NormalizeDomain(raw_host);
            return !host.empty();
        }

        if (line_end == end) {
            break;
        }
        line_start = line_end;
    }

    return true;
}

std::string SniExtractor::NormalizeDomain(const std::string& value) {
    std::string normalized = TrimCopy(value);
    if (normalized.empty()) {
        return "";
    }

    if (normalized.front() == '[') {
        const std::size_t closing_bracket = normalized.find(']');
        if (closing_bracket != std::string::npos) {
            normalized = normalized.substr(0, closing_bracket + 1);
        }
    } else {
        const std::size_t colon = normalized.find(':');
        if (colon != std::string::npos) {
            normalized = normalized.substr(0, colon);
        }
    }

    while (!normalized.empty() && normalized.back() == '.') {
        normalized.pop_back();
    }

    return ToLowerCopy(TrimCopy(normalized));
}

AppType SniExtractor::MapDomainToApp(const std::string& domain,
                                     bool is_tls_client_hello,
                                     bool is_http_request) {
    const std::string lowered = NormalizeDomain(domain);

    if (!lowered.empty()) {
        if (lowered == "facebook.com" || EndsWith(lowered, ".facebook.com") ||
            lowered == "fb.com" || EndsWith(lowered, ".fb.com") ||
            lowered == "fbcdn.net" || EndsWith(lowered, ".fbcdn.net") ||
            lowered == "facebook.net" || EndsWith(lowered, ".facebook.net")) {
            return AppType::Facebook;
        }

        if (lowered == "instagram.com" || EndsWith(lowered, ".instagram.com") ||
            lowered == "cdninstagram.com" || EndsWith(lowered, ".cdninstagram.com")) {
            return AppType::Instagram;
        }

        if (lowered == "youtube.com" || EndsWith(lowered, ".youtube.com") ||
            lowered == "youtu.be" || EndsWith(lowered, ".googlevideo.com")) {
            return AppType::YouTube;
        }

        if (lowered == "google.com" || EndsWith(lowered, ".google.com") ||
            lowered == "googleapis.com" || EndsWith(lowered, ".googleapis.com") ||
            lowered == "gstatic.com" || EndsWith(lowered, ".gstatic.com")) {
            return AppType::Google;
        }

        if (lowered == "twitter.com" || EndsWith(lowered, ".twitter.com") ||
            lowered == "x.com" || EndsWith(lowered, ".x.com") ||
            lowered == "twimg.com" || EndsWith(lowered, ".twimg.com")) {
            return AppType::X;
        }

        if (lowered == "github.com" || EndsWith(lowered, ".github.com") ||
            lowered == "githubusercontent.com" || EndsWith(lowered, ".githubusercontent.com")) {
            return AppType::GitHub;
        }

        if (lowered == "tiktok.com" || EndsWith(lowered, ".tiktok.com") ||
            lowered == "tiktokcdn.com" || EndsWith(lowered, ".tiktokcdn.com") ||
            lowered == "byteoversea.com" || EndsWith(lowered, ".byteoversea.com")) {
            return AppType::TikTok;
        }

        if (lowered == "netflix.com" || EndsWith(lowered, ".netflix.com") ||
            lowered == "nflxvideo.net" || EndsWith(lowered, ".nflxvideo.net") ||
            lowered == "nflximg.net" || EndsWith(lowered, ".nflximg.net")) {
            return AppType::Netflix;
        }

        if (lowered == "whatsapp.com" || EndsWith(lowered, ".whatsapp.com") ||
            lowered == "whatsapp.net" || EndsWith(lowered, ".whatsapp.net")) {
            return AppType::WhatsApp;
        }

        if (lowered == "openai.com" || EndsWith(lowered, ".openai.com") ||
            lowered == "chatgpt.com" || EndsWith(lowered, ".chatgpt.com")) {
            return AppType::OpenAI;
        }
    }

    if (is_tls_client_hello) {
        return AppType::HTTPS;
    }

    if (is_http_request) {
        return AppType::HTTP;
    }

    return AppType::Unknown;
}

std::string SniExtractor::ToLowerCopy(const std::string& value) {
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char character) {
                       return static_cast<char>(std::tolower(character));
                   });
    return lowered;
}

std::string SniExtractor::TrimCopy(const std::string& value) {
    std::size_t start = 0;
    while (start < value.size() &&
           std::isspace(static_cast<unsigned char>(value[start])) != 0) {
        ++start;
    }

    std::size_t end = value.size();
    while (end > start &&
           std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }

    return value.substr(start, end - start);
}

bool SniExtractor::EndsWith(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

}  // namespace DeepTrace
