#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "types.h"

namespace DeepTrace {

class SniExtractor {
public:
    AppMetadata Inspect(const std::uint8_t* packet_data,
                        std::size_t packet_length,
                        const ParsedPacket& parsed_packet) const;

    static std::string AppTypeToString(AppType app_type);
    static std::string NormalizeDomain(const std::string& value);
    static AppType ClassifyDomain(const std::string& domain,
                                  bool is_tls_client_hello = false,
                                  bool is_http_request = false);

private:
    static bool ExtractTlsSni(const std::uint8_t* payload,
                              std::size_t payload_length,
                              std::string& sni);
    static bool ExtractHttpHost(const std::uint8_t* payload,
                                std::size_t payload_length,
                                std::string& host);
    static AppType MapDomainToApp(const std::string& domain,
                                  bool is_tls_client_hello,
                                  bool is_http_request);
    static std::string ToLowerCopy(const std::string& value);
    static std::string TrimCopy(const std::string& value);
    static bool EndsWith(const std::string& value, const std::string& suffix);
};

}  // namespace DeepTrace
