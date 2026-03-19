#pragma once

#include <cstddef>
#include <cstdint>

#include "types.h"

namespace DeepTrace {

class DnsParser {
public:
    AppMetadata Inspect(const std::uint8_t* packet_data,
                        std::size_t packet_length,
                        const ParsedPacket& parsed_packet) const;

private:
    static bool ExtractQueryName(const std::uint8_t* payload,
                                 std::size_t payload_length,
                                 std::string& query_name);
    static std::uint16_t ReadBigEndian16(const std::uint8_t* data);
};

}  // namespace DeepTrace
