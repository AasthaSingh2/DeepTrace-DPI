#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "types.h"

namespace DeepTrace {

class PacketParser {
public:
    ParsedPacket Parse(const std::uint8_t* data, std::size_t length, bool& malformed) const;

    static std::string FormatMacAddress(const std::uint8_t mac[6]);
    static std::string FormatIPv4Address(std::uint32_t address);
    static std::string FormatTcpFlags(std::uint8_t flags);

private:
    static constexpr std::size_t kEthernetHeaderLength = 14;
    static constexpr std::size_t kMinimumIPv4HeaderLength = 20;
    static constexpr std::size_t kMinimumTcpHeaderLength = 20;
    static constexpr std::size_t kUdpHeaderLength = 8;

    static std::uint16_t ReadBigEndian16(const std::uint8_t* data);
    static std::uint32_t ReadBigEndian32(const std::uint8_t* data);
};

}  // namespace DeepTrace
