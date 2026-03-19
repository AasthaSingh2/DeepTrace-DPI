#include "pcap_reader.h"

#include <limits>

namespace DeepTrace {

namespace {

constexpr std::uint32_t kPcapMagicNative = 0xa1b2c3d4;
constexpr std::uint32_t kPcapMagicSwapped = 0xd4c3b2a1;
constexpr std::size_t kGlobalHeaderSize = 24;
constexpr std::size_t kPacketHeaderSize = 16;

std::uint16_t ReadLittleEndian16(const char* data) {
    return static_cast<std::uint16_t>(
        static_cast<std::uint8_t>(data[0]) |
        (static_cast<std::uint16_t>(static_cast<std::uint8_t>(data[1])) << 8));
}

std::uint32_t ReadLittleEndian32(const char* data) {
    return static_cast<std::uint32_t>(
        static_cast<std::uint8_t>(data[0]) |
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(data[1])) << 8) |
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(data[2])) << 16) |
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(data[3])) << 24));
}

}  // namespace

bool PcapReader::Open(const std::string& file_path, std::string& error_message) {
    input_.close();
    input_.clear();
    is_open_ = false;
    global_header_ = {};

    input_.open(file_path, std::ios::binary);
    if (!input_.is_open()) {
        error_message = "Failed to open PCAP file: " + file_path;
        return false;
    }

    char buffer[kGlobalHeaderSize]{};
    input_.read(buffer, static_cast<std::streamsize>(kGlobalHeaderSize));
    if (input_.gcount() != static_cast<std::streamsize>(kGlobalHeaderSize)) {
        error_message = "PCAP file is too small to contain a valid global header.";
        return false;
    }

    global_header_.magic_number = ReadLittleEndian32(buffer);
    if (global_header_.magic_number != kPcapMagicNative &&
        global_header_.magic_number != kPcapMagicSwapped) {
        error_message = "Unsupported PCAP magic number. Only classic little-endian PCAP is supported.";
        return false;
    }

    if (global_header_.magic_number == kPcapMagicSwapped) {
        error_message = "Big-endian PCAP files are not supported in Version 1.";
        return false;
    }

    global_header_.version_major = ReadLittleEndian16(buffer + 4);
    global_header_.version_minor = ReadLittleEndian16(buffer + 6);
    global_header_.thiszone = static_cast<std::int32_t>(ReadLittleEndian32(buffer + 8));
    global_header_.sigfigs = ReadLittleEndian32(buffer + 12);
    global_header_.snaplen = ReadLittleEndian32(buffer + 16);
    global_header_.network = ReadLittleEndian32(buffer + 20);

    if (global_header_.version_major == 0 || global_header_.snaplen == 0) {
        error_message = "PCAP global header is invalid.";
        return false;
    }

    if (global_header_.network != static_cast<std::uint32_t>(LinkType::Ethernet)) {
        error_message = "Unsupported link type. Version 1 expects Ethernet PCAP files.";
        return false;
    }

    is_open_ = true;
    error_message.clear();
    return true;
}

bool PcapReader::ReadNextPacket(RawPacket& packet, std::string& error_message) {
    if (!is_open_) {
        error_message = "PCAP reader is not open.";
        return false;
    }

    char header_buffer[kPacketHeaderSize]{};
    input_.read(header_buffer, static_cast<std::streamsize>(kPacketHeaderSize));

    if (input_.gcount() == 0 && input_.eof()) {
        error_message.clear();
        return false;
    }

    if (input_.gcount() != static_cast<std::streamsize>(kPacketHeaderSize)) {
        error_message = "Encountered truncated PCAP packet header.";
        return false;
    }

    packet.header.ts_sec = ReadLittleEndian32(header_buffer);
    packet.header.ts_usec = ReadLittleEndian32(header_buffer + 4);
    packet.header.incl_len = ReadLittleEndian32(header_buffer + 8);
    packet.header.orig_len = ReadLittleEndian32(header_buffer + 12);

    if (packet.header.incl_len > global_header_.snaplen) {
        error_message = "Packet captured length exceeds PCAP snaplen.";
        return false;
    }

    if (packet.header.incl_len >
        static_cast<std::uint32_t>(std::numeric_limits<std::streamsize>::max())) {
        error_message = "Packet captured length is too large.";
        return false;
    }

    packet.data.resize(packet.header.incl_len);
    input_.read(reinterpret_cast<char*>(packet.data.data()),
                static_cast<std::streamsize>(packet.header.incl_len));

    if (input_.gcount() != static_cast<std::streamsize>(packet.header.incl_len)) {
        error_message = "Encountered truncated PCAP packet payload.";
        return false;
    }

    error_message.clear();
    return true;
}

bool PcapReader::IsOpen() const {
    return is_open_;
}

const PcapGlobalHeader& PcapReader::GetGlobalHeader() const {
    return global_header_;
}

}  // namespace DeepTrace
