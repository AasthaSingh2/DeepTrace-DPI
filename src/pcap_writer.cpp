#include "pcap_writer.h"

namespace DeepTrace {

namespace {

void WriteLittleEndian16(char* buffer, std::uint16_t value) {
    buffer[0] = static_cast<char>(value & 0xff);
    buffer[1] = static_cast<char>((value >> 8) & 0xff);
}

void WriteLittleEndian32(char* buffer, std::uint32_t value) {
    buffer[0] = static_cast<char>(value & 0xff);
    buffer[1] = static_cast<char>((value >> 8) & 0xff);
    buffer[2] = static_cast<char>((value >> 16) & 0xff);
    buffer[3] = static_cast<char>((value >> 24) & 0xff);
}

}  // namespace

bool PcapWriter::Open(const std::string& file_path,
                      const PcapGlobalHeader& global_header,
                      std::string& error_message) {
    output_.close();
    output_.clear();
    is_open_ = false;

    output_.open(file_path, std::ios::binary | std::ios::trunc);
    if (!output_.is_open()) {
        error_message = "Failed to open filtered PCAP for writing: " + file_path;
        return false;
    }

    char buffer[24]{};
    WriteLittleEndian32(buffer, global_header.magic_number);
    WriteLittleEndian16(buffer + 4, global_header.version_major);
    WriteLittleEndian16(buffer + 6, global_header.version_minor);
    WriteLittleEndian32(buffer + 8, static_cast<std::uint32_t>(global_header.thiszone));
    WriteLittleEndian32(buffer + 12, global_header.sigfigs);
    WriteLittleEndian32(buffer + 16, global_header.snaplen);
    WriteLittleEndian32(buffer + 20, global_header.network);

    output_.write(buffer, sizeof(buffer));
    if (!output_.good()) {
        error_message = "Failed while writing PCAP global header: " + file_path;
        return false;
    }

    is_open_ = true;
    error_message.clear();
    return true;
}

bool PcapWriter::WritePacket(const RawPacket& packet, std::string& error_message) {
    if (!is_open_) {
        error_message = "PCAP writer is not open.";
        return false;
    }

    char header_buffer[16]{};
    WriteLittleEndian32(header_buffer, packet.header.ts_sec);
    WriteLittleEndian32(header_buffer + 4, packet.header.ts_usec);
    WriteLittleEndian32(header_buffer + 8, packet.header.incl_len);
    WriteLittleEndian32(header_buffer + 12, packet.header.orig_len);

    output_.write(header_buffer, sizeof(header_buffer));
    if (!packet.data.empty()) {
        output_.write(reinterpret_cast<const char*>(packet.data.data()),
                      static_cast<std::streamsize>(packet.data.size()));
    }

    if (!output_.good()) {
        error_message = "Failed while writing filtered PCAP packet.";
        return false;
    }

    error_message.clear();
    return true;
}

bool PcapWriter::IsOpen() const {
    return is_open_;
}

}  // namespace DeepTrace
