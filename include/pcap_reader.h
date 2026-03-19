#pragma once

#include <fstream>
#include <string>

#include "types.h"

namespace DeepTrace {

class PcapReader {
public:
    PcapReader() = default;

    bool Open(const std::string& file_path, std::string& error_message);
    bool ReadNextPacket(RawPacket& packet, std::string& error_message);
    bool IsOpen() const;

    const PcapGlobalHeader& GetGlobalHeader() const;

private:
    std::ifstream input_;
    PcapGlobalHeader global_header_{};
    bool is_open_ = false;
};

}  // namespace DeepTrace
