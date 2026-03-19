#pragma once

#include <fstream>
#include <string>

#include "types.h"

namespace DeepTrace {

class PcapWriter {
public:
    PcapWriter() = default;

    bool Open(const std::string& file_path,
              const PcapGlobalHeader& global_header,
              std::string& error_message);
    bool WritePacket(const RawPacket& packet, std::string& error_message);
    bool IsOpen() const;

private:
    std::ofstream output_;
    bool is_open_ = false;
};

}  // namespace DeepTrace
