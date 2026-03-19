#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "types.h"

namespace DeepTrace {

struct BlockingRules {
    std::vector<AppType> blocked_apps;
    std::vector<std::string> blocked_domain_substrings;
    std::vector<std::uint32_t> blocked_ips;

    bool Empty() const;
};

class BlockingEngine {
public:
    static bool ApplyRules(const BlockingRules& rules, Flow& flow);
    static bool ParseAppRule(const std::string& value, AppType& app_type);
    static bool ParseIpRule(const std::string& value, std::uint32_t& ip_address);

private:
    static std::string NormalizeText(const std::string& value);
    static std::string BuildBlockReason(const BlockingRules& rules, const Flow& flow);
};

}  // namespace DeepTrace
