#include "blocking_engine.h"

#include <algorithm>
#include <cctype>
#include <sstream>

#include "packet_parser.h"
#include "sni_extractor.h"

namespace DeepTrace {

namespace {

bool ContainsText(const std::string& text, const std::string& needle) {
    return !needle.empty() && text.find(needle) != std::string::npos;
}

}  // namespace

bool BlockingRules::Empty() const {
    return blocked_apps.empty() &&
           blocked_domain_substrings.empty() &&
           blocked_ips.empty();
}

bool BlockingEngine::ApplyRules(const BlockingRules& rules, Flow& flow) {
    const bool was_blocked = flow.blocked;
    const std::string previous_reason = flow.block_reason;

    flow.block_reason = BuildBlockReason(rules, flow);
    flow.blocked = !flow.block_reason.empty();

    return flow.blocked != was_blocked || flow.block_reason != previous_reason;
}

bool BlockingEngine::ParseAppRule(const std::string& value, AppType& app_type) {
    const std::string normalized = NormalizeText(value);

    if (normalized == "unknown") {
        app_type = AppType::Unknown;
        return true;
    }
    if (normalized == "http") {
        app_type = AppType::HTTP;
        return true;
    }
    if (normalized == "https") {
        app_type = AppType::HTTPS;
        return true;
    }
    if (normalized == "facebook") {
        app_type = AppType::Facebook;
        return true;
    }
    if (normalized == "instagram") {
        app_type = AppType::Instagram;
        return true;
    }
    if (normalized == "google") {
        app_type = AppType::Google;
        return true;
    }
    if (normalized == "x" || normalized == "twitter") {
        app_type = AppType::X;
        return true;
    }
    if (normalized == "youtube") {
        app_type = AppType::YouTube;
        return true;
    }
    if (normalized == "github") {
        app_type = AppType::GitHub;
        return true;
    }
    if (normalized == "tiktok") {
        app_type = AppType::TikTok;
        return true;
    }
    if (normalized == "netflix") {
        app_type = AppType::Netflix;
        return true;
    }
    if (normalized == "whatsapp") {
        app_type = AppType::WhatsApp;
        return true;
    }
    if (normalized == "openai") {
        app_type = AppType::OpenAI;
        return true;
    }

    return false;
}

bool BlockingEngine::ParseIpRule(const std::string& value, std::uint32_t& ip_address) {
    std::istringstream stream(value);
    std::string octet_text;
    std::uint32_t octets[4]{};

    for (std::size_t index = 0; index < 4; ++index) {
        if (!std::getline(stream, octet_text, '.')) {
            return false;
        }

        if (octet_text.empty()) {
            return false;
        }

        for (const char character : octet_text) {
            if (!std::isdigit(static_cast<unsigned char>(character))) {
                return false;
            }
        }

        const int octet = std::stoi(octet_text);
        if (octet < 0 || octet > 255) {
            return false;
        }

        octets[index] = static_cast<std::uint32_t>(octet);
    }

    if (stream.rdbuf()->in_avail() != 0) {
        return false;
    }

    ip_address = (octets[0] << 24) |
                 (octets[1] << 16) |
                 (octets[2] << 8) |
                 octets[3];
    return true;
}

std::string BlockingEngine::NormalizeText(const std::string& value) {
    std::string normalized = value;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char character) {
                       return static_cast<char>(std::tolower(character));
                   });
    return normalized;
}

std::string BlockingEngine::BuildBlockReason(const BlockingRules& rules, const Flow& flow) {
    for (const AppType blocked_app : rules.blocked_apps) {
        if (flow.app_type == blocked_app) {
            return "app:" + SniExtractor::AppTypeToString(blocked_app);
        }
    }

    const std::string normalized_domain = NormalizeText(flow.detected_domain);
    for (const std::string& blocked_domain : rules.blocked_domain_substrings) {
        if (ContainsText(normalized_domain, blocked_domain)) {
            return "domain:" + blocked_domain;
        }
    }

    for (const std::uint32_t blocked_ip : rules.blocked_ips) {
        if (flow.key.endpoint_a_ip == blocked_ip || flow.key.endpoint_b_ip == blocked_ip) {
            return "ip:" + PacketParser::FormatIPv4Address(blocked_ip);
        }
    }

    return "";
}

}  // namespace DeepTrace
