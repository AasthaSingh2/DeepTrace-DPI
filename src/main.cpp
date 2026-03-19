#include <cstdlib>
#include <algorithm>
#include <chrono>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#include "blocking_engine.h"
#include "dns_parser.h"
#include "flow_tracker.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "pcap_writer.h"
#include "sni_extractor.h"

namespace DeepTrace {

namespace {

void PrintUsage() {
    std::cout << "Usage: deeptrace_dpi <pcap_file> [max_packets] [--pred-out <csv_file>]"
                 " [--out <filtered_pcap_file>] [--block-app <app>]"
                 " [--block-domain <domain_substring>] [--block-ip <ip>]\n";
}

bool ParseMaxPackets(const char* value, std::size_t& max_packets) {
    try {
        const std::string input(value);
        std::size_t parsed_characters = 0;
        const unsigned long long parsed_value = std::stoull(input, &parsed_characters, 10);
        if (parsed_characters != input.size()) {
            return false;
        }
        if (parsed_value == 0 ||
            parsed_value > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
            return false;
        }
        max_packets = static_cast<std::size_t>(parsed_value);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

void PrintFinalSummary(const RunStats& stats) {
    const double processing_time_seconds = stats.processing_time_seconds;
    const double packets_per_second =
        processing_time_seconds > 0.0 ? static_cast<double>(stats.packets_seen) / processing_time_seconds : 0.0;
    const double bytes_per_second =
        processing_time_seconds > 0.0 ? static_cast<double>(stats.bytes_processed) / processing_time_seconds : 0.0;

    std::cout << "\nFinal summary\n";
    std::cout << "-------------\n";
    std::cout << "Packets seen:       " << stats.packets_seen << '\n';
    std::cout << "Bytes processed:    " << stats.bytes_processed << '\n';
    std::cout << "Packets parsed:     " << stats.packets_parsed << '\n';
    std::cout << "Malformed packets:  " << stats.malformed_packets << '\n';
    std::cout << "Non-IPv4 packets:   " << stats.non_ipv4_packets << '\n';
    std::cout << "TCP packets:        " << stats.tcp_packets << '\n';
    std::cout << "UDP packets:        " << stats.udp_packets << '\n';
    std::cout << "Other IPv4 packets: " << stats.other_ipv4_packets << '\n';
    std::cout << "Flows tracked:      " << stats.flows_seen << '\n';
    std::cout << "Flows classified:   " << stats.classified_flows << '\n';
    std::cout << "Processing time:    " << std::fixed << std::setprecision(6)
              << processing_time_seconds << " s\n";
    std::cout << "Packets/sec:        " << packets_per_second << '\n';
    std::cout << "Bytes/sec:          " << bytes_per_second << '\n';
    std::cout << std::defaultfloat;
}

std::string BuildPacketApplicationSummary(const AppMetadata& metadata) {
    std::string suffix;

    if (!metadata.sni.empty()) {
        suffix += " packet_sni=" + metadata.sni;
    }

    if (!metadata.http_host.empty()) {
        suffix += " packet_host=" + metadata.http_host;
    }

    if (!metadata.dns_query.empty()) {
        suffix += " packet_dns_query=" + metadata.dns_query;
    }

    if (!metadata.detected_domain.empty()) {
        suffix += " packet_domain=" + metadata.detected_domain;
    }

    if (metadata.app_type != AppType::Unknown) {
        suffix += " packet_app=" + SniExtractor::AppTypeToString(metadata.app_type);
    }

    return suffix;
}

std::string FormatTransportProtocol(std::uint8_t protocol) {
    switch (protocol) {
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        default:
            return std::to_string(static_cast<unsigned int>(protocol));
    }
}

std::string BuildFlowLabel(const Flow& flow) {
    return PacketParser::FormatIPv4Address(flow.key.endpoint_a_ip) + ":" +
           std::to_string(flow.key.endpoint_a_port) + " <-> " +
           PacketParser::FormatIPv4Address(flow.key.endpoint_b_ip) + ":" +
           std::to_string(flow.key.endpoint_b_port) + " proto=" +
           FormatTransportProtocol(flow.key.protocol);
}

std::string EscapeCsvField(const std::string& value) {
    bool needs_quotes = false;
    std::string escaped;
    escaped.reserve(value.size());

    for (const char character : value) {
        if (character == '"' || character == ',' || character == '\n' || character == '\r') {
            needs_quotes = true;
        }

        if (character == '"') {
            escaped += "\"\"";
        } else {
            escaped += character;
        }
    }

    if (!needs_quotes) {
        return escaped;
    }

    return "\"" + escaped + "\"";
}

std::string BuildFlowSummary(const Flow* flow) {
    if (flow == nullptr) {
        return "";
    }

    std::string suffix = " | flow=" + BuildFlowLabel(*flow);

    if (flow->blocked) {
        suffix += " BLOCKED(" + flow->block_reason + ")";
    }

    if (!flow->detected_domain.empty()) {
        suffix += " domain=" + flow->detected_domain;
    } else {
        if (!flow->sni.empty()) {
            suffix += " sni=" + flow->sni;
        }

        if (!flow->http_host.empty()) {
            suffix += " host=" + flow->http_host;
        }

        if (!flow->dns_query.empty()) {
            suffix += " dns_query=" + flow->dns_query;
        }
    }

    suffix += " app=" + SniExtractor::AppTypeToString(flow->app_type);
    suffix += " packets=" + std::to_string(flow->packets_seen);
    return suffix;
}

void PrintFlowClassificationEvent(const Flow& flow) {
    std::cout << "      FLOW CLASSIFIED: " << BuildFlowLabel(flow)
              << " app=" << SniExtractor::AppTypeToString(flow.app_type);

    if (flow.blocked) {
        std::cout << " BLOCKED(" << flow.block_reason << ")";
    }

    if (!flow.detected_domain.empty()) {
        std::cout << " domain=" << flow.detected_domain;
    } else {
        if (!flow.sni.empty()) {
            std::cout << " sni=" << flow.sni;
        }

        if (!flow.http_host.empty()) {
            std::cout << " host=" << flow.http_host;
        }

        if (!flow.dns_query.empty()) {
            std::cout << " dns_query=" << flow.dns_query;
        }
    }

    std::cout << '\n';
}

void PrintFlowTableSummary(const FlowTracker& flow_tracker) {
    std::vector<const Flow*> flows = flow_tracker.GetFlows();
    std::sort(flows.begin(), flows.end(),
              [](const Flow* left, const Flow* right) {
                  if (left->classified != right->classified) {
                      return left->classified > right->classified;
                  }
                  if (left->app_type != right->app_type) {
                      return static_cast<int>(left->app_type) < static_cast<int>(right->app_type);
                  }
                  if (left->packets_seen != right->packets_seen) {
                      return left->packets_seen > right->packets_seen;
                  }
                  return BuildFlowLabel(*left) < BuildFlowLabel(*right);
              });

    std::cout << "\nFlow summary\n";
    std::cout << "------------\n";

    if (flows.empty()) {
        std::cout << "No IPv4 TCP/UDP flows tracked.\n";
        return;
    }

    for (const Flow* flow : flows) {
        std::cout << "["
                  << (flow->blocked ? "blocked" : "allowed")
                  << "/"
                  << (flow->classified ? "classified" : "unclassified")
                  << "] "
                  << BuildFlowLabel(*flow)
                  << " app=" << SniExtractor::AppTypeToString(flow->app_type)
                  << " packets=" << flow->packets_seen
                  << " bytes=" << flow->bytes_seen;

        if (flow->blocked) {
            std::cout << " block_reason=" << flow->block_reason;
        }

        if (!flow->detected_domain.empty()) {
            std::cout << " domain=" << flow->detected_domain;
        } else {
            if (!flow->sni.empty()) {
                std::cout << " sni=" << flow->sni;
            }

            if (!flow->http_host.empty()) {
                std::cout << " host=" << flow->http_host;
            }

            if (!flow->dns_query.empty()) {
                std::cout << " dns_query=" << flow->dns_query;
            }
        }

        std::cout << '\n';
    }
}

bool WritePredictionCsv(const FlowTracker& flow_tracker,
                        const std::string& csv_file_path,
                        std::string& error_message) {
    std::ofstream output(csv_file_path, std::ios::out | std::ios::trunc);
    if (!output.is_open()) {
        error_message = "Failed to open prediction CSV for writing: " + csv_file_path;
        return false;
    }

    output << "flow_id,predicted_app,domain,packet_count,byte_count\n";

    const std::vector<const Flow*> flows = flow_tracker.GetFlows();
    for (const Flow* flow : flows) {
        output << EscapeCsvField(BuildFlowLabel(*flow)) << ','
               << EscapeCsvField(SniExtractor::AppTypeToString(flow->app_type)) << ','
               << EscapeCsvField(flow->detected_domain) << ','
               << flow->packets_seen << ','
               << flow->bytes_seen << '\n';

        if (!output.good()) {
            error_message = "Failed while writing prediction CSV: " + csv_file_path;
            return false;
        }
    }

    error_message.clear();
    return true;
}

bool ParseBlockingRules(const std::vector<std::string>& arguments,
                        BlockingRules& rules,
                        std::string& error_message) {
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const std::string& argument = arguments[index];
        if (argument != "--block-app" &&
            argument != "--block-domain" &&
            argument != "--block-ip") {
            continue;
        }

        if (index + 1 >= arguments.size()) {
            error_message = "Missing value after " + argument + ".";
            return false;
        }

        const std::string value = arguments[index + 1];
        if (argument == "--block-app") {
            AppType app_type = AppType::Unknown;
            if (!BlockingEngine::ParseAppRule(value, app_type)) {
                error_message = "Unsupported app for --block-app: " + value;
                return false;
            }
            rules.blocked_apps.push_back(app_type);
        } else if (argument == "--block-domain") {
            const std::string normalized = SniExtractor::NormalizeDomain(value);
            if (normalized.empty()) {
                error_message = "Invalid value for --block-domain.";
                return false;
            }
            rules.blocked_domain_substrings.push_back(normalized);
        } else {
            std::uint32_t ip_address = 0;
            if (!BlockingEngine::ParseIpRule(value, ip_address)) {
                error_message = "Invalid IPv4 address for --block-ip: " + value;
                return false;
            }
            rules.blocked_ips.push_back(ip_address);
        }

        ++index;
    }

    error_message.clear();
    return true;
}

}  // namespace

}  // namespace DeepTrace

int main(int argc, char* argv[]) {
    using namespace DeepTrace;

    if (argc < 2) {
        PrintUsage();
        return EXIT_FAILURE;
    }

    std::size_t max_packets = 0;
    bool limit_packets = false;
    std::string prediction_csv_path;
    std::string filtered_pcap_path;
    std::string error_message;
    BlockingRules blocking_rules;
    std::vector<std::string> deferred_blocking_arguments;

    int argument_index = 2;
    while (argument_index < argc) {
        const std::string argument = argv[argument_index];
        if (argument == "--pred-out") {
            if (argument_index + 1 >= argc) {
                std::cerr << "Missing CSV file after --pred-out.\n";
                return EXIT_FAILURE;
            }

            prediction_csv_path = argv[argument_index + 1];
            argument_index += 2;
            continue;
        }

        if (argument == "--out") {
            if (argument_index + 1 >= argc) {
                std::cerr << "Missing PCAP file after --out.\n";
                return EXIT_FAILURE;
            }

            filtered_pcap_path = argv[argument_index + 1];
            argument_index += 2;
            continue;
        }

        if (argument == "--block-app" ||
            argument == "--block-domain" ||
            argument == "--block-ip") {
            if (argument_index + 1 >= argc) {
                std::cerr << "Missing value after " << argument << ".\n";
                return EXIT_FAILURE;
            }

            deferred_blocking_arguments.push_back(argument);
            deferred_blocking_arguments.push_back(argv[argument_index + 1]);
            argument_index += 2;
            continue;
        }

        if (!limit_packets) {
            if (!ParseMaxPackets(argv[argument_index], max_packets)) {
                std::cerr << "Invalid max_packets value. It must be a positive integer.\n";
                return EXIT_FAILURE;
            }
            limit_packets = true;
            ++argument_index;
            continue;
        }

        std::cerr << "Unknown argument: " << argument << '\n';
        PrintUsage();
        return EXIT_FAILURE;
    }

    if (!ParseBlockingRules(deferred_blocking_arguments, blocking_rules, error_message)) {
        std::cerr << error_message << '\n';
        return EXIT_FAILURE;
    }

    PcapReader reader;
    if (!reader.Open(argv[1], error_message)) {
        std::cerr << error_message << '\n';
        return EXIT_FAILURE;
    }

    const auto& global_header = reader.GetGlobalHeader();
    std::cout << "DeepTrace-DPI Version 1\n";
    std::cout << "Reading PCAP: " << argv[1] << '\n';
    std::cout << "PCAP version: " << global_header.version_major << '.'
              << global_header.version_minor << '\n';
    std::cout << "Snaplen: " << global_header.snaplen << '\n';
    if (limit_packets) {
        std::cout << "Packet limit: " << max_packets << '\n';
    }
    if (!prediction_csv_path.empty()) {
        std::cout << "Prediction CSV: " << prediction_csv_path << '\n';
    }
    if (!filtered_pcap_path.empty()) {
        std::cout << "Filtered PCAP: " << filtered_pcap_path << '\n';
    }
    if (!blocking_rules.blocked_apps.empty() ||
        !blocking_rules.blocked_domain_substrings.empty() ||
        !blocking_rules.blocked_ips.empty()) {
        std::cout << "Blocking rules: enabled\n";
    }
    std::cout << '\n';

    PacketParser parser;
    SniExtractor extractor;
    DnsParser dns_parser;
    FlowTracker flow_tracker(blocking_rules);
    PcapWriter filtered_writer;
    RunStats stats;
    RawPacket raw_packet;
    const auto processing_start = std::chrono::steady_clock::now();

    if (!filtered_pcap_path.empty() &&
        !filtered_writer.Open(filtered_pcap_path, global_header, error_message)) {
        std::cerr << error_message << '\n';
        return EXIT_FAILURE;
    }

    while (true) {
        if (limit_packets && stats.packets_seen >= max_packets) {
            break;
        }

        if (!reader.ReadNextPacket(raw_packet, error_message)) {
            if (!error_message.empty()) {
                std::cerr << "Read error: " << error_message << '\n';
            }
            break;
        }

        ++stats.packets_seen;
        stats.bytes_processed += raw_packet.header.incl_len;

        bool malformed = false;
        const ParsedPacket parsed_packet =
            parser.Parse(raw_packet.data.data(), raw_packet.data.size(), malformed);
        AppMetadata packet_metadata;
        if (!malformed) {
            packet_metadata = extractor.Inspect(raw_packet.data.data(),
                                                raw_packet.data.size(),
                                                parsed_packet);
            const AppMetadata dns_metadata = dns_parser.Inspect(raw_packet.data.data(),
                                                                raw_packet.data.size(),
                                                                parsed_packet);
            if (packet_metadata.detected_domain.empty() && !dns_metadata.detected_domain.empty()) {
                packet_metadata.detected_domain = dns_metadata.detected_domain;
            }
            if (packet_metadata.app_type == AppType::Unknown &&
                dns_metadata.app_type != AppType::Unknown) {
                packet_metadata.app_type = dns_metadata.app_type;
            }
            if (packet_metadata.dns_query.empty()) {
                packet_metadata.dns_query = dns_metadata.dns_query;
            }
            packet_metadata.is_dns_query = packet_metadata.is_dns_query || dns_metadata.is_dns_query;
        }
        bool is_new_flow = false;
        bool classification_changed = false;
        bool blocking_changed = false;
        Flow* flow = malformed ? nullptr
                               : flow_tracker.TrackPacket(parsed_packet,
                                                          raw_packet.header.incl_len,
                                                          packet_metadata,
                                                          is_new_flow,
                                                          classification_changed,
                                                          blocking_changed);

        const bool allow_packet = flow == nullptr || !flow->blocked;
        if (allow_packet && filtered_writer.IsOpen()) {
            if (!filtered_writer.WritePacket(raw_packet, error_message)) {
                std::cerr << error_message << '\n';
                return EXIT_FAILURE;
            }
        }

        if (malformed) {
            ++stats.malformed_packets;
        } else {
            ++stats.packets_parsed;
        }

        if (!parsed_packet.is_ipv4) {
            ++stats.non_ipv4_packets;
        } else if (parsed_packet.is_tcp) {
            ++stats.tcp_packets;
        } else if (parsed_packet.is_udp) {
            ++stats.udp_packets;
        } else {
            ++stats.other_ipv4_packets;
        }

        stats.flows_seen = flow_tracker.FlowCount();
        stats.classified_flows = flow_tracker.ClassifiedFlowCount();

        std::cout << "[" << std::setw(6) << stats.packets_seen << "] "
                  << "ts=" << raw_packet.header.ts_sec << '.'
                  << std::setw(6) << std::setfill('0') << raw_packet.header.ts_usec
                  << std::setfill(' ') << " captured=" << raw_packet.header.incl_len
                  << " original=" << raw_packet.header.orig_len
                  << " | " << parsed_packet.summary
                  << BuildPacketApplicationSummary(packet_metadata)
                  << BuildFlowSummary(flow) << '\n';

        if (flow != nullptr && blocking_changed && flow->blocked) {
            std::cout << "      FLOW BLOCKED: " << BuildFlowLabel(*flow)
                      << " reason=" << flow->block_reason << '\n';
        }

        if (flow != nullptr && (is_new_flow || classification_changed) && flow->classified) {
            PrintFlowClassificationEvent(*flow);
        }
    }

    stats.processing_time_seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - processing_start).count();

    PrintFinalSummary(stats);
    PrintFlowTableSummary(flow_tracker);

    if (!prediction_csv_path.empty()) {
        if (!WritePredictionCsv(flow_tracker, prediction_csv_path, error_message)) {
            std::cerr << error_message << '\n';
            return EXIT_FAILURE;
        }

        std::cout << "\nPrediction CSV written: " << prediction_csv_path << '\n';
    }

    if (!filtered_pcap_path.empty()) {
        std::cout << "Filtered PCAP written: " << filtered_pcap_path << '\n';
    }

    return EXIT_SUCCESS;
}
