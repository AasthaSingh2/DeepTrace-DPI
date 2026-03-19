#include "flow_tracker.h"

#include <utility>

#include "blocking_engine.h"

namespace DeepTrace {

FlowTracker::FlowTracker(BlockingRules rules)
    : blocking_rules_(std::move(rules)) {}

Flow* FlowTracker::TrackPacket(const ParsedPacket& parsed_packet,
                               std::size_t captured_length,
                               const AppMetadata& metadata,
                               bool& is_new_flow,
                               bool& classification_changed,
                               bool& blocking_changed) {
    is_new_flow = false;
    classification_changed = false;
    blocking_changed = false;

    const std::optional<FiveTuple> key = BuildFiveTuple(parsed_packet);
    if (!key.has_value()) {
        return nullptr;
    }

    auto [iterator, inserted] = flow_table_.try_emplace(*key);
    Flow& flow = iterator->second;
    if (inserted) {
        flow.key = *key;
        is_new_flow = true;
    }

    ++flow.packets_seen;
    flow.bytes_seen += captured_length;

    const bool was_classified = flow.classified;
    classification_changed = MergeMetadataIntoFlow(metadata, flow);
    if (!was_classified && flow.classified) {
        ++classified_flow_count_;
    }

    blocking_changed = BlockingEngine::ApplyRules(blocking_rules_, flow);

    return &flow;
}

std::size_t FlowTracker::FlowCount() const {
    return flow_table_.size();
}

std::size_t FlowTracker::ClassifiedFlowCount() const {
    return classified_flow_count_;
}

std::vector<const Flow*> FlowTracker::GetFlows() const {
    std::vector<const Flow*> flows;
    flows.reserve(flow_table_.size());

    for (const auto& entry : flow_table_) {
        flows.push_back(&entry.second);
    }

    return flows;
}

std::optional<FiveTuple> FlowTracker::BuildFiveTuple(const ParsedPacket& parsed_packet) {
    if (!parsed_packet.is_ipv4 || !parsed_packet.ipv4.has_value()) {
        return std::nullopt;
    }

    if (parsed_packet.is_tcp && parsed_packet.tcp.has_value()) {
        return BuildCanonicalKey(parsed_packet.ipv4->source_ip,
                                 parsed_packet.tcp->source_port,
                                 parsed_packet.ipv4->destination_ip,
                                 parsed_packet.tcp->destination_port,
                                 parsed_packet.ipv4->protocol);
    }

    if (parsed_packet.is_udp && parsed_packet.udp.has_value()) {
        return BuildCanonicalKey(parsed_packet.ipv4->source_ip,
                                 parsed_packet.udp->source_port,
                                 parsed_packet.ipv4->destination_ip,
                                 parsed_packet.udp->destination_port,
                                 parsed_packet.ipv4->protocol);
    }

    return std::nullopt;
}

FiveTuple FlowTracker::BuildCanonicalKey(std::uint32_t source_ip,
                                         std::uint16_t source_port,
                                         std::uint32_t destination_ip,
                                         std::uint16_t destination_port,
                                         std::uint8_t protocol) {
    FiveTuple key{};
    key.protocol = protocol;

    const bool source_is_first =
        (source_ip < destination_ip) ||
        (source_ip == destination_ip && source_port <= destination_port);

    if (source_is_first) {
        key.endpoint_a_ip = source_ip;
        key.endpoint_a_port = source_port;
        key.endpoint_b_ip = destination_ip;
        key.endpoint_b_port = destination_port;
    } else {
        key.endpoint_a_ip = destination_ip;
        key.endpoint_a_port = destination_port;
        key.endpoint_b_ip = source_ip;
        key.endpoint_b_port = source_port;
    }

    return key;
}

bool FlowTracker::MergeMetadataIntoFlow(const AppMetadata& metadata, Flow& flow) {
    bool changed = false;

    if (!metadata.sni.empty() && flow.sni != metadata.sni) {
        flow.sni = metadata.sni;
        changed = true;
    }

    if (!metadata.http_host.empty() && flow.http_host != metadata.http_host) {
        flow.http_host = metadata.http_host;
        changed = true;
    }

    if (!metadata.dns_query.empty() && flow.dns_query != metadata.dns_query) {
        flow.dns_query = metadata.dns_query;
        changed = true;
    }

    if (!metadata.detected_domain.empty() && flow.detected_domain != metadata.detected_domain) {
        flow.detected_domain = metadata.detected_domain;
        changed = true;
    }

    if (metadata.is_tls_client_hello && !flow.is_tls_client_hello) {
        flow.is_tls_client_hello = true;
        changed = true;
    }

    if (metadata.is_http_request && !flow.is_http_request) {
        flow.is_http_request = true;
        changed = true;
    }

    if (metadata.is_dns_query && !flow.is_dns_query) {
        flow.is_dns_query = true;
        changed = true;
    }

    if (metadata.app_type != AppType::Unknown && flow.app_type != metadata.app_type) {
        flow.app_type = metadata.app_type;
        changed = true;
    }

    const bool now_classified = flow.app_type != AppType::Unknown ||
                                !flow.detected_domain.empty();
    if (now_classified && !flow.classified) {
        flow.classified = true;
        changed = true;
    }

    return changed;
}

}  // namespace DeepTrace
