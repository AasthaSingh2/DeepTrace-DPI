#pragma once

#include <optional>
#include <unordered_map>
#include <vector>

#include "blocking_engine.h"
#include "types.h"

namespace DeepTrace {

class FlowTracker {
public:
    explicit FlowTracker(BlockingRules rules = {});

    Flow* TrackPacket(const ParsedPacket& parsed_packet,
                      std::size_t captured_length,
                      const AppMetadata& metadata,
                      bool& is_new_flow,
                      bool& classification_changed,
                      bool& blocking_changed);

    std::size_t FlowCount() const;
    std::size_t ClassifiedFlowCount() const;
    std::vector<const Flow*> GetFlows() const;

private:
    static std::optional<FiveTuple> BuildFiveTuple(const ParsedPacket& parsed_packet);
    static FiveTuple BuildCanonicalKey(std::uint32_t source_ip,
                                       std::uint16_t source_port,
                                       std::uint32_t destination_ip,
                                       std::uint16_t destination_port,
                                       std::uint8_t protocol);
    static bool MergeMetadataIntoFlow(const AppMetadata& metadata, Flow& flow);

    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flow_table_;
    std::size_t classified_flow_count_ = 0;
    BlockingRules blocking_rules_;
};

}  // namespace DeepTrace
