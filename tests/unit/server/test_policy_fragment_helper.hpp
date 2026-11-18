#pragma once

// PolicyStore::create_fragment REQUIRES the authorized-pair snapshot (it has no default). Tests that
// are not about authorization store fragments through this helper, which authorizes every instruction
// the YAML names as `test.pair` - or, given an InstructionStore, as the plugin.action each id really
// resolves to (needed when the evaluator will dispatch it, which refuses a snapshot that does not
// match the definition).

#include "instruction_store.hpp"
#include "policy_store.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace yuzu::test {

inline std::string authorized_pairs_for(const std::string& yaml,
                                        yuzu::server::InstructionStore* instructions = nullptr) {
    nlohmann::json pairs = nlohmann::json::object();
    for (const auto& [role, id] : yuzu::server::PolicyStore::peek_fragment_instructions(yaml)) {
        std::string pair = "test.pair";
        if (instructions) {
            auto def = instructions->get_definition(id);
            if (def && *def)
                pair = (*def)->plugin + "." + (*def)->action;
        }
        pairs[id] = pair;
    }
    return pairs.dump();
}

inline std::expected<std::string, std::string>
create_fragment_for_test(yuzu::server::PolicyStore& store, const std::string& yaml,
                         yuzu::server::InstructionStore* instructions = nullptr) {
    // A fragment naming no instruction takes the empty snapshot, like production.
    const auto pairs = yuzu::server::PolicyStore::peek_fragment_instructions(yaml).empty()
                           ? std::string{}
                           : authorized_pairs_for(yaml, instructions);
    return store.create_fragment(yaml, pairs);
}

} // namespace yuzu::test
