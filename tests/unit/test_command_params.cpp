// command_params_have_nul: the pure predicate the agent applies BEFORE the dedup claim and the
// stagger sleep (sg10 / UP-1). A key or value with an embedded NUL is truncated by c_str() and read
// by a plugin as a different name.

#include "command_params.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>
#include <unordered_map>

using yuzu::agent::command_params_have_nul;

TEST_CASE("command_params_have_nul: key and value NULs are found on every map shape",
          "[command_params][sg10]") {
    const std::map<std::string, std::string> clean{{"targets", "10.0.0.1"}, {"k", ""}};
    CHECK_FALSE(command_params_have_nul(clean));
    CHECK_FALSE(command_params_have_nul(std::map<std::string, std::string>{}));
    CHECK_FALSE(command_params_have_nul(std::unordered_map<std::string, std::string>{}));

    const std::map<std::string, std::string> key_nul{{std::string("targets\0x", 9), "v"}};
    CHECK(command_params_have_nul(key_nul));
    const std::map<std::string, std::string> val_nul{{"k", std::string("v\0w", 3)}};
    CHECK(command_params_have_nul(val_nul));
    const std::unordered_map<std::string, std::string> twin{{"a", "b"}, {std::string("\0", 1), "v"}};
    CHECK(command_params_have_nul(twin));
    // Other control bytes are not NULs: c_str() does not truncate on them.
    const std::map<std::string, std::string> ctrl{{"a\tb", "c\nd"}};
    CHECK_FALSE(command_params_have_nul(ctrl));
}
