#pragma once

/// @file test_export_cap_guard.hpp
/// Scoped override of the shared response-export byte cap (#4703). One definition for
/// every test file, so a failed REQUIRE can never leak a tiny cap into a later test in
/// the same process, and the legacy and v1 export suites cannot drift on how they
/// restore it.

#include <cstddef>

#include "response_query_params.hpp"

namespace yuzu::test {

class ExportByteCapGuard {
public:
    explicit ExportByteCapGuard(std::size_t cap)
        : saved_(yuzu::server::export_body_byte_cap().exchange(cap)) {}
    ~ExportByteCapGuard() { yuzu::server::export_body_byte_cap().store(saved_); }

    ExportByteCapGuard(const ExportByteCapGuard&) = delete;
    ExportByteCapGuard& operator=(const ExportByteCapGuard&) = delete;
    ExportByteCapGuard(ExportByteCapGuard&&) = delete;
    ExportByteCapGuard& operator=(ExportByteCapGuard&&) = delete;

private:
    std::size_t saved_;
};

} // namespace yuzu::test
