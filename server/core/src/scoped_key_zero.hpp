#pragma once

#include <yuzu/secure_zero.hpp>

#include <string>

/// @file scoped_key_zero.hpp
/// Hoisted out of server.cpp (HA WS-6 CRL follow-ups, #4828) so crl_publisher.cpp can share the
/// same RAII guard without depending on server.cpp's translation unit.
namespace yuzu::server::detail {

// RAII guard that zeroes a std::string's bytes on scope exit (incl. exception
// unwind). Used wherever a private key is transiently materialised — the CA
// signing + CRL paths — so the crown jewel is not left in freed heap. (DRYs the
// formerly-duplicated local KeyZero structs — gov cpp-expert SHOULD.)
struct ScopedKeyZero {
    std::string& s;
    ~ScopedKeyZero() { yuzu::secure_zero(s); }
};

} // namespace yuzu::server::detail
