#pragma once

/// @file gateway_peer_pinset.hpp
/// The immutable set of public-key pins a gateway-upstream peer may present, and
/// the boot-time loader that builds it.
///
/// WHO DECIDES. This file decides only WHICH PINS ARE IN FORCE. Whether a
/// presented certificate is admitted is `gateway_peer_policy.hpp`.
///
/// A PIN is the SHA-256 of a certificate's full DER SubjectPublicKeyInfo, as 64
/// lowercase hex characters (`gateway_peer_cert.hpp`). It identifies a KEY, so a
/// re-issued certificate over the same key keeps matching and revoking one
/// certificate serial does not remove the pin. Withdrawing a pin means removing
/// it and restarting every serving replica.
///
/// BOOT-FIXED, NO RELOAD. `load_boot_pins` runs once. Nothing here re-reads a
/// file, ages a pin out, or consults a revocation source; a `PinSet` never
/// changes after construction, so a reader needs no lock. Do not add any of those
/// without re-opening the design record.
///
/// SOURCES (a union):
///   1. explicit hex pins (`split_pin_list` splits the comma-separated form),
///   2. pin files, repeatable: a PEM file of one or more CERTIFICATE blocks (every
///      block contributes its pin) or a text file of 64-hex pins, one per line
///      (blank lines and lines starting with '#' are ignored). A file that mixes
///      the two forms is malformed. One leading UTF-8 byte order mark is
///      tolerated; UTF-16 and NUL bytes are refused (malformed).
///   3. one auto-pin file (the default gateway certificate), used ONLY when no
///      explicit source was given.
///
/// FAIL CLOSED. Any explicit source that is malformed, missing, unreadable,
/// oversized, over the count bound or empty is an ERROR, and so is a union of zero
/// pins. A broken explicit source NEVER falls back to the auto-pin: the caller
/// that wrote `--gateway-peer-pin-file` meant that file.
///
/// BOUNDS: `kMaxPinFileBytes` per file, `kMaxPinsPerFile` per file, `kMaxPins`
/// across the union (after de-duplication).

#include <algorithm>
#include <cstddef>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace yuzu::server::gateway_peer {

inline constexpr std::size_t kPinHexLen = 64;
inline constexpr std::size_t kMaxPinFileBytes = 64 * 1024;
inline constexpr std::size_t kMaxPinsPerFile = 32;
inline constexpr std::size_t kMaxPins = 64;

/// Normalise one hex pin: exactly 64 hex characters (either case) -> lowercase.
/// Surrounding ASCII whitespace is trimmed first. `nullopt` if malformed.
[[nodiscard]] std::optional<std::string> parse_pin_hex(std::string_view text);

/// Split a comma-separated pin list (the environment form). Whitespace around a
/// token is trimmed and an empty token is skipped, so a trailing comma is
/// harmless. Tokens are NOT validated here; `load_boot_pins` rejects a malformed one. A list
/// with no token in it returns an empty vector: a caller that needs "supplied but blank" to
/// stay visible must record it before calling (`normalize_gateway_peer_options` does).
[[nodiscard]] std::vector<std::string> split_pin_list(std::string_view list);

enum class PinFileState : unsigned char {
    Loaded,    ///< parsed; at least one pin
    Empty,     ///< parsed cleanly but held no pins
    TooLarge,  ///< over `kMaxPinFileBytes`
    Malformed, ///< not a complete valid pin file
    OverCount, ///< over `kMaxPinsPerFile`
};

[[nodiscard]] constexpr std::string_view to_label(PinFileState s) {
    switch (s) {
    case PinFileState::Loaded:
        return "loaded";
    case PinFileState::Empty:
        return "empty";
    case PinFileState::TooLarge:
        return "too_large";
    case PinFileState::Malformed:
        return "malformed";
    case PinFileState::OverCount:
        return "over_count";
    }
    return "malformed";
}

struct ParsedPinFile {
    PinFileState state{PinFileState::Malformed};
    std::vector<std::string> pins; ///< lowercase hex, de-duplicated, source order; empty unless Loaded
    /// Distinct pins whose certificate does not list serverAuth in ANY block of the file that
    /// carries that key: the policy will deny such a certificate, so a non-zero count is worth a
    /// boot-time warning. Always `lacking_pins.size()`.
    std::size_t pins_without_server_auth{0};
    std::vector<std::string> lacking_pins; ///< the pins counted above (a subset of `pins`)
};

/// Parse one pin file's text. Pure.
[[nodiscard]] ParsedPinFile parse_pin_file(std::string_view content);

/// Immutable once constructed. Probe with `string_view` without building a `std::string`.
class PinSet {
public:
    PinSet() = default;
    /// `pins` must already be normalised (`parse_pin_hex` output); duplicates collapse.
    explicit PinSet(const std::vector<std::string>& pins, std::size_t pins_without_server_auth = 0)
        : pins_(pins.begin(), pins.end()), without_eku_(pins_without_server_auth) {}

    [[nodiscard]] bool contains(std::string_view pin) const { return pins_.find(pin) != pins_.end(); }
    [[nodiscard]] std::size_t size() const { return pins_.size(); }
    [[nodiscard]] bool empty() const { return pins_.empty(); }
    /// How many DISTINCT pins have no source that lists serverAuth (see `ParsedPinFile`). It is
    /// at most `size()` for a set `load_boot_pins` built; a hex-only pin is never counted, since
    /// a bare key carries no extended key usage to inspect.
    [[nodiscard]] std::size_t pins_without_server_auth() const { return without_eku_; }
    /// Every pin, sorted, so a log line over the set is stable across runs and replicas.
    [[nodiscard]] std::vector<std::string> sorted_pins() const {
        std::vector<std::string> out(pins_.begin(), pins_.end());
        std::sort(out.begin(), out.end());
        return out;
    }

private:
    struct Hash {
        using is_transparent = void;
        [[nodiscard]] std::size_t operator()(std::string_view s) const noexcept {
            return std::hash<std::string_view>{}(s);
        }
    };
    std::unordered_set<std::string, Hash, std::equal_to<>> pins_;
    std::size_t without_eku_{0};
};

/// Result of reading one file. `Ok` carries the content.
struct FileReadResult {
    enum class Status : unsigned char { Ok, Missing, Unreadable, TooLarge };
    Status status{Status::Unreadable};
    std::string content;
};

/// Reads at most `max_bytes` of `path`; a longer file is `TooLarge` and its content is not
/// returned. Must not throw (an exception is reported as an unreadable source).
using FileReader = std::function<FileReadResult(const std::string& path, std::size_t max_bytes)>;

/// The filesystem reader used when none is injected: regular files only. On POSIX it opens the
/// path ONCE (non-blocking, so a FIFO cannot hold the boot thread) and decides from that
/// descriptor: a FIFO, device or directory is `Unreadable`, an oversized file `TooLarge`. A
/// symlink is followed (secret mounts present files that way).
[[nodiscard]] FileReadResult read_file_bounded(const std::string& path, std::size_t max_bytes);

/// Build the boot pin set. See "FAIL CLOSED" in the file banner. `auto_pin_file` is read only
/// when `hex_pins` and `pin_files` are both empty. A null `reader` means `read_file_bounded`.
/// An empty or whitespace-only entry in `hex_pins` is an error (a supplied option that holds no
/// pin). The error string names the offending source and never echoes a whole pin.
[[nodiscard]] std::expected<PinSet, std::string>
load_boot_pins(const std::vector<std::string>& hex_pins, const std::vector<std::string>& pin_files,
               const std::string& auto_pin_file, const FileReader& reader = {});

} // namespace yuzu::server::gateway_peer
