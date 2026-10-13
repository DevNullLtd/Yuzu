#include "gateway_peer_pinset.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <utility>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "gateway_peer_cert.hpp"

namespace yuzu::server::gateway_peer {

namespace {

constexpr std::string_view kPemBegin = "-----BEGIN ";
constexpr std::string_view kPemBeginCert = "-----BEGIN CERTIFICATE-----";
constexpr std::string_view kPemEndCert = "-----END CERTIFICATE-----";

bool is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && is_ws(s.front()))
        s.remove_prefix(1);
    while (!s.empty() && is_ws(s.back()))
        s.remove_suffix(1);
    return s;
}

void push_unique(std::vector<std::string>& out, std::string pin) {
    if (std::find(out.begin(), out.end(), pin) == out.end())
        out.push_back(std::move(pin));
}

ParsedPinFile failed(PinFileState s) {
    ParsedPinFile r;
    r.state = s;
    return r;
}

ParsedPinFile finish(ParsedPinFile r) {
    r.state = r.pins.empty() ? PinFileState::Empty : PinFileState::Loaded;
    r.pins_without_server_auth = r.lacking_pins.size();
    return r;
}

ParsedPinFile parse_pem_pins(std::string_view rest) {
    ParsedPinFile r;
    std::size_t blocks = 0;
    while (true) {
        const std::size_t b = rest.find(kPemBegin);
        // Text between (or after) blocks must be whitespace: a partially understood file
        // is a malformed file.
        if (!trim(rest.substr(0, b)).empty())
            return failed(PinFileState::Malformed);
        if (b == std::string_view::npos)
            break;
        rest.remove_prefix(b);
        // Only a CERTIFICATE block is accepted; a key, CSR or any other label makes the
        // whole file malformed before its body is touched.
        if (!rest.starts_with(kPemBeginCert))
            return failed(PinFileState::Malformed);
        const std::size_t e = rest.find(kPemEndCert);
        if (e == std::string_view::npos)
            return failed(PinFileState::Malformed);
        const std::string_view block = rest.substr(0, e + kPemEndCert.size());
        rest.remove_prefix(block.size());
        if (++blocks > kMaxPinsPerFile)
            return failed(PinFileState::OverCount);
        const auto facts = parse_cert_facts(block);
        if (!facts)
            return failed(PinFileState::Malformed);
        // A pin is "lacking serverAuth" only if EVERY block that carries its key lacks it, and it
        // is counted once however many blocks repeat it: the count is compared with the number of
        // distinct pins (see `build_boot_pins`), so it must be a count of distinct pins too.
        const auto lacking = std::find(r.lacking_pins.begin(), r.lacking_pins.end(),
                                       facts->spki_sha256_hex);
        if (facts->has_server_auth_eku) {
            if (lacking != r.lacking_pins.end())
                r.lacking_pins.erase(lacking);
        } else if (lacking == r.lacking_pins.end() &&
                   std::find(r.pins.begin(), r.pins.end(), facts->spki_sha256_hex) == r.pins.end()) {
            r.lacking_pins.push_back(facts->spki_sha256_hex);
        }
        push_unique(r.pins, facts->spki_sha256_hex);
    }
    return finish(std::move(r));
}

ParsedPinFile parse_hex_pins(std::string_view content) {
    ParsedPinFile r;
    std::size_t lines = 0;
    while (!content.empty()) {
        const std::size_t nl = content.find('\n');
        const std::string_view line = trim(content.substr(0, nl));
        content = (nl == std::string_view::npos) ? std::string_view{} : content.substr(nl + 1);
        if (line.empty() || line.front() == '#')
            continue;
        if (++lines > kMaxPinsPerFile)
            return failed(PinFileState::OverCount);
        auto pin = parse_pin_hex(line);
        if (!pin)
            return failed(PinFileState::Malformed);
        push_unique(r.pins, std::move(*pin));
    }
    return finish(std::move(r));
}

/// Name a source in an error without echoing a whole pin.
std::string short_pin(const std::string& raw) {
    return raw.substr(0, 8);
}

/// Read and parse one pin file into `pins`/`lacking`; the error names the file. `lacking` holds
/// the distinct pins every known source of which lacks serverAuth: a pin that ANY source supplies
/// without that information (a hex pin) or with serverAuth is not in it.
std::expected<void, std::string> add_file(const std::string& path, const FileReader& reader,
                                          std::vector<std::string>& pins,
                                          std::vector<std::string>& lacking) {
    if (path.empty())
        return std::unexpected("a gateway peer pin file was given an empty path");
    FileReadResult rd;
    try {
        rd = reader(path, kMaxPinFileBytes);
    } catch (...) {
        rd.status = FileReadResult::Status::Unreadable;
    }
    switch (rd.status) {
    case FileReadResult::Status::Ok:
        break;
    case FileReadResult::Status::Missing:
        return std::unexpected("gateway peer pin file '" + path + "' does not exist");
    case FileReadResult::Status::Unreadable:
        return std::unexpected("gateway peer pin file '" + path + "' could not be read");
    case FileReadResult::Status::TooLarge:
        return std::unexpected("gateway peer pin file '" + path + "' is larger than " +
                               std::to_string(kMaxPinFileBytes) + " bytes");
    }
    const ParsedPinFile parsed = parse_pin_file(rd.content);
    if (parsed.state != PinFileState::Loaded)
        return std::unexpected("gateway peer pin file '" + path + "' is " +
                               std::string{to_label(parsed.state)} +
                               (parsed.state == PinFileState::Empty ? " (it holds no pins)" : ""));
    for (const auto& p : parsed.pins) {
        const bool this_file_lacks = std::find(parsed.lacking_pins.begin(), parsed.lacking_pins.end(),
                                               p) != parsed.lacking_pins.end();
        const auto at = std::find(lacking.begin(), lacking.end(), p);
        if (this_file_lacks) {
            // New to the set and lacking here: lacking so far. Already known: keep its state.
            if (at == lacking.end() && std::find(pins.begin(), pins.end(), p) == pins.end())
                lacking.push_back(p);
        } else if (at != lacking.end()) {
            lacking.erase(at); // this source supplies it as usable
        }
        push_unique(pins, p);
    }
    return {};
}

} // namespace

std::optional<std::string> parse_pin_hex(std::string_view text) {
    text = trim(text);
    if (text.size() != kPinHexLen)
        return std::nullopt;
    std::string out;
    out.reserve(kPinHexLen);
    for (const char c : text) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            out += c;
        else if (c >= 'A' && c <= 'F')
            out += static_cast<char>(c - 'A' + 'a');
        else
            return std::nullopt;
    }
    return out;
}

std::vector<std::string> split_pin_list(std::string_view list) {
    std::vector<std::string> out;
    while (!list.empty()) {
        const std::size_t comma = list.find(',');
        const std::string_view tok = trim(list.substr(0, comma));
        if (!tok.empty())
            out.emplace_back(tok);
        if (comma == std::string_view::npos)
            break;
        list.remove_prefix(comma + 1);
    }
    return out;
}

ParsedPinFile parse_pin_file(std::string_view content) {
    if (content.size() > kMaxPinFileBytes)
        return failed(PinFileState::TooLarge);
    // One leading UTF-8 byte order mark is not content (Windows PowerShell 5.1 writes one for
    // `-Encoding UTF8`). UTF-16 is not decoded: its NUL bytes make it malformed, fail closed.
    if (content.starts_with("\xEF\xBB\xBF"))
        content.remove_prefix(3);
    if (content.find('\0') != std::string_view::npos)
        return failed(PinFileState::Malformed);
    if (content.find(kPemBegin) != std::string_view::npos)
        return parse_pem_pins(content);
    return parse_hex_pins(content);
}

#ifndef _WIN32

namespace {

/// Closes the descriptor on every exit of the scope that owns it. File-local on purpose: the
/// agent-side `ScopedFd` is not reachable from the server tree and `common/include/` takes no
/// I/O type (CLAUDE.md "Project layout").
struct FdCloser {
    int fd{-1};
    explicit FdCloser(int f) noexcept : fd(f) {}
    FdCloser(const FdCloser&) = delete;
    FdCloser& operator=(const FdCloser&) = delete;
    ~FdCloser() {
        if (fd >= 0)
            ::close(fd);
    }
};

} // namespace

// ONE open, then everything is decided from that descriptor: a path-based status/size/open
// sequence lets the path change between the steps (a regular file replaced by a FIFO blocks the
// open; a file that grows is read past its checked size). `O_NONBLOCK` makes the open of a FIFO
// return at once instead of waiting for a writer; a FIFO, device or directory is then refused by
// the `fstat` below, before any read. A symlink is FOLLOWED (no `O_NOFOLLOW`): secret mounts such
// as Kubernetes projected volumes present files as symlinks, and the target is held to the same
// regular-file and size checks.
FileReadResult read_file_bounded(const std::string& path, std::size_t max_bytes) {
    FileReadResult r;
    // The read below is bounded by max_bytes + 1: refuse a bound that would wrap or exhaust memory.
    if (max_bytes >= (std::size_t{1} << 30))
        return r; // Unreadable
    int raw = -1;
    do {
        raw = ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    } while (raw < 0 && errno == EINTR);
    if (raw < 0) {
        if (errno == ENOENT || errno == ENOTDIR)
            r.status = FileReadResult::Status::Missing;
        return r;
    }
    const FdCloser fd{raw};
    struct stat st{};
    if (::fstat(fd.fd, &st) != 0 || !S_ISREG(st.st_mode))
        return r;
    if (st.st_size > 0 && static_cast<std::uintmax_t>(st.st_size) > max_bytes) {
        r.status = FileReadResult::Status::TooLarge;
        return r;
    }
    // Read at most one byte past the bound so a file that grew since fstat() is classified
    // TooLarge rather than silently truncated.
    std::string buf;
    std::array<char, 4096> chunk{};
    while (buf.size() <= max_bytes) {
        const std::size_t want = std::min(chunk.size(), max_bytes + 1 - buf.size());
        const ssize_t n = ::read(fd.fd, chunk.data(), want);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return r; // Unreadable
        }
        if (n == 0)
            break;
        buf.append(chunk.data(), static_cast<std::size_t>(n));
    }
    if (buf.size() > max_bytes) {
        r.status = FileReadResult::Status::TooLarge;
        return r;
    }
    r.status = FileReadResult::Status::Ok;
    r.content = std::move(buf);
    return r;
}

#else // _WIN32

FileReadResult read_file_bounded(const std::string& path, std::size_t max_bytes) {
    namespace fs = std::filesystem;
    FileReadResult r;
    // The buffer below is max_bytes + 1: refuse a bound that would wrap or exhaust memory.
    if (max_bytes >= (std::size_t{1} << 30))
        return r; // Unreadable
    std::error_code ec;
    const fs::file_status st = fs::status(path, ec);
    if (st.type() == fs::file_type::not_found) {
        r.status = FileReadResult::Status::Missing;
        return r;
    }
    if (ec || st.type() != fs::file_type::regular)
        return r;
    const std::uintmax_t size = fs::file_size(path, ec);
    if (ec)
        return r;
    if (size > max_bytes) {
        r.status = FileReadResult::Status::TooLarge;
        return r;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return r;
    // Read one byte past the bound so a file that grew since file_size() is classified
    // TooLarge rather than silently truncated.
    std::string buf(max_bytes + 1, '\0');
    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    const std::size_t got = static_cast<std::size_t>(in.gcount());
    if (in.bad())
        return r;
    if (got > max_bytes) {
        r.status = FileReadResult::Status::TooLarge;
        return r;
    }
    buf.resize(got);
    r.status = FileReadResult::Status::Ok;
    r.content = std::move(buf);
    return r;
}

#endif

std::expected<PinSet, std::string> load_boot_pins(const std::vector<std::string>& hex_pins,
                                                  const std::vector<std::string>& pin_files,
                                                  const std::string& auto_pin_file,
                                                  const FileReader& reader) {
    const FileReader& read = reader ? reader : FileReader{&read_file_bounded};
    std::vector<std::string> pins;
    std::vector<std::string> lacking; // distinct pins with no serverAuth source (see add_file)

    for (const auto& raw : hex_pins) {
        // A supplied value with no pin in it is an error, never "not supplied": falling through
        // would let a blank option select the auto-pin (or report a different problem).
        if (trim(raw).empty())
            return std::unexpected("gateway peer pin option supplied but contains no pin");
        auto pin = parse_pin_hex(raw);
        if (!pin)
            return std::unexpected("gateway peer pin '" + short_pin(raw) +
                                   "...' is not 64 hexadecimal characters (the SHA-256 of the "
                                   "gateway certificate's SubjectPublicKeyInfo)");
        push_unique(pins, std::move(*pin));
    }
    for (const auto& f : pin_files) {
        if (auto r = add_file(f, read, pins, lacking); !r)
            return std::unexpected(r.error());
    }
    // The auto-pin is the default ONLY: any explicit source, working or not, replaces it.
    if (hex_pins.empty() && pin_files.empty()) {
        if (auto r = add_file(auto_pin_file, read, pins, lacking); !r)
            return std::unexpected(r.error());
    }

    if (pins.empty())
        return std::unexpected("no gateway peer pin was configured, so every gateway-upstream call "
                               "would be denied");
    if (pins.size() > kMaxPins)
        return std::unexpected("more than " + std::to_string(kMaxPins) +
                               " gateway peer pins were configured across all sources");
    return PinSet{pins, lacking.size()};
}

} // namespace yuzu::server::gateway_peer
