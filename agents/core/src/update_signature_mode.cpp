#include <yuzu/agent/update_signature_mode.hpp>

#include <yuzu/agent/detached_signature.hpp> // probe_trust_bundle, signature_refusal_reason

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <exception>
#include <format>
#include <memory>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <win_str.hpp> // yuzu::win::from_wide (CP_UTF8), docs/cpp-conventions.md
#elif defined(__APPLE__)
#include <crt_externs.h> // _NSGetEnviron(): a dylib cannot rely on the `environ` symbol
#endif

#if !defined(_WIN32) && !defined(__APPLE__)
// Declared at TRUE FILE SCOPE, outside every namespace, for the reason given in
// subprocess_runner.cpp: an extern inside a namespace mangles into that
// namespace and does not bind to libc's unmangled global.
extern char** environ;
#endif

namespace yuzu::agent {
namespace {

char ascii_upper(char c) noexcept {
    return static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
}

bool iequals_ascii(std::string_view a, std::string_view b) noexcept {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return ascii_upper(x) == ascii_upper(y);
           });
}

bool istarts_with_ascii(std::string_view s, std::string_view prefix) noexcept {
    return s.size() >= prefix.size() && iequals_ascii(s.substr(0, prefix.size()), prefix);
}

} // namespace

std::vector<std::string> unrecognised_update_env_names(std::span<const std::string> env_names,
                                                       bool names_case_insensitive) {
    std::vector<std::string> out;
    for (const auto& name : env_names) {
        if (!istarts_with_ascii(name, kUpdateEnvPrefix))
            continue;
        const bool recognised = std::any_of(
            std::begin(kRecognisedUpdateEnvNames), std::end(kRecognisedUpdateEnvNames),
            [&](std::string_view known) {
                return names_case_insensitive ? iequals_ascii(name, known) : name == known;
            });
        if (!recognised)
            out.push_back(name);
    }
    return out;
}

std::vector<std::string> process_environment_names() {
    std::vector<std::string> names;
#ifdef _WIN32
    // Owned block, released on every exit path including an exception from the
    // string/vector work below (same RAII shape as subprocess_runner.cpp BR-004).
    struct EnvironmentStringsDeleter {
        void operator()(wchar_t* p) const noexcept {
            if (p)
                ::FreeEnvironmentStringsW(p);
        }
    };
    std::unique_ptr<wchar_t, EnvironmentStringsDeleter> block{::GetEnvironmentStringsW()};
    if (!block)
        return names; // reporting only: an unreadable environment just skips the check
    for (const wchar_t* p = block.get(); *p != L'\0';) {
        const std::wstring_view entry{p};
        p += entry.size() + 1;
        // "=C:=C:\\..." per-drive pseudo-entries are not settable variable names.
        if (entry.empty() || entry.front() == L'=')
            continue;
        const auto eq = entry.find(L'=');
        const auto name = entry.substr(0, eq == std::wstring_view::npos ? entry.size() : eq);
        names.push_back(yuzu::win::from_wide(name.data(), static_cast<int>(name.size())));
    }
#else
#if defined(__APPLE__)
    char** env = *_NSGetEnviron();
#else
    char** env = ::environ;
#endif
    if (!env)
        return names;
    for (char** e = env; *e != nullptr; ++e) {
        const std::string_view entry{*e};
        const auto eq = entry.find('=');
        names.emplace_back(entry.substr(0, eq == std::string_view::npos ? entry.size() : eq));
    }
#endif
    return names;
}

std::vector<UpdateSignatureStartupLine> build_update_signature_startup_lines(
    const UpdateConfig& cfg, std::span<const std::string> env_names, bool names_case_insensitive) {
    std::vector<UpdateSignatureStartupLine> lines;
    const auto mode = update_signature_mode(cfg);
    const auto mode_name = update_signature_mode_name(mode);

    if (mode == UpdateSignatureMode::kOff) {
        lines.push_back(
            {false, std::format("OTA update signature mode: {} (no update trust bundle "
                                "configured; update binaries are NOT signature-checked)",
                                mode_name)});
    } else {
        const std::string bundle = cfg.signature_trust_bundle.string();
        lines.push_back({false, std::format("OTA update signature mode: {} (trust bundle: {})",
                                            mode_name, bundle)});
        // NO bundle probe here (#5249 Gate 7): this runs before the Windows SCM
        // hand-off. The probe runs on the OTA update thread instead
        // (log_update_trust_bundle_probe, agent.cpp step 4b).
    }

    for (const auto& name : unrecognised_update_env_names(env_names, names_case_insensitive)) {
        lines.push_back(
            {true, std::format("Environment variable '{}' starts with {} but is not an option this "
                               "agent reads, so it is ignored. Check the spelling: a misspelt "
                               "update-signing variable leaves signing in the mode logged above.",
                               name, kUpdateEnvPrefix)});
    }
    return lines;
}

void log_update_signature_startup_report(const UpdateConfig& cfg) noexcept {
    try {
        const auto env_names = process_environment_names();
        for (const auto& line :
             build_update_signature_startup_lines(cfg, env_names, kEnvNamesCaseInsensitive)) {
            if (line.warning)
                spdlog::warn("{}", line.text);
            else
                spdlog::info("{}", line.text);
        }
    } catch (const std::exception& e) {
        try {
            spdlog::warn("OTA update signature startup report skipped: {} (reporting only; "
                         "signature enforcement is unaffected)",
                         e.what());
        } catch (...) {}
    } catch (...) {
        try {
            spdlog::warn("OTA update signature startup report skipped: non-standard exception "
                         "(reporting only; signature enforcement is unaffected)");
        } catch (...) {}
    }
}

std::optional<UpdateSignatureStartupLine> update_trust_bundle_warning(const UpdateConfig& cfg) {
    const auto mode = update_signature_mode(cfg);
    if (mode == UpdateSignatureMode::kOff)
        return std::nullopt;
    const auto err = probe_trust_bundle(cfg.signature_trust_bundle);
    if (!err)
        return std::nullopt;
    std::string text = std::format(
        "OTA update trust bundle cannot be loaded as of this check: {}. Every SIGNED update will "
        "be REFUSED (reason={}) until it loads",
        err->detail, signature_refusal_reason(err->kind));
    text += mode == UpdateSignatureMode::kBundle
                ? "; unsigned updates are still accepted because --update-require-signature is off."
                : ".";
    return UpdateSignatureStartupLine{true, std::move(text)};
}

void log_update_trust_bundle_probe(const UpdateConfig& cfg) noexcept {
    try {
        if (const auto line = update_trust_bundle_warning(cfg))
            spdlog::warn("{}", line->text);
    } catch (const std::exception& e) {
        try {
            spdlog::warn("OTA update trust bundle check skipped: {} (reporting only; signature "
                         "enforcement is unaffected)",
                         e.what());
        } catch (...) {}
    } catch (...) {
        try {
            spdlog::warn("OTA update trust bundle check skipped: non-standard exception "
                         "(reporting only; signature enforcement is unaffected)");
        } catch (...) {}
    }
}

} // namespace yuzu::agent
