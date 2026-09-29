/**
 * privacy_permissions_plugin.cpp -- per-app sensitive-permission grant visibility
 * (camera/microphone/location/full-disk-access equivalents), read-only. One action,
 * `permissions`, emitting `permissions|<os>|<app_id>|<category>|<state>|<raw>|<last_used_start>
 * |<last_used_stop>` rows (the leading field is the YAML's `row_kind` column; states and the
 * row contract in privacy_permissions_parsers.hpp):
 *   Linux:   xdg-desktop-portal PermissionStore.Lookup over the agent's OWN session bus (rung 1)
 *   macOS:   the system TCC.db + every /Users home's per-user TCC.db, read-only, in-process
 *            sqlite3 over one descriptor with an immutable URI (rung 1)
 *   Windows: PLANNED, follows as its own PR: HKLM ProfileList -> each real profile's
 *            ConsentStore (live HKU hive or offline NTUSER.DAT mount) + the HKLM
 *            ...\CapabilityAccessManager\ConsentStore mirror (rung 1)
 *
 * The Windows leg is a placeholder: it reports ONE whole-source row (category "-", state
 * `unsupported`, `windows:planned` in `raw`) and result status UNAVAILABLE/PARTIAL with
 * `windows:planned` as the provenance, never an empty success -- never claimed working the way
 * the Linux leg's own "no session bus" case is (UNAVAILABLE/FULL, portal:unavailable -- a real,
 * complete answer about that one mechanism; see privacy_permissions_legs.hpp's banner for why
 * the two are deliberately different). The macOS leg is real: a TCC-protected read reports
 * `denied` per source, never collapsed into the Windows leg's whole-source placeholder shape.
 *
 * Default-off (Forensics class, same posture as execution_artifacts) -- the server-side
 * kill-switch seed (server.cpp) gates whether this plugin's dispatch is even reachable; this
 * plugin performs no authz itself.
 *
 * WHY (stated plainly): no business or compliance driver is documented for this plugin. See
 * README "Caveats and known gaps".
 *
 * Portable except the dispatch #if; all three descriptor legs are declared unconditionally so
 * the capability-matrix generator sees one shape everywhere.
 */

#include <string>
#include <string_view>

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include "privacy_permissions_legs.hpp"

namespace {

#if defined(_WIN32)
constexpr std::string_view kInternalErrorRow = yuzu::privacy_permissions::kInternalErrorRowWindows;
#elif defined(__linux__)
constexpr std::string_view kInternalErrorRow = yuzu::privacy_permissions::kInternalErrorRowLinux;
#elif defined(__APPLE__)
constexpr std::string_view kInternalErrorRow = yuzu::privacy_permissions::kInternalErrorRowMacos;
#else
#error "privacy_permissions: unsupported platform"
#endif

const YuzuActionDescriptor kActionDescriptors[] = {
    {"permissions",
     /* linux_leg   = */
     {YUZU_SUPPORT_CONSTRAINED, 1,
      "xdg-desktop-portal org.freedesktop.impl.portal.PermissionStore.Lookup over the agent "
      "process's own session bus (sd_bus_open_user)",
      "never another user's session: a system-service agent has no session bus in every shipped "
      "deployment and reports unavailable, which says nothing about interactive users' grants; "
      "only portal-mediated grants are visible (an app opening the device directly never "
      "appears); full_disk_access is unsupported (no portal equivalent)"},
     /* macos_leg   = */
     {YUZU_SUPPORT_CONSTRAINED, 1,
      "TCC.db read-only, in-process sqlite3 over one descriptor with an immutable URI (no lock, "
      "no -journal/-wal/-shm ever opened or created; a WAL-mode or journal-bearing file is "
      "refused, and a file that changes during the read is discarded): the system /Library/Application Support/"
      "com.apple.TCC/TCC.db plus each /Users/<home> (uid >= 500) per-user "
      "Library/Application Support/com.apple.TCC/TCC.db",
      "every TCC.db is TCC-protected: without Full Disk Access each read is denied; camera and "
      "microphone grants normally live in the per-user dbs; per-user rows report what that user's "
      "own TCC.db records, not what tccd enforces; homes outside /Users or on a network mount "
      "are not read; location is unsupported (locationd, outside TCC)"},
     /* windows_leg = */
     {YUZU_SUPPORT_PLANNED, 1,
      "HKLM ProfileList enumeration, then each real profile's "
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore via its "
      "loaded HKU\\<SID> hive or an offline NTUSER.DAT mount (RegLoadKeyW, SeBackup/SeRestore), "
      "plus the same HKLM ConsentStore path",
      "follows as its own PR"}},
};

} // namespace

class PrivacyPermissionsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "privacy_permissions"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Per-app sensitive-permission grants -- camera, microphone, location, "
               "full-disk-access equivalents (read-only)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"permissions", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        namespace pp = yuzu::privacy_permissions;
        // Frozen seam: nothing may escape the plugin ABI (the SDK trampoline does not catch),
        // so the whole body, the unknown-action row included, sits inside the one try.
        try {
            if (action != pp::kPermissionsAction) {
                ctx.write_output("unknown action: " + yuzu::util::safe_output_field(action));
                return 1;
            }
#if defined(_WIN32)
            return pp::collect_windows_permissions(ctx);
#elif defined(__linux__)
            return pp::collect_linux_permissions(ctx);
#elif defined(__APPLE__)
            return pp::collect_macos_permissions(ctx);
#endif
            return 1;
        } catch (...) {
            // Same 8-field shape as a data row (row_kind `constrained`), so the YAML columns
            // still line up. No formatting here; the SDK wrapper copies, so the writes are guarded.
            try {
                ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                      YUZU_RESULT_COMPLETENESS_PARTIAL, "internal_error");
                ctx.write_output(kInternalErrorRow);
            } catch (...) {
            }
            return 1;
        }
    }
};

YUZU_PLUGIN_EXPORT(PrivacyPermissionsPlugin)
