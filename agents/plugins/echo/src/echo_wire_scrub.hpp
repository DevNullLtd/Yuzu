// echo_wire_scrub.hpp -- make every collected identity string well-formed UTF-8 AT COLLECTION.
//
// Why this exists (WP07 / F16 follow-up). Echo's diff baselines are stored as JSON dumped with
// nlohmann's error_handler_t::replace (a strict dump throws on invalid UTF-8 and aborted the
// whole collect tick). `replace` turns each bad byte into U+FFFD, but the NEXT enumeration still
// holds the RAW bytes, so a name-keyed diff of (decoded baseline, raw current) never matches
// and emits a started/removed (or added/removed) pair EVERY tick: fabricated forensic events.
// The cure is to make the dump lossless: scrub the current set with scrub_wire_bytes ('?') BEFORE
// it is diffed or encoded. A well-formed string passes `replace` unchanged, so baseline and
// current agree byte for byte. Call these on the freshly enumerated set, before compute_*_events.
//
// Idempotent and cheap (a validation pass per string; a write only on a bad byte).
#pragma once

#include "echo_collectors.hpp"

#include <wire_utf8.hpp>

#include <string>
#include <vector>

namespace yuzu::echo {

inline void scrub_wire_strings(std::string& s) {
    if (yuzu::shared::count_invalid_wire_bytes(s) != 0)
        yuzu::shared::scrub_wire_bytes(s);
}

inline void scrub_wire_strings(NetConnection& c) {
    scrub_wire_strings(c.proto);
    scrub_wire_strings(c.local_addr);
    scrub_wire_strings(c.remote_addr);
    scrub_wire_strings(c.remote_host);
    scrub_wire_strings(c.state);
    scrub_wire_strings(c.process_name);
}
inline void scrub_wire_strings(ServiceInfo& s) {
    scrub_wire_strings(s.name);
    scrub_wire_strings(s.display_name);
    scrub_wire_strings(s.status);
    scrub_wire_strings(s.startup_type);
}
inline void scrub_wire_strings(UserSession& u) {
    scrub_wire_strings(u.user);
    scrub_wire_strings(u.domain);
    scrub_wire_strings(u.logon_type);
    scrub_wire_strings(u.session_id);
}
inline void scrub_wire_strings(SoftwareInfo& s) {
    scrub_wire_strings(s.name);
    scrub_wire_strings(s.version);
    scrub_wire_strings(s.publisher);
    scrub_wire_strings(s.install_date);
}
inline void scrub_wire_strings(ArpEntry& a) {
    scrub_wire_strings(a.iface);
    scrub_wire_strings(a.ip_address);
    scrub_wire_strings(a.mac_address);
    scrub_wire_strings(a.entry_type);
}
inline void scrub_wire_strings(DnsEntry& d) {
    scrub_wire_strings(d.name);
    scrub_wire_strings(d.record_type);
    scrub_wire_strings(d.data);
    scrub_wire_strings(d.source);
}
inline void scrub_wire_strings(MapDriveEntry& m) {
    scrub_wire_strings(m.direction);
    scrub_wire_strings(m.local_mount);
    scrub_wire_strings(m.remote_path);
    scrub_wire_strings(m.remote_host);
    scrub_wire_strings(m.username);
    scrub_wire_strings(m.provider);
}
inline void scrub_wire_strings(yuzu::agent::ProcessInfo& p) {
    scrub_wire_strings(p.name);
    scrub_wire_strings(p.user);
}

template <class T>
inline void scrub_wire_strings(std::vector<T>& v) {
    for (auto& e : v)
        scrub_wire_strings(e);
}

} // namespace yuzu::echo
