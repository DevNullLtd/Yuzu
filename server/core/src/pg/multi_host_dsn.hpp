#pragma once

/// @file multi_host_dsn.hpp
/// HA WS-8: the server refuses to run a multi-host Postgres DSN that could put
/// its connections on a server that cannot take writes.
///
/// WHY. With `host=n1,n2,n3` and no `target_session_attrs`, libpq takes the
/// FIRST host that accepts a connection — a standby included. The pool then
/// holds connections whose writes fail, and nothing the `/readyz` probe does can
/// see all of them (it holds one connection; the pool holds many, possibly on
/// different hosts). Governance rounds 2–4 of WS-8 found four HIGH false-green
/// shapes, all this one root cause. The documented HA pattern
/// (docs/user-manual/ha-postgres.md) already sets
/// `target_session_attrs=read-write`; this makes it the enforced behaviour.
///
/// POLICY (operator decisions, 2026-09-24):
///   - an EMPTY DSN: unchanged (the server refuses to start on it, ADR-0007);
///   - `load_balance_hosts` set to anything but `disable` (in the DSN or
///     `PGLOADBALANCEHOSTS`), with any number of hosts: REFUSED. libpq would
///     shuffle hosts and addresses for every new pool connection while the
///     /readyz probe holds one connection, so a host failing some new
///     connections could never show; with read-write only one host is
///     acceptable, so the shuffle balances nothing (Gate 8 round 6);
///   - one host: unchanged;
///   - multi-host with NO `target_session_attrs` (or an empty one): the DSN is
///     REBUILT as a keyword/value DSN from libpq's own parse, every value
///     quoted, with `target_session_attrs=read-write` added, and re-parsed to
///     prove every other option is unchanged — never string-appended (Gate 8
///     round 5: an unquoted trailing `\`, a raw `?` in a URI password, or a URI
///     ending in `?`/`&` each defeated or broke an append). A DSN keyword
///     overrides a `PGTARGETSESSIONATTRS` environment value, so the
///     environment cannot weaken it;
///   - multi-host with `read-write` or `primary`: unchanged;
///   - multi-host with any other value (`any`, `read-only`, `standby`,
///     `prefer-standby`, or anything unrecognised): REFUSED — the caller exits
///     with the returned message.
/// A host list that arrives through `PGHOST`/`PGHOSTADDR` counts. What only
/// libpq sees — a `service=`/`PGSERVICE` entry (or anything else resolved at
/// connect time) — is checked by `check_effective_connection` on the first
/// pooled connection at boot (Gate 8 round 7: a service-file
/// `load_balance_hosts=random` bypassed this DSN-only check). Residual, not
/// seen by either: a SINGLE host name that resolves to several servers (DNS
/// round-robin, a headless service) — set `target_session_attrs=read-write`
/// explicitly for those.
///
/// The error message never contains the DSN (it can carry a password), and
/// echoes the offending `target_session_attrs` / `load_balance_hosts` value
/// only when it is one of libpq's own values.

#include <libpq-fe.h>

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>

namespace yuzu::server::pg {

struct MultiHostDsn {
    std::string dsn;            ///< the DSN to use (rebuilt when `appended`)
    bool appended{false};       ///< true when target_session_attrs=read-write was added
    std::size_t hosts{1};       ///< hosts seen (DSN list, else PGHOST/PGHOSTADDR)
    bool hosts_from_env{false}; ///< the multi-host list came from PGHOST/PGHOSTADDR
};

/// Apply the policy above. An empty or unparseable DSN is returned unchanged
/// (the server reports it at boot, as before).
std::expected<MultiHostDsn, std::string> enforce_multi_host_read_write(const std::string& dsn);

/// The same policy, applied to the settings libpq actually RESOLVED for a live
/// connection (`PQconninfo`: DSN, environment and any `service=` file), for
/// what the DSN-only check above cannot see: `load_balance_hosts` other than
/// `disable` is refused, and a host list of two or more needs
/// `target_session_attrs` of `read-write` or `primary` (nothing can be added
/// here — it came from outside the DSN). main.cpp runs it on the auth
/// bootstrap pool's first connection and refuses to start on an error; the
/// readiness probe runs it on every new connection of its own (libpq re-reads a
/// service file on each connect) and reports not-ready on an error.
/// `listed_hosts`: how many hosts the caller's full list had, when `conn` was made
/// over a narrowed list (the probe's restart after a silent host) — the
/// read-write rule follows the list the pool walks, not the narrowed one.
std::expected<void, std::string> check_effective_connection(PGconn* conn,
                                                            std::size_t listed_hosts = 0);

/// `value` as a single-quoted libpq keyword/value conninfo value (`'` and `\`
/// backslash-escaped). Shared by the DSN rebuild here and the readiness probe's
/// restart, so neither ever string-appends to an operator's DSN.
std::string quote_conninfo_value(std::string_view value);

} // namespace yuzu::server::pg
