#include "multi_host_dsn.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <cstdlib>
#include <map>
#include <memory>
#include <string_view>

namespace yuzu::server::pg {

namespace {

using OptionsPtr = std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)>;
using Values = std::map<std::string, std::string, std::less<>>;

constexpr std::string_view kTsa = "target_session_attrs";

/// libpq's own `target_session_attrs` values. Only these are ever echoed in the
/// refusal: an unparsed value could be a DSN fragment carrying a password.
constexpr std::string_view kKnownTsaValues[] = {"any",     "read-write", "read-only",
                                                "primary", "standby",    "prefer-standby"};

std::size_t list_len(std::string_view v) {
    return v.empty() ? 0 : static_cast<std::size_t>(std::count(v.begin(), v.end(), ',')) + 1;
}

/// Parse with libpq. libpq's error text is owned and freed, never read: it can
/// echo a DSN fragment, including part of a password (e.g. a bad percent-escape).
OptionsPtr parse(const std::string& dsn) {
    char* errmsg = nullptr;
    OptionsPtr opts(PQconninfoParse(dsn.c_str(), &errmsg), &PQconninfoFree);
    const std::unique_ptr<char, decltype(&PQfreemem)> errmsg_owner(errmsg, &PQfreemem);
    return opts;
}

/// Every option the DSN sets (a non-null value), keyed by libpq keyword.
Values values_of(const PQconninfoOption* o) {
    Values v;
    for (; o->keyword != nullptr; ++o)
        if (o->val != nullptr)
            v.emplace(o->keyword, o->val);
    return v;
}

std::string_view get(const Values& v, std::string_view key) {
    const auto it = v.find(key);
    return it == v.end() ? std::string_view{} : std::string_view{it->second};
}

/// Rebuild a keyword/value DSN from libpq's own parse, every value single-quoted
/// (libpq escapes `'` and `\` with a backslash inside quotes). Appending text to
/// the operator's string instead is fragile: a keyword value ending in an
/// unquoted `\` swallows the appended pair, a URI with a raw `?` in the password
/// puts it inside the host list, and a URI ending in `?`/`&` stops parsing
/// (Gate 8 round 5, all reproduced against libpq 16).
std::string rebuild_with_read_write(const Values& v) {
    std::string out;
    for (const auto& [key, val] : v) {
        if (key == kTsa)
            continue;
        out += key;
        out += '=';
        out += quote_conninfo_value(val);
        out += ' ';
    }
    out += kTsa;
    out += "='read-write'";
    return out;
}

} // namespace

std::string quote_conninfo_value(std::string_view value) {
    std::string out = "'";
    for (const char ch : value) {
        if (ch == '\'' || ch == '\\')
            out += '\\';
        out += ch;
    }
    out += '\'';
    return out;
}

std::expected<void, std::string> check_effective_connection(PGconn* conn,
                                                            std::size_t listed_hosts) {
    if (conn == nullptr)
        return std::unexpected(std::string("no connection to check"));
    const OptionsPtr info(PQconninfo(conn), &PQconninfoFree);
    if (!info)
        return std::unexpected(std::string("could not read the connection's settings"));
    const Values v = values_of(info.get());
    const std::string_view lbh = get(v, "load_balance_hosts");
    if (!lbh.empty() && lbh != "disable")
        return std::unexpected(
            std::string("load_balance_hosts") + (lbh == "random" ? "=random" : "") +
            " is set in the Postgres connection settings and is not supported for the server: "
            "remove it (check the service file and environment too), or set "
            "load_balance_hosts=disable.");
    const std::size_t hosts = std::max<std::size_t>(
        {list_len(get(v, "host")), list_len(get(v, "hostaddr")), listed_hosts, 1});
    const std::string_view tsa = get(v, kTsa);
    if (hosts >= 2 && tsa != "read-write" && tsa != "primary") {
        const bool known = std::ranges::find(kKnownTsaValues, tsa) != std::end(kKnownTsaValues);
        return std::unexpected(
            "the Postgres connection settings list " + std::to_string(hosts) + " hosts with " +
            (tsa.empty() || tsa == "any"
                 ? std::string("target_session_attrs=any (or none set)")
                 : "target_session_attrs=" +
                       (known ? std::string(tsa) : std::string("<unrecognised>"))) +
            ": set target_session_attrs=read-write where the host list is defined, so the "
            "server only connects to a writable primary.");
    }
    return {};
}

std::expected<MultiHostDsn, std::string> enforce_multi_host_read_write(const std::string& dsn) {
    MultiHostDsn out{.dsn = dsn};
    // An unset DSN stays unset: the server refuses to start on it (ADR-0006/0007
    // fail closed). Rewriting it would hand back a non-empty DSN that connects
    // wherever the libpq environment points (Gate 8 round 5, architect F1).
    if (dsn.empty())
        return out;
    const OptionsPtr opts = parse(dsn);
    if (!opts)
        return out; // unparseable: unchanged; the pool fails it at boot
    const Values v = values_of(opts.get());

    // A host list or load-balancing setting may come from the environment when
    // the DSN names none (libpq falls back to it the same way).
    bool hosts_from_env = false;
    auto with_env = [&](std::string_view key, const char* env, bool* from_env) {
        if (auto s = get(v, key); !s.empty())
            return s;
        const char* e = std::getenv(env);
        if (e == nullptr || *e == '\0')
            return std::string_view{};
        if (from_env != nullptr)
            *from_env = true;
        return std::string_view{e};
    };
    const std::string_view host = with_env("host", "PGHOST", &hosts_from_env);
    const std::string_view hostaddr = with_env("hostaddr", "PGHOSTADDR", &hosts_from_env);
    const std::string_view lbh = with_env("load_balance_hosts", "PGLOADBALANCEHOSTS", nullptr);
    const std::string_view tsa = get(v, kTsa); // empty counts as absent, as in libpq
    out.hosts = std::max<std::size_t>({list_len(host), list_len(hostaddr), 1});
    out.hosts_from_env = hosts_from_env && out.hosts > 1;

    // load_balance_hosts: REFUSED (operator decision, Gate 8 round 6). libpq then
    // shuffles hosts (and a name's addresses) for every new pool connection,
    // while the /readyz probe holds one connection — so a host that fails some
    // new connections cannot show on /readyz. With read-write there is only one
    // acceptable host anyway, so the shuffle balances nothing.
    if (!lbh.empty() && lbh != "disable") {
        const bool known = lbh == "random";
        const bool env = get(v, "load_balance_hosts").empty();
        return std::unexpected(
            std::string("load_balance_hosts") + (known ? "=" + std::string(lbh) : std::string()) +
            (env ? " (from PGLOADBALANCEHOSTS)" : "") +
            " is not supported for the server's Postgres connection: the server writes to "
            "one primary, and /readyz cannot see a host that fails only some of the pool's "
            "connections. Remove it, or set load_balance_hosts=disable.");
    }
    if (out.hosts < 2)
        return out;
    if (tsa == "read-write" || tsa == "primary")
        return out;
    if (!tsa.empty()) {
        const bool known = std::ranges::find(kKnownTsaValues, tsa) != std::end(kKnownTsaValues);
        return std::unexpected(
            "a multi-host Postgres DSN needs target_session_attrs=read-write "
            "(or primary); " +
            (known ? "'" + std::string(tsa) + "'" : std::string("the value given")) +
            " lets the server's connections land on a server that cannot take writes, which "
            "/readyz cannot detect. Remove target_session_attrs (the server then uses "
            "read-write) or set it to read-write.");
    }

    // Rebuild, then prove it: the new DSN must parse, carry read-write, and set
    // every other option exactly as the operator's did. Anything else refuses boot
    // rather than run on a DSN that says something different.
    std::string rebuilt = rebuild_with_read_write(v);
    const OptionsPtr check = parse(rebuilt);
    Values expect = v;
    expect[std::string(kTsa)] = "read-write";
    if (!check || values_of(check.get()) != expect)
        return std::unexpected(
            "could not add target_session_attrs=read-write to the multi-host Postgres DSN "
            "without changing its meaning; set target_session_attrs=read-write in the DSN "
            "yourself.");
    out.dsn = std::move(rebuilt);
    out.appended = true;
    return out;
}

} // namespace yuzu::server::pg
