#!/usr/bin/env python3
"""Self-test for tests/test_response_store_read_tripwire.py (#4990).

A tripwire that has never been seen to fail proves nothing. This runs the tripwire's checks against
mutated copies of the real header and source tree (held in memory, nothing on disk is touched) and
asserts each mutation is caught: a new unlisted read, a read that lost its ResponseTierFilter, a
defaulted filter, a stale list entry, a fifth internal-consumer site, a vanished site, a
reintroduced marker, a parameter that only mentions the filter's name, and the literal-unrestricted
spellings `exclude(set, std::nullopt)` and `for_fixed_plugin_poll(nullptr)`, including their wrapped
forms (`VisibleSet(std::nullopt)`, `{std::nullopt}`, `std::optional<...>(std::nullopt)`, a
`static_cast<...>(...)`, a C-style cast, extra parentheses, a null plugin set under a cast) and a
same-file alias of the filter type. It also pins the comment stripper against the string literal that
would otherwise hide call sites from the scan. Stdlib only.
"""
from __future__ import annotations

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "response_store_read_tripwire", os.path.join(HERE, "test_response_store_read_tripwire.py"))
t = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = t
spec.loader.exec_module(t)

FAILURES: list[str] = []


def expect(cond: bool, what: str) -> None:
    if not cond:
        FAILURES.append(what)
        print(f"FAIL: {what}", file=sys.stderr)


def with_extra_public(header: str, decl: str) -> str:
    anchor = "    void reap_expired();"
    assert anchor in header, "selftest anchor moved: update the selftest"
    return header.replace(anchor, anchor + "\n    " + decl, 1)


def any_mentions(errors: list[str], needle: str) -> bool:
    return any(needle in e for e in errors)


def main() -> int:
    header = open(os.path.join(t.REPO_ROOT, t.STORE_HEADER), encoding="utf-8").read()
    server = t._read_tree(t.REPO_ROOT, "server")

    # The unmutated tree is clean (the tripwire itself is green).
    expect(t.check_store_reads(header) == [], "real header must pass CHECK 1")
    expect(t.check_internal_sites(server) == [], "real tree must pass CHECK 2")
    expect(t.check_forbidden_markers(server) == [], "real tree must pass CHECK 3")
    expect(t.check_unrestricted_idioms(server) == [], "real tree must pass CHECK 2b")
    expect(len(t.INTERNAL_CONSUMER_SITES) == 4, "the frozen internal-consumer list is four sites")

    # CHECK 1 mutations.
    errs = t.check_store_reads(with_extra_public(
        header, "[[nodiscard]] std::optional<int> bogus_read(const std::string& id) const;"))
    expect(any_mentions(errs, "bogus_read"), "an unlisted new method must fail")

    errs = t.check_store_reads(with_extra_public(
        header, "std::size_t peek(const ResponseTierFilter& tier) const;"))
    expect(any_mentions(errs, "peek"), "an unlisted method taking a filter must fail")

    stripped = header.replace(
        "query_by_ids(const std::vector<int64_t>& response_ids, const ResponseTierFilter& tier) const;",
        "query_by_ids(const std::vector<int64_t>& response_ids) const;", 1)
    expect(stripped != header, "selftest anchor moved: query_by_ids declaration")
    expect(any_mentions(t.check_store_reads(stripped), "query_by_ids"),
           "a read that lost its ResponseTierFilter must fail")

    defaulted = header.replace("total_count(const ResponseTierFilter& tier) const;",
                               "total_count(const ResponseTierFilter& tier = ResponseTierFilter::"
                               "unrestricted_internal_consumer()) const;", 1)
    expect(defaulted != header, "selftest anchor moved: total_count declaration")
    expect(any_mentions(t.check_store_reads(defaulted), "default value"),
           "a defaulted filter must fail")

    removed = header.replace("    void reap_expired();", "", 1)
    expect(any_mentions(t.check_store_reads(removed), "reap_expired"),
           "a stale frozen-list entry must fail")

    # A parameter that merely mentions the filter's name is not the filter.
    lookalike = header.replace(
        "query_by_ids(const std::vector<int64_t>& response_ids, const ResponseTierFilter& tier) const;",
        "query_by_ids(const std::vector<int64_t>& response_ids, int ResponseTierFilterCount) const;", 1)
    expect(lookalike != header, "selftest anchor moved: query_by_ids declaration (lookalike)")
    expect(any_mentions(t.check_store_reads(lookalike), "query_by_ids"),
           "a parameter that only names the filter type must fail")
    byvalue = header.replace(
        "query_by_ids(const std::vector<int64_t>& response_ids, const ResponseTierFilter& tier) const;",
        "query_by_ids(const std::vector<int64_t>& response_ids, ResponseTierFilter tier) const;", 1)
    expect(any_mentions(t.check_store_reads(byvalue), "query_by_ids"),
           "a by-value filter parameter must fail")

    # A comment mentioning a method is not a method.
    commented = with_extra_public(header, "// bogus_read(const std::string& id) const;")
    expect(t.check_store_reads(commented) == [], "a commented-out declaration must not count")

    # CHECK 2 mutations.
    extra = dict(server)
    extra["server/core/src/new_surface.cpp"] = (
        "auto rows = store_->query_by_execution(exec_id,\n"
        "    ResponseTierFilter::unrestricted_internal_consumer());\n")
    expect(any_mentions(t.check_internal_sites(extra), "new_surface.cpp"),
           "an eighth internal-consumer site must fail")

    fewer = {k: v for k, v in server.items() if not k.endswith("preflight_eval.cpp")}
    expect(any_mentions(t.check_internal_sites(fewer), "preflight_eval.cpp"),
           "a vanished internal-consumer site must fail")

    # The three sites that were fixed must not come back.
    for name in ("policy_evaluator.cpp", "bundle_orchestrator.cpp"):
        again = dict(server)
        again[f"server/core/src/{name}"] = (
            "auto rows = d_.response_store->query_by_execution(f.execution_id,\n"
            "    ResponseTierFilter::unrestricted_internal_consumer());\n")
        expect(any_mentions(t.check_internal_sites(again), name),
               f"re-adding an internal-consumer call to {name} must fail")

    # CHECK 2b: the literal-unrestricted spellings.
    def idiom(text: str) -> list[str]:
        d = dict(server)
        d["server/core/src/idiom.cpp"] = text
        return t.check_unrestricted_idioms(d)

    expect(any_mentions(idiom("auto f = ResponseTierFilter::exclude(*set, std::nullopt);"), "idiom.cpp"),
           "exclude(set, std::nullopt) must fail")
    expect(any_mentions(idiom("auto f = ResponseTierFilter::exclude(*set, authz::VisibleSet{});"), "idiom.cpp"),
           "exclude(set, authz::VisibleSet{}) must fail")
    expect(any_mentions(idiom("auto f = ResponseTierFilter::exclude(*set, {});"), "idiom.cpp"),
           "exclude(set, {}) must fail")
    expect(any_mentions(idiom("auto f = ResponseTierFilter::exclude(*set, authz::VisibleSet());"), "idiom.cpp"),
           "exclude(set, authz::VisibleSet()) must fail")
    expect(any_mentions(idiom("auto f = ResponseTierFilter::exclude(*set, authz::VisibleSet{std::nullopt});"),
                        "idiom.cpp"),
           "exclude(set, authz::VisibleSet{std::nullopt}) must fail")
    expect(any_mentions(idiom("auto f = ResponseTierFilter::exclude(*set, "
                              "std::optional<std::unordered_set<std::string>>{});"), "idiom.cpp"),
           "exclude(set, std::optional<...>{}) must fail")
    expect(any_mentions(idiom("auto f = ResponseTierFilter::exclude(*set, "
                              "std::optional<std::unordered_set<std::string>>());"), "idiom.cpp"),
           "exclude(set, std::optional<...>()) must fail")
    expect(any_mentions(idiom("auto f = ResponseTierFilter::exclude(*set, std::nullopt_t());"), "idiom.cpp"),
           "exclude(set, std::nullopt_t()) must fail")
    for spelling in (
            "authz::VisibleSet(std::nullopt)",
            "authz::VisibleSet{std::nullopt}",
            "{std::nullopt}",
            "std::optional<std::unordered_set<std::string>>(std::nullopt)",
            "std::optional<std::unordered_set<std::string>>{std::nullopt}",
            "static_cast<authz::VisibleSet>(std::nullopt)",
            "static_cast<std::optional<std::unordered_set<std::string>>>(std::nullopt)",
            "static_cast<authz::VisibleSet>(authz::VisibleSet{})",
            "(authz::VisibleSet)std::nullopt",
            "(std::nullopt)",
            "((std::nullopt))",
            "static_cast<authz::VisibleSet>((std::nullopt))",
            # Spellings that wrap the literal in a leading-scope qualifier or a braced initializer.
            "::yuzu::server::authz::VisibleSet{std::nullopt}",
            "::yuzu::server::authz::VisibleSet{}",
            "::std::nullopt",
            "::std::optional<std::unordered_set<std::string>>{}",
            "authz::VisibleSet{std::nullopt,}",
            "{std::nullopt,}",
            "std::move(std::optional<authz::VisibleSet>{})",
            "std::move(authz::VisibleSet{})",
            "::std::move(std::nullopt)",
            "auto{std::nullopt}",
            "auto(std::nullopt)",
            "decltype(vis){}",
            "decltype(vis)()"):
        expect(any_mentions(idiom(f"auto f = ResponseTierFilter::exclude(*set, {spelling});"), "idiom.cpp"),
               f"exclude(set, {spelling}) must fail")
    # Whitespace around `::`, a line splice, a bare nullopt after a using-declaration
    # in the same file, and an alias of an alias.
    for spelling in ("std :: nullopt", "std:: nullopt", "std ::nullopt", ":: std :: nullopt",
                     "std :: optional<std::unordered_set<std::string>>{}",
                     "authz :: VisibleSet{}", "static_cast<authz::VisibleSet>(std :: nullopt)"):
        expect(any_mentions(idiom(f"auto f = ResponseTierFilter::exclude(*set, {spelling});"), "idiom.cpp"),
               f"exclude(set, {spelling}) must fail")
    expect(any_mentions(idiom("auto f = ResponseTierFilter::exclude(*set, std::nullo\\\npt);"), "idiom.cpp"),
           "a backslash-newline splice inside std::nullopt must not hide it")
    expect(any_mentions(idiom("auto f = ResponseTierFilter::exclude(*set, std::nul\\\r\nlopt);"), "idiom.cpp"),
           "a CRLF line splice inside std::nullopt must not hide it")
    for using, spelling in (("using std::nullopt;", "nullopt"),
                            ("using ::std::nullopt;", "nullopt"),
                            ("using namespace std;", "nullopt"),
                            ("using std::nullopt_t;", "nullopt_t()"),
                            ("using std::optional;", "optional<std::unordered_set<std::string>>{}"),
                            ("using namespace std;", "authz::VisibleSet{nullopt}")):
        expect(any_mentions(idiom(f"{using}\nauto f = ResponseTierFilter::exclude(*set, {spelling});"),
                            "idiom.cpp"),
               f"after '{using}', exclude(set, {spelling}) must fail")
    # The two features together: a using-declaration AND whitespace around `::`.
    for using in ("using std::nullopt;", "using namespace std;"):
        for spelling in ("std :: nullopt", "std:: nullopt", "std ::nullopt", "std::\nnullopt",
                         "static_cast<authz::VisibleSet>(std :: nullopt)",
                         "static_cast<authz :: VisibleSet>(std:: nullopt)",
                         "std :: optional<std::unordered_set<std::string>>{}"):
            expect(any_mentions(idiom(f"{using}\nauto f = ResponseTierFilter::exclude(*set, {spelling});"),
                                "idiom.cpp"),
                   f"after '{using}', exclude(set, {spelling!r}) must fail")
    expect(idiom("using namespace std;\nauto f = ResponseTierFilter::exclude(*set, std :: nullopt_like);") == [],
           "a using-declaration with spaced `::` does not turn an unrelated name into the literal")
    expect(idiom("auto f = ResponseTierFilter::exclude(*set, nullopt);") == [],
           "a bare nullopt WITHOUT a using-declaration is some other symbol, not flagged")
    expect(idiom("using std::nullopt;\nauto f = ResponseTierFilter::exclude(*set, nullopt_like);") == [],
           "a using-declaration does not turn an unrelated name into the literal")
    expect(any_mentions(idiom("using A = ResponseTierFilter;\nusing B = A;\n"
                              "auto f = B::exclude(*set, std::nullopt);"), "idiom.cpp"),
           "an alias of an alias of the filter type must not hide exclude(set, nullopt)")
    expect(any_mentions(idiom("using A = yuzu::server::ResponseTierFilter;\ntypedef A B;\nusing C = const B;\n"
                              "auto f = C::exclude(*set, {});"), "idiom.cpp"),
           "a chain of using/typedef aliases must not hide exclude(set, {})")
    expect(idiom("using A = ResponseTierFilter;\nusing B = Other;\nauto f = B::exclude(*set, std::nullopt);") == [],
           "an alias of an unrelated type is not the filter")
    for fixed in ("static_cast<const ForensicsPluginSet*>(nullptr)",
                  "(const ForensicsPluginSet*)nullptr",
                  "static_cast<const yuzu::server::ForensicsPluginSet*>((nullptr))",
                  "NULL", "0", "{}", "(nullptr)"):
        expect(any_mentions(idiom(f"auto f = ResponseTierFilter::for_fixed_plugin_poll({fixed});"), "idiom.cpp"),
               f"for_fixed_plugin_poll({fixed}) must fail")
    # A same-file alias of the filter type is searched too.
    expect(any_mentions(idiom("using RTF = ResponseTierFilter;\nauto f = RTF::exclude(*set, std::nullopt);"),
                        "idiom.cpp"), "an alias (using) of the filter type must not hide exclude(set, nullopt)")
    expect(any_mentions(idiom("using RTF = yuzu::server::ResponseTierFilter;\n"
                              "auto f = RTF::exclude(*set, static_cast<authz::VisibleSet>(std::nullopt));"),
                        "idiom.cpp"), "a qualified alias must not hide a wrapped nullopt")
    expect(any_mentions(idiom("typedef ResponseTierFilter RTF;\nauto f = RTF::exclude(*set, {});"),
                        "idiom.cpp"), "an alias (typedef) of the filter type must not hide exclude(set, {})")
    expect(idiom("using RTF = ResponseTierFilter;\nauto f = RTF::exclude(*set, authz::deny_all());") == [],
           "an alias with a real visibility argument is not flagged")
    # Real (non-literal) arguments, with and without wrappers, are never flagged.
    expect(idiom("auto f = ResponseTierFilter::exclude(*set, static_cast<authz::VisibleSet>(ids));") == [],
           "a cast of a variable is not the unrestricted literal")
    expect(idiom("auto f = ResponseTierFilter::exclude(*set, (fn)(req));") == [],
           "a call through a parenthesised callable is not the unrestricted literal")
    expect(idiom("auto f = ResponseTierFilter::exclude(*set, std::optional<std::unordered_set<std::string>>(ids));")
           == [], "std::optional<...>(<variable>) is a real set, not the unrestricted literal")
    expect(idiom("auto f = ResponseTierFilter::for_fixed_plugin_poll(static_cast<const ForensicsPluginSet*>"
                 "(forensics_plugins()));") == [],
           "a cast of the accessor is not the null literal")
    expect(idiom("auto f = ResponseTierFilter::exclude(*set, authz::VisibleSet{ids});") == [],
           "exclude(set, VisibleSet{<non-empty>}) is a real set, not the unrestricted literal")
    for real in ("::yuzu::server::authz::deny_all()", "std::move(ids)", "std::move(authz::deny_all())",
                 "auto{ids}", "decltype(vis){ids}", "::authz::VisibleSet{ids}",
                 "authz::VisibleSet{std::nullopt_like}"):
        expect(idiom(f"auto f = ResponseTierFilter::exclude(*set, {real});") == [],
               f"exclude(set, {real}) is a real argument, not the unrestricted literal")
    expect(any_mentions(idiom("auto f = ResponseTierFilter::for_fixed_plugin_poll(nullptr);"), "idiom.cpp"),
           "for_fixed_plugin_poll(nullptr) must fail")
    expect(idiom("auto f = ResponseTierFilter::exclude(*set, authz::deny_all());") == [],
           "exclude(set, deny_all()) is the sanctioned spelling")
    expect(idiom("auto f = ResponseTierFilter::exclude(*set, fn ? fn(req) : authz::deny_all());") == [],
           "exclude(set, <variable expression>) is the tier_filter_for shape")
    expect(idiom("auto f = ResponseTierFilter::for_fixed_plugin_poll(forensics_plugins());") == [],
           "for_fixed_plugin_poll(<accessor>) is allowed")
    expect(idiom("// ResponseTierFilter::exclude(*set, std::nullopt)\n") == [],
           "a comment is not a construction")

    # The definition header is not a call site, and a comment is not a call.
    only_comment = dict(server)
    only_comment["server/core/src/c.cpp"] = "// ResponseTierFilter::unrestricted_internal_consumer()\n"
    expect(t.check_internal_sites(only_comment) == [], "a comment is not an internal-consumer call")

    # A string literal containing "/*" must not hide the code after it.
    sneaky = dict(server)
    sneaky["server/core/src/sneaky.cpp"] = (
        'const char* k = "/api/*";\n'
        "auto rows = store_->query(id, ResponseTierFilter::unrestricted_internal_consumer());\n"
        "/* a real comment */\n")
    expect(any_mentions(t.check_internal_sites(sneaky), "sneaky.cpp"),
           "a call after a string containing /* must still be found")

    # CHECK 3 mutations.
    for marker in t.FORBIDDEN_MARKERS:
        bad = dict(server)
        bad["server/core/src/x.cpp"] = f"// {marker}\n"
        expect(any_mentions(t.check_forbidden_markers(bad), marker), f"{marker} must fail")

    if FAILURES:
        return 1
    print("OK: the #4990 read tripwire fails on every mutation it is meant to catch")
    return 0


if __name__ == "__main__":
    sys.exit(main())
