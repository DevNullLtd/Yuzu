# WP14B: one-month pin rule waived for cowboy 2.21.0, cowlib 2.22.0 and gun 2.8.0 (2026-11-18)

## What was waived

`gateway/rebar.config` pins gateway dependencies to a release at least one month old (a window
meant to catch supply-chain tampering and bad releases). That rule is waived for exactly three
packages and versions:

| Package | Version | Released | Lock `pkg_hash` (inner) | Lock `pkg_hash_ext` (outer, sha256 of the tarball) |
|---|---|---|---|---|
| cowboy | 2.21.0 | 2026-11-09 | `16BEFCB9B60E81119C2AA5864D33B1494855138C71A2D0C95E4D878D850FDE71` | `90B4D6FE91806054538349DBEABCAC86315A3FDAEC4EB491F5445259668398F6` |
| cowlib | 2.22.0 | 2026-11-09 | `ED32663B11E0B96C4FC2E7D42CF627CD095F006E78A24D0C6B98A91F2E532CD3` | `B1EA5995D8F1AB5086AE7AFE710C2075C7872C7E1ACAF45DD0DB7595E900C0FC` |
| gun | 2.8.0 | 2026-11-09 | `556A7CA0EB399BA4597A40F540F3EDB0F004D2A06984339F19B81AB3C557CF36` | `21A7C716F472FC5BC2C2BBCB2EC74FFA5D20D8073DC712ACD054862B0A5176D8` |

It does **not** extend to any other package. ranch stays at 2.3.0 (2.4.0 exists but is also inside
the window and is not needed). The rule applies to every other pin, and to any later bump of these
three.

Base: merge-base `98c26bcee3` (`origin/dev` when the branch was cut).

## Who, when, and why

- **Fraser Jarvis, owner**, direct ruling 2026-11-17 (cowboy and cowlib): "Waive the pin rule for
  cowboy and cowlib, record that I approved this as we must get away from the version(s) with
  CVE".
- **Fraser Jarvis, owner**, direct ruling 2026-11-18 (gun): "Extend the waiver".

**Approver and author are the same person; there is no second approver.** The change was reviewed
by the governance gates (independence is asserted, not verified).

Why: cowlib 2.21.0 and earlier do not enforce `SETTINGS_MAX_HEADER_LIST_SIZE`
(CVE-2026-113431, published 2026-11-06 by the EEF CNA as EEF-CVE-2026-113431: "Unbounded decoded
HTTP/2 header-list size in cowlib `cow_http2_machine` enables HPACK amplification memory
exhaustion"; CVSS v4 `AV:N/AC:L/AT:N/PR:N/UI:N/VA:H`; affected cowlib 2.7.0 up to but not
including 2.22.0; advisory <https://cna.erlef.org/cves/CVE-2026-113431.html>, also
<https://nvd.nist.gov/vuln/detail/CVE-2026-113431> and <https://osv.dev/vulnerability/EEF-CVE-2026-113431>,
read through the OSV API on 2026-11-18; the advisory's fix commits include the tag commit
`b92326f0`; the behaviour is also verified empirically by the before/after regression pin below), so an unauthenticated peer on the agent-facing gateway listener can send an
HPACK header block that decodes to an unbounded header list. The fix exists only in cowlib 2.22.0
(released 2026-11-09), and cowboy 2.21.0 requires cowlib >= 2.22.0. gun is included because gun
2.5.0 cannot run on cowlib 2.22.0: cowlib's `cow_http2_machine:frame/2` can now return
`{window_changed, Increment, State}` (DATA on a stream the client already reset, a rejected header
list), gun 2.5.0's `case` has no clause for it and the gun connection process crashes. In this tree
that surfaced as a failing existing test (`yuzu_grpc_client_tests:oversize_multi_frame_response_is_abandoned`)
and the gateway cancels streams (`gun:cancel`, `yuzu_grpc_client.erl`). gun 2.8.0 adds the clause and
requires cowlib >= 2.22.0.

## Compensating checks performed

All tarballs were fetched from `https://repo.hex.pm/tarballs/<name>-<vsn>.tar` into an empty scratch
directory, extracted only there, and never executed; scripts ran with `python3 -I`.

1. **Outer checksum**: sha256 of each whole tarball equals the lock's `pkg_hash_ext` for cowboy
   2.21.0, cowlib 2.22.0 and gun 2.8.0 (and for the replaced gun 2.5.0).
2. **Inner checksum, recomputed independently**: sha256 over the tarball's `VERSION`,
   `metadata.config` and `contents.tar.gz` members, concatenated in that order (the hex package
   spec), upper-cased. It equals both the tarball's `CHECKSUM` member and the lock's `pkg_hash` for
   all three packages (and gun 2.5.0). This verifies the tarballs match what the lock records; it
   does not prove the registry itself was not compromised before the lock was written.
3. **Upstream comparison** (GitHub `ninenines/<pkg>` at the release tag against the extracted hex
   contents):
   - cowboy 2.21.0 and gun 2.8.0: every file in the tarball is byte-identical to the tag (the tag
     has extra repository-only files).
   - cowlib 2.22.0: `src/`, `include/` and `ebin/cowlib.app` are identical to the tag;
     `Makefile` and `README.asciidoc` differ. The signed tag `2.22.0` points at commit
     `b92326f0`. The release commit `49bd2119` ("Cowlib 2.22.0", one minute after the tag) is a
     SIBLING of it, not a descendant: both have parent `e04ee626`, the tag sits on a side commit and
     `49bd2119` is on master. `49bd2119` changes only `Makefile` (`PROJECT_VERSION`, the hex doc
     link, three lines in the `prepare_tag` info target that echo the README links),
     `README.asciidoc` (the 2.22 doc link) and `ebin/cowlib.app` (the version). The hex tarball is
     **byte-identical to `49bd2119`** (checked: no file differs). The two later commits (`1b95bb1c`
     and `457a520f`, 2026-11-17) descend from `49bd2119` and are not in the tarball. Reading: the
     published release is the master commit, not the tagged one; the difference is benign (a dev
     info target and doc links) but it is a real tag-versus-tarball difference, recorded here
     rather than assumed away.
4. **Source diff review** (read from the extracted tarballs):
   - cowlib 2.21.0 to 2.22.0: `Makefile`, `erlang.mk` (diff skimmed for added code: dev tooling only),
     `cow_http2.erl`, `cow_http2_machine.erl`, `cow_http_te.erl`, `cow_http_hd.erl`,
     `cow_http_struct_hd.erl`, `cow_http.erl`/`cow_inline.hrl` (diff existence and the added-line
     grep only for `cow_http.erl`).
   - cowboy 2.19.0 to 2.21.0: `cowboy_http2.erl` (full diff), `cowboy_http.erl`, `cowboy_clock.erl`,
     `cowboy_metrics_h.erl`, `cowboy_router.erl`, `cowboy_static.erl`, `Makefile`, `rebar.config`.
     `cowboy_rest.erl` and `cowboy_websocket.erl` were read only in part (first hunks); the gateway
     uses none of REST, websocket, static or router (it calls `cowboy:start_clear/start_tls` and
     implements the `cowboy_stream` behaviour), so they are not on its code path.
   - gun 2.5.0 to 2.8.0: `Makefile`, `rebar.config`, `erlang.mk`, `gun.erl`, `gun_http2.erl`,
     `gun_http.erl`, `gun_protocols.erl`, `gun_tls_proxy.erl`. `gun_cookies*`, `gun_pool*`,
     `gun_ws`, `gun_tunnel`, `gun_socks`, `gun_sse_h`, `gun_public_suffix` were NOT read line by line
     (the gateway uses none of them: it calls `gun:open/post/get/await/await_up/cancel/flush/close`);
     for those the check was a grep of every added line for `os:cmd`, `open_port`, `httpc`,
     `binary_to_term`, `spawn`, `on_load`, `file:`, `code:`, `persistent_term`, `apply(`: no hits.
   - The same grep over the added lines of cowlib's and cowboy's `src/` and `include/` found
     nothing; the only `file:read_file` additions are inside `-ifdef(TEST)`.
   - Result: no new dependency (cowlib and ranch only; gun still depends on cowlib only), no
     build-time code in `rebar.config`, nothing that runs code at load, no network or file access
     outside tests. Findings were behaviour and API changes (below), none suspicious.
5. **Behaviour changes relevant to the gateway** (all exercised by the tests below):
   - cowlib 2.22.0 enforces `max_header_list_size`, default 32768 when unset (this is the fix).
     The listeners set nothing; `yuzu_grpc_listener_tests:http2_header_list_bound_test_` pins it.
     The check runs after the whole HPACK block is decoded, so decode itself is bounded only by
     `max_fragmented_header_block_size` and the table size; that is not tested here, so `http2.max_headers` (Cowboy's count limit, 100 headers) and `max_fragmented_header_block_size` must stay at their defaults: they are the other half of the bound.
   - `cow_http2:frame/0` gains a 5-tuple DATA form and `settings/0` is widened; dialyzer is clean.
   - gun 2.8.0: handles `window_changed`; rejects CR/LF/NUL in method, path and header names/values
     and an invalid `content-length` on the request side (the gateway sends neither); stricter
     HTTP/1.1 response parsing (affects only the CRL fetch client); ALPN now errors when the server
     selects a protocol that was not offered, while a missing ALPN with the single offered `http2`
     still yields `http2` (the gateway offers `[http2]` only); `cacerts` default now unconditional
     `public_key:cacerts_get()` (OTP 25+; the toolchain is OTP 28).
   - cowboy 2.21.0: HEAD responses end at the header block; an early response with an open request
     body now resets the stream with `no_error`; `cowboy_bstr` and `cowboy_clock:stop/0` removed
     (the gateway uses neither).

## Tests run on the final tree (cowboy 2.21.0, cowlib 2.22.0, gun 2.8.0)

- Full gateway eunit (`rebar3 eunit --dir apps/yuzu_gw/test`): 2835 passed, 0 failed (re-run after the governance-round fixes; the first run was 2832),
  including `yuzu_grpc_client_tests` (23/23, in particular the oversize multi-frame abandon case that
  failed on gun 2.5.0 with cowlib 2.22.0) and the new tests below.
- `rebar3 dialyzer`: no warnings. `gateway/scripts/check-proto-codegen.sh`: OK.
- `rebar3 ct --dir apps/yuzu_gw/test/ct`: integration (19), e2e (5), fullstack (5), prometheus (5),
  metrics_e2e (4) suites all passed. The perf and scale suites were not run.
- New tests: `yuzu_grpc_listener_tests:http2_header_list_bound_test_` (no listener override; server
  SETTINGS advertise 32768; 8 x 4000-octet headers accepted, 9 refused) and
  `yuzu_grpc_wire_tests:header_list_over_limit` (a REAL Cowboy listener: nine 4000-octet
  `user-agent` headers, about 2.5 KB of HPACK on the wire, are refused with RST_STREAM
  `enhance_your_calm`, the handler is never called, and the same connection serves the next
  request).
- Mutation check of the committed pins against cowlib 2.21.0's modules (compiled in a scratch
  directory and put first on the code path): the SETTINGS-preface, over-bound and real-listener
  tests go RED; the no-override, within-bound, allow-list, `max_headers` and early-reset tests stay
  green by design. Also added: an under-limit control in the wire test (the handler count must not
  move on a refusal), and a wire test that a trailers-only gRPC status survives Cowboy's early reset
  of an open request body (3 repeat runs green).
- Before/after on the same scratch probe against a live listener: with cowlib 2.21.0's modules
  loaded, 8, 9 and 40 copies (a 160 KB header list) were all accepted and reached the handler; with
  2.22.0, 9 copies are refused and the connection stays usable. The old-library run is a one-off
  scratch probe (not committed): it shows the pre-fix acceptance, not memory growth.

## What could not be done

- No independent verification of the packages beyond the checks above (no reproducible build of
  the hex tarballs, no review of cowlib 2.22.0's unreleased follow-up commits).
- The remaining diffs listed above as not read line by line were not read.
- Memory growth under the pre-fix library was not measured.
- A longer cancel/late-DATA soak against the real yuzu-server was not run; the unit suite exercises
  the gun cancel path only against the gateway's own listener.

## When the rule resumes

The newest of the three releases is 2026-11-09; the one-month rule would have admitted them from
**2026-12-09**. From that date, and for any later bump of these packages, the one-month rule applies
again unchanged. The comment in `gateway/rebar.config` names this waiver and its limits.
