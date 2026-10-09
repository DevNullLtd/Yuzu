# Vendored grpcbox (Yuzu patches: PKI PR5c, #1422, connection accessor)

This is a **vendored copy of grpcbox v0.17.1** (`github.com/tsloughter/grpcbox`,
the tag the gateway pins in `rebar.config` / `rebar.lock`), carried in `_checkouts/`
so rebar3 uses it in place of the fetched dependency. Only the **source** is
vendored (`src/`, `include/`, `rebar.config`, `LICENSE`); grpcbox's own deps
(chatterbox, ctx, acceptor_pool, gproc) are still fetched normally.

## The patch: three places

### 1. `src/grpcbox_pool.erl` — configurable listener mTLS strictness (PKI PR5c)

In `init/1` (search `YUZU PATCH`):

```erlang
%% before (stock v0.17.1):
{fail_if_no_peer_cert, true},
{verify, verify_peer},
%% after:
{fail_if_no_peer_cert, maps:get(fail_if_no_peer_cert, TransportOpts, true)},
{verify, maps:get(verify, TransportOpts, verify_peer)},
```

Stock grpcbox **hardcodes** `fail_if_no_peer_cert=true` + `verify=verify_peer` on
every TLS listener — i.e. every TLS listener is mutual TLS, with no
request-but-don't-require mode. That makes it impossible for an **unenrolled**
agent (which has no client cert until it completes CSR enrollment) to bootstrap
over a TLS gateway listener, forcing the agent↔gateway hop to stay plaintext.

The patch makes those two options read from the listener's `transport_opts` map,
**defaulting to the stock strict values** (so existing mTLS listeners are
unchanged). A listener can now opt into **one-way / server-authenticated TLS**:

```erlang
transport_opts => #{ssl => true, certfile => ..., keyfile => ..., cacertfile => ...,
                    verify => verify_none, fail_if_no_peer_cert => false}
```

which encrypts the hop + authenticates the gateway to the agent **without
requiring a client cert** — closing the plaintext agent↔gateway edge (a fleet-RCE
risk on an exposed gateway) while keeping bootstrap working. See
`docs/pki-architecture.md` "Gateway TLS".

### 2. `src/grpcbox_stream.erl` — streams with trailers already sent must not execute handlers (#1422)

In `on_receive_data/2` (search `YUZU PATCH`): one guard clause,

```erlang
on_receive_data(_, State=#state{trailers_sent=true}) ->
    {ok, State};
```

When `auth_fun` rejects the peer, stock v0.17.1 sends UNAUTHENTICATED trailers
(`end_stream` sets `trailers_sent=true`), but the method the service lookup stored
in the stream state stays set. The request's DATA frame then still reaches
`handle_message`, which **executes the service handler** for a unary or
server-streaming method and merely discards its response (`end_stream` is a no-op
once `trailers_sent=true`). This is not a race: a normal unary client sends its
HEADERS and DATA together, so it happens on every rejected call. For a peer the
mgmt-plane auth_fun rejected, that is an authorization bypass: the client sees
status 16 while the RPC's side effects (command fan-out!) still run. The guard
drops all data once `trailers_sent` is set. Regression-pinned by
`yuzu_gw_authz_rpc_tests` ("handler never runs" cases).

Only the `auth_fun` rejection path is an **authorization** bypass. The guard also
covers one post-admission path: a decode or handler error caught in
`on_receive_data` ends the stream with the method still set, so in stock a later
DATA frame from the (already admitted) peer runs the handler again while the
client has been told the call failed. Do not narrow the guard to the auth path.

Two other early ends are **not** covered. A `grpc-timeout` deadline
(DEADLINE_EXCEEDED) and a spawned handler process exiting both end the stream
from `handle_info`, which discards `end_stream`'s returned state, so
`trailers_sent` stays false. For a server-streaming method, later DATA then runs
the handler again; for client-streaming or bidi, it goes to the dead handler
process and runs nothing. Only an admitted peer can be affected: a rejected
stream already has `trailers_sent` set, so the guard drops its data even if the
deadline fires. This is stock behaviour that neither this patch nor
tsloughter/grpcbox#123 changes.

An unknown method (UNIMPLEMENTED) is not affected: the method is never stored, so
the stock `method=undefined` clause already drops the data.

Reported upstream as tsloughter/grpcbox#122, with the same fix and a regression
test in tsloughter/grpcbox#123. Still unfixed in v0.18.0, the latest release as of
2026-10-09.

### 3. `src/grpcbox_stream.erl`: typed accessors for the connection pid

Two exported functions, placed just above `ctx_with_stream/2` (search `YUZU PATCH`):

```erlang
-spec connection_pid(t()) -> pid().
connection_pid(#state{connection=Conn}) ->
    h2_stream_set:connection(Conn).

-spec connection_pid_from_ctx(ctx:t()) -> pid() | undefined.
connection_pid_from_ctx(Ctx) ->
    case ctx:get(Ctx, ctx_stream_key, undefined) of
        State=#state{} -> connection_pid(State);
        _ -> undefined
    end.
```

The stream state record is private to `grpcbox_stream`, so a service handler cannot
read the connection out of it. These accessors return the pid of the HTTP/2
connection process that carries the stream: every stream of one connection reports
the same pid and streams of different connections report different pids. A bidi
handler receives the stream state itself (use `connection_pid/1`); a unary handler
receives a ctx wrapping it (use `connection_pid_from_ctx/1`, which answers
`undefined` for a ctx with no stream such as `ctx:background()`). The gateway's
`yuzu_gw_conn` module is the only caller. The accessors read state only: they install
no authenticator and do not touch `auth_fun` (which stays forbidden on `:50051`).
The `connection_pid/1` spec refers to chatterbox's `h2_stream_set:stream_set()`, which is
why `gateway/rebar.config` lists `chatterbox` and `ssl` in the dialyzer `plt_extra_apps`.

## Integrity gate (machine-verifiable)

The exact change is committed as a canonical patch file,
`gateway/_checkouts/grpcbox.yuzu.patch`. **`gateway/scripts/verify-vendored-grpcbox.sh`**
re-clones upstream grpcbox at the `rebar.config`-pinned tag, applies that patch, and
diffs **every** vendored file against it — failing on any tamper, drift, or version
skew (so the only permitted difference between this vendor and pristine upstream is
the documented patch). It runs in CI (the `release.yml` gateway job, before compile)
and should be run on any re-sync:

```
bash gateway/scripts/verify-vendored-grpcbox.sh
```

## Re-syncing with upstream

This is intentionally a *minimal* vendor of a *pinned* tag. To move to a newer
grpcbox: re-copy `src/`+`include/`+`rebar.config`+`LICENSE` from the new tag,
re-apply `grpcbox.yuzu.patch` (or the three `YUZU PATCH` sites:
`grpcbox_pool.erl:init/1`, `grpcbox_stream.erl:on_receive_data/2` and the
`connection_pid` accessors in `grpcbox_stream.erl`, by hand), regenerate
`grpcbox.yuzu.patch` against the new stock, bump the `{tag, "vX.Y.Z"}` pin in
`rebar.config` (grpcbox stays OUT of `rebar.lock` — it is a checkout; rebar3
refuses to lock it), update `EXPECTED_SHA` in
`gateway/scripts/verify-vendored-grpcbox.sh` to the new tag's commit, run the
gateway suite + dialyzer, and re-run `verify-vendored-grpcbox.sh`. The
upstreaming target is making `verify`/`fail_if_no_peer_cert` configurable in
grpcbox itself (then this vendor can be dropped). Tracked with PR5c.

Patch 2 can be dropped only once the vendored release drops data on **every**
stream with `trailers_sent=true`, as tsloughter/grpcbox#123 does today. Check the
merged upstream code, not just the PR number, and keep `yuzu_gw_authz_rpc_tests`
either way.

Any re-sync to grpcbox v0.18.0 or later (chatterbox 0.16) must also handle the
chatterbox module rename: `h2_*` becomes `chatterbox_h2_*`. Three places use the
old names: patch 3's `connection_pid/1` (call and `-spec`), the dialyzer comment
on `h2_stream_set:stream_set()` in `gateway/rebar.config`, and
`apps/yuzu_gw/test/yuzu_gw_heartbeat_conn_drain_tests.erl`, which calls
`h2_stream_set:connection/1` and `h2_connection:send_frame/2` directly. A missed
rename in patch 3 does not crash: `yuzu_gw_conn` catches the `undef` and returns
`undefined`, and a session bound to `undefined` admits nothing, so every agent's
heartbeat is refused fleet-wide. Dialyzer and the conn-drain test catch it; do
not skip either.
