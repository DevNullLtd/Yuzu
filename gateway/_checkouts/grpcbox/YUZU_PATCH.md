# Vendored grpcbox (Yuzu patches — PKI PR5c + #1422)

This is a **vendored copy of grpcbox v0.17.1** (`github.com/tsloughter/grpcbox`,
the tag the gateway pins in `rebar.config` / `rebar.lock`), carried in `_checkouts/`
so rebar3 uses it in place of the fetched dependency. Only the **source** is
vendored (`src/`, `include/`, `rebar.config`, `LICENSE`); grpcbox's own deps
(chatterbox, ctx, acceptor_pool, gproc) are still fetched normally.

## The patch — two places

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

### 2. `src/grpcbox_stream.erl` — terminated streams must not execute handlers (#1422)

In `on_receive_data/2` (search `YUZU PATCH`): one guard clause,

```erlang
on_receive_data(_, State=#state{trailers_sent=true}) ->
    {ok, State};
```

Stock v0.17.1 terminates a stream server-side (auth_fun rejection →
UNAUTHENTICATED, unknown method → UNIMPLEMENTED) by sending trailers — but any
DATA frame already in flight still reaches `handle_message`, which **executes
the service handler** and merely discards its response (`end_stream` is a no-op
once `trailers_sent=true`). For a peer the mgmt-plane auth_fun rejected, that is
an authorization bypass: the client sees status 16 while the RPC's side effects
(command fan-out!) still run. The guard drops all data on a terminated stream.
Regression-pinned by `yuzu_gw_authz_rpc_tests` ("handler never runs" cases).

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
re-apply `grpcbox.yuzu.patch` (or the two `YUZU PATCH` sites — `grpcbox_pool.erl:init/1`
and `grpcbox_stream.erl:on_receive_data/2` — by hand), regenerate `grpcbox.yuzu.patch` against the new
stock, bump the `{tag, "vX.Y.Z"}` pin in `rebar.config` (grpcbox stays OUT of
`rebar.lock` — it is a checkout; rebar3 refuses to lock it), update `EXPECTED_SHA`
in `gateway/scripts/verify-vendored-grpcbox.sh` to the new tag's commit, run the
gateway suite + dialyzer, and re-run `verify-vendored-grpcbox.sh`. The upstreaming target is making
`verify`/`fail_if_no_peer_cert` configurable in grpcbox itself (then this vendor can
be dropped). Tracked with PR5c.
