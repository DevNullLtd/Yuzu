#!/usr/bin/env python3
"""nft-spoof-probe.py — capability-holding netlink sender-verification harness.

WHAT THIS PROVES. firewall_plugin.cpp's nftables backend defends against a
non-kernel process injecting forged NFT_MSG_NEW* rows into an nftables dump
reply by checking the SENDER of every received datagram: recvmsg()'s own
msg_name (an AF_NETLINK sockaddr the kernel itself fills in — see
firewall_plugin.cpp, the recvmsg block around `rsa.nl_pid != 0`) must show
nl_pid == 0, because only the kernel's own netlink replies carry that portid.
This script proves that check actually rejects a delivered forgery, by being
the forger.

WHY IT RUNS AS CAP_NET_ADMIN IN A THROWAWAY NETWORK NAMESPACE, NOT AS AN
UNPRIVILEGED PROCESS. The obvious "run as nobody, needs no privilege" design
is undeliverable and was rejected (review R1): a UNICAST netlink send to a
NONZERO destination portid over NETLINK_NETFILTER is gated by the kernel's
own netlink_allowed(sock, NL_CFG_F_NONROOT_SEND) check
(net/netlink/af_netlink.c), and nfnetlink's netlink_kernel_cfg
(net/netfilter/nfnetlink.c) declares NO .flags — so it never opts in to
non-root unicast. An unprivileged sender gets EPERM before the forged
datagram ever reaches the agent's socket, and the live assertion would read
"SPOOFED absent" both before and after a fix, for the wrong reason (the
kernel blocked the send, not the agent's filter). Running as CAP_NET_ADMIN
inside an `unshare --net` namespace clears that unrelated kernel gate (the
permission check, not the thing under test) while ALSO guaranteeing the
forged unicast can never touch the host's real nftables state — the
namespace's netlink is a private plane, wired only to this script and
whatever agent process the operator also placed in it.

WHAT THIS SCRIPT NEVER DOES. It never issues an NFT_MSG_NEWCHAIN (or any
NFT_MSG_NEW*/DEL*/GETSET) request against the REAL nftables ruleset — it only
hand-crafts raw netlink BYTES and writes them directly to a peer socket's
bound portid with sendto(); nftables' kernel-side ADD/DELETE machinery is
never invoked because this is not a request the kernel is asked to act on,
it is a forged REPLY aimed at a userspace listener. This is a read-path
adversarial harness, not a mutation tool.

THE FORGED FIXTURE IS A BASE CHAIN, NOT A BARE TABLE+NAME (review R2). A
NEWCHAIN carrying only NFTA_CHAIN_TABLE/NFTA_CHAIN_NAME is silently skipped
by try_nftables_rules()'s `!is_base_chain` guard (firewall_plugin.cpp) and
never surfaces in output — the spoof would be undetectable even if the
sender check were absent. This script therefore always attaches
NFTA_CHAIN_HOOK (making parse_nft_chains() set is_base_chain=true) and
NFTA_CHAIN_POLICY=NF_DROP (so nft_has_content() flips the state verdict to
"active" and format_nft_chain_rule_row() emits a `rule|nftables|...|SPOOFED|
...` row) — a spoof, if the sender check were absent or broken, is
observable.

POSITIVE-CONTROL PROTOCOL (the-rig/CI only, not this Mac). Run this script
against an UNPATCHED agent .so first: the forged NEWCHAIN must actually
surface (a "SPOOFED" chain row, or the state verdict flipping to active) —
that is the positive control proving the datagram was genuinely delivered
and would have fooled a naive parser. Only then is the SAME delivered
forgery run against the PATCHED .so, where it must be silently dropped
(nl_pid != 0) and "SPOOFED" must never appear. A negative result against the
unpatched .so alone proves nothing; the pair is the assertion.

USAGE (inside a throwaway netns, as a CAP_NET_ADMIN process):
    unshare --net --map-root-user -- \\
        python3 scripts/dev/nft-spoof-probe.py --target-pid <agent-portid>

    # or let the script discover the target from /proc/net/netlink:
    unshare --net --map-root-user -- \\
        python3 scripts/dev/nft-spoof-probe.py --duration 10

Discovery reads ONLY /proc/net/netlink (never a process listing, never
/proc/<pid>/fd) and looks for NETLINK_NETFILTER (protocol 12) sockets with a
nonzero bound portid; pass --target-pid explicitly when more than one
candidate is present or discovery is ambiguous.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

# ── linux/netlink.h ─────────────────────────────────────────────────────
NLMSG_DONE = 0x3
NLM_F_MULTI = 0x2
NLA_ALIGNTO = 4

# ── linux/netfilter/nfnetlink.h ─────────────────────────────────────────
NETLINK_NETFILTER = 12
NFNL_SUBSYS_NFTABLES = 10

# ── linux/netfilter/nf_tables.h ─────────────────────────────────────────
NFT_MSG_NEWCHAIN = 3

NFTA_CHAIN_TABLE = 1
NFTA_CHAIN_NAME = 3
NFTA_CHAIN_HOOK = 4
NFTA_CHAIN_POLICY = 5

NFTA_HOOK_HOOKNUM = 1

NF_DROP = 0

# nfproto family (linux/netfilter.h) — NFPROTO_INET default, matching
# firewall_parsers.hpp's nft_family_name() table.
NFPROTO_INET = 1

# NF_INET_* hook numbers (linux/netfilter.h), mirrored by
# firewall_parsers.hpp's nft_hook_name(): 0=prerouting 1=input 2=forward
# 3=output 4=postrouting.
DEFAULT_HOOKNUM = 1  # NF_INET_LOCAL_IN ("input")

SPOOFED_CHAIN_NAME = "SPOOFED"


def _nft_msg_type(subtype: int) -> int:
    """Packs the NFNETLINK subsystem into the high byte, subtype into the low
    byte — mirrors firewall_parsers.hpp's nft_msg_type()."""
    return (NFNL_SUBSYS_NFTABLES << 8) | subtype


def _pad4(n: int) -> int:
    return (n + (NLA_ALIGNTO - 1)) & ~(NLA_ALIGNTO - 1)


def _nla_string(attr_type: int, value: str) -> bytes:
    """One NUL-terminated string nlattr, 4-byte aligned."""
    raw = value.encode("utf-8") + b"\x00"
    hdr = struct.pack("<HH", 4 + len(raw), attr_type)
    body = hdr + raw
    return body + b"\x00" * (_pad4(len(body)) - len(body))


def _nla_be32(attr_type: int, value: int) -> bytes:
    """One big-endian u32 nlattr — nftables' own numeric-attribute
    convention (see firewall_parsers.hpp's byte-order note), distinct from
    the little-endian nlattr HEADER fields."""
    hdr = struct.pack("<HH", 4 + 4, attr_type)
    body = hdr + struct.pack(">I", value)
    return body + b"\x00" * (_pad4(len(body)) - len(body))


def _nla_nested(attr_type: int, inner: bytes) -> bytes:
    hdr = struct.pack("<HH", 4 + len(inner), attr_type)
    body = hdr + inner
    return body + b"\x00" * (_pad4(len(body)) - len(body))


def build_spoofed_newchain(
    seq: int,
    dst_portid: int,
    table: str,
    chain_name: str,
    hooknum: int,
    family: int = NFPROTO_INET,
) -> bytes:
    """Builds one forged NFT_MSG_NEWCHAIN datagram: nlmsghdr (host order) +
    nfgenmsg (host order) + attributes (NFTA_CHAIN_TABLE/NAME/HOOK/POLICY,
    numeric values big-endian) — the exact shape parse_nft_chains() in
    firewall_parsers.hpp decodes, with NFTA_CHAIN_HOOK present (so
    is_base_chain becomes true) and NFTA_CHAIN_POLICY=NF_DROP (so
    nft_has_content() reads this ruleset as active). `dst_portid` is the
    header's own `pid` field — set to 0 to mimic a genuine kernel reply, the
    exact value the sender-trust check (recvmsg's msg_name, not this field)
    is defending against being trusted on its own.
    """
    nfgenmsg = struct.pack("<BBH", family, 0, 0)  # family, version, res_id (unused)

    hook_inner = _nla_be32(NFTA_HOOK_HOOKNUM, hooknum)
    attrs = (
        _nla_string(NFTA_CHAIN_TABLE, table)
        + _nla_string(NFTA_CHAIN_NAME, chain_name)
        + _nla_nested(NFTA_CHAIN_HOOK, hook_inner)
        + _nla_be32(NFTA_CHAIN_POLICY, NF_DROP)
    )

    payload = nfgenmsg + attrs
    total_len = 16 + len(payload)
    # dst_portid mimics the kernel's own reply pid (0) at the PROTOCOL level;
    # this is cosmetic forgery of the message body only — it cannot forge the
    # socket-level sender identity recvmsg()'s msg_name reports, which is
    # exactly what makes the sender-trust check effective.
    hdr = struct.pack(
        "<IHHII",
        total_len,
        _nft_msg_type(NFT_MSG_NEWCHAIN),
        NLM_F_MULTI,
        seq,
        0,
    )
    return hdr + payload


def build_done(seq: int) -> bytes:
    """NLMSG_DONE with a zeroed dump_done_errno body (post-v4.13 shape;
    parse_nft_done_errno() in firewall_parsers.hpp treats a too-short/absent
    body as ok too, so this is the stricter of the two accepted forms)."""
    payload = struct.pack("<i", 0)
    hdr = struct.pack("<IHHII", 16 + len(payload), NLMSG_DONE, 0, seq, 0)
    return hdr + payload


def discover_target_portid() -> int | None:
    """Reads ONLY /proc/net/netlink (per this harness's boundary — never a
    process listing) for a bound NETLINK_NETFILTER (protocol 12) socket with
    a nonzero portid. Returns None, prompting --target-pid, when the file is
    unreadable or the match is not exactly one row."""
    try:
        with open("/proc/net/netlink", "r", encoding="ascii") as f:
            lines = f.read().splitlines()
    except OSError as exc:
        print(f"nft-spoof-probe: cannot read /proc/net/netlink: {exc}", file=sys.stderr)
        return None

    if not lines:
        return None

    candidates = []
    for line in lines[1:]:  # header row: "sk  Eth Pid ..."
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            proto = int(fields[1])
            portid = int(fields[2], 16) if fields[2].lower().startswith("0x") else int(fields[2])
        except ValueError:
            continue
        if proto == NETLINK_NETFILTER and portid != 0:
            candidates.append(portid)

    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        print("nft-spoof-probe: no NETLINK_NETFILTER socket found in /proc/net/netlink",
              file=sys.stderr)
    else:
        print(
            "nft-spoof-probe: multiple NETLINK_NETFILTER sockets found "
            f"({candidates}) — pass --target-pid explicitly",
            file=sys.stderr,
        )
    return None


def run(args: argparse.Namespace) -> int:
    target_portid = args.target_pid or discover_target_portid()
    if target_portid is None:
        return 2

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    sock.bind((args.portid, 0))
    # BR-06: the --duration budget above only checks the clock BETWEEN
    # sendto() calls; a blocking sendto (the peer stops draining its receive
    # queue) is otherwise unbounded and the script would overrun its
    # advertised duration. A short send timeout, well under the 0.05s
    # inter-send sleep, keeps every iteration's own worst case negligible.
    sock.settimeout(1.0)
    src_portid = sock.getsockname()[0]

    print(
        f"nft-spoof-probe: unicasting forged NEWCHAIN(table={args.table!r}, "
        f"name={SPOOFED_CHAIN_NAME!r}, hook={args.hooknum}, policy=drop) "
        f"from portid={src_portid} to portid={target_portid} for "
        f"{args.duration}s"
    )

    seq = 1
    deadline = time.monotonic() + args.duration
    sent = 0
    try:
        while time.monotonic() < deadline:
            datagram = build_spoofed_newchain(
                seq, target_portid, args.table, SPOOFED_CHAIN_NAME, args.hooknum
            ) + build_done(seq)
            try:
                sock.sendto(datagram, (target_portid, 0))
                sent += 1
            except OSError as exc:
                print(f"nft-spoof-probe: sendto failed: {exc}", file=sys.stderr)
                return 1
            seq += 1
            time.sleep(0.05)
    finally:
        sock.close()

    print(f"nft-spoof-probe: sent {sent} forged datagrams. Positive-control assertion "
          "(the-rig/CI, not this Mac): pre-fix .so must surface SPOOFED for a "
          "delivered forgery; the patched .so must never surface it for the "
          "same delivered forgery.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Forges NFT_MSG_NEWCHAIN base-chain datagrams and unicasts them at "
            "a target netlink portid to prove the agent's recvmsg sender-trust "
            "check (nl_pid==0) rejects a delivered non-kernel forgery. Requires "
            "CAP_NET_ADMIN inside an isolated network namespace (unshare --net) "
            "— an unprivileged unicast to a nonzero NETLINK_NETFILTER portid is "
            "EPERM'd by the kernel before delivery (no NL_CFG_F_NONROOT_SEND on "
            "this subsystem), so this harness cannot run unprivileged. Never "
            "mutates real nftables state."
        )
    )
    parser.add_argument(
        "--target-pid", type=int, default=None,
        help="destination netlink portid (the agent's bound socket portid). "
             "Discovered from /proc/net/netlink when omitted.",
    )
    parser.add_argument(
        "--portid", type=int, default=0,
        help="source portid to bind (0 = kernel-assigned; default 0).",
    )
    parser.add_argument(
        "--duration", type=float, default=10.0,
        help="seconds to keep unicasting forged datagrams, synchronized with "
             "the agent's periodic GETCHAIN dump window (default 10).",
    )
    parser.add_argument(
        "--table", default="filter",
        help="NFTA_CHAIN_TABLE value in the forged chain (default 'filter').",
    )
    parser.add_argument(
        "--hooknum", type=int, default=DEFAULT_HOOKNUM,
        help="NFTA_HOOK_HOOKNUM value — 0=prerouting 1=input 2=forward "
             "3=output 4=postrouting (default 1, 'input').",
    )
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
