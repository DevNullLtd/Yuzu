#!/usr/bin/env python3
"""Probe client for scripts/ha/ha-gateway-two-replica-probe.sh (HA WS-13 slice 13.6, #7082).

LAB MEASUREMENT TOOL for a two-replica rig that is NOT a supported deployment. Run with `python3 -I`.
Standard library only. It talks to the rig's two server replicas over their published REST ports with
the throwaway admin session the runner logged in (curl cookie jars); nothing here is for production.

Subcommands (all take --run RUNDIR, where the runner keeps the raw data):
  holders    which replica holds each agent's session (two independent methods, both recorded)
  sample     choose the agents attached to the victim gateway and tag holder replica + cohort
  probe      one probe round: every sampled agent through BOTH replicas, both REST surfaces, plus one
             scope-arm probe per replica; scored against a polled deadline
  recovered  exit 0 when the latest probe round delivered every id-arm probe on both replicas
  resolve    re-read the response store for every send that was "accepted, no result" at its deadline (a
             server-synthesised terminal can arrive up to the 300 s SendCommand deadline after the send)
  analyse    classify and tabulate: probes.csv, summary.md
  export     (--state DIR --out DIR) summarise every run under a state dir for the committed record

Outcome classes of ONE probe (the first match wins):
  probe_invalid      HTTP 400 "could not be parsed": the probe itself was malformed; never counted as a dispatch result
  rig_error          anything else that is not a 2xx (no connection, 401, 403, 429, 500...): never a dispatch result
  refused            the dispatch REFUSED it: HTTP 503, or 202/200 with agents_reached == 0. The body
                     is kept, because the refusals differ: "no agent connected" (before the arm walk)
                     versus a not-sent (`no_agents_reached`); neither writes a response row.
  server_synthesised a response row whose error text carries a `[gateway_...]` prefix (built by the
                     server when its forward to the gateway fails). NOT delivered: the agent did not
                     produce it.
  delivered          a response row produced by the agent: status SUCCESS with output, or an
                     agent-reported FAILURE/REJECTED without a server prefix
  timeout            a response row with status TIMEOUT (not scored as delivered)
  accepted_no_result accepted, and no response row inside the deadline (re-read at the end of the run)
"""
import argparse
import csv
import glob
import hashlib
import http.cookiejar
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request



def _tls_context():
    """Verify the chain against the rig's own install CA (the runner copies it to $TWOREP_CA).

    The servers' certificates carry the rig's DNS names, not 127.0.0.1, which is where the REST ports are
    published, so the HOSTNAME check is off; the chain check stays on. Without a CA file the client refuses
    to run rather than fall back to an unverified connection.
    """
    ca = os.environ.get("TWOREP_CA", "")
    if not ca or not os.path.exists(ca):
        sys.exit("TWOREP_CA must name the rig's install CA file (the runner exports it); refusing to connect unverified")
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    return ctx


CTX = _tls_context() if os.environ.get("TWOREP_CA") else None
STATUS = {0: "RUNNING", 1: "SUCCESS", 2: "FAILURE", 3: "TIMEOUT", 4: "REJECTED"}  # agent.proto CommandResponse.Status


def load_rows(path):
    """Read a JSON-lines file, skipping (and counting) a line that does not parse: an interrupted writer must
    not take the whole analysis down, and the count is printed so a loss is never silent."""
    rows, bad = [], 0
    if os.path.exists(path):
        for line in open(path, errors="replace"):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                bad += 1
    if bad:
        print("WARNING: %d unparseable line(s) skipped in %s" % (bad, path), file=sys.stderr)
    return rows


def write_atomic(path, text):
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def classify_cohorts(rows):
    """Tag every row with `cohort_eff`: its sampled cohort, except that an agent of the clean cohort whose
    CONTROL did not deliver through both replicas on both surfaces (id arm) is `inconclusive` for the whole
    run, never a pass and never a refusal; a row with no cohort tag is `unknown`, never `clean`. Returns the
    sorted list of inconclusive agent ids."""
    bad = set()
    for r in rows:
        if r.get("label") == "control" and r.get("arm") == "ids" and r.get("cohort") == "clean" \
                and r.get("final_outcome", r.get("outcome")) != "delivered":
            bad.add(r["agent_id"])
    for r in rows:
        c = r.get("cohort") or "unknown"
        r["cohort_eff"] = "inconclusive" if (c == "clean" and r["agent_id"] in bad) else c
    return sorted(bad)


def median(values):
    v = sorted(values)
    n = len(v)
    return v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2.0


def now_ms():
    return int(time.time() * 1000)


class Session:
    """One replica: base URL + the cookie jar the runner wrote with curl."""

    def __init__(self, base, jar):
        self.base = base
        cookies = []
        for line in open(jar):
            line = line.strip()
            if line.startswith("#HttpOnly_"):
                line = line[len("#HttpOnly_"):]
            if not line or line.startswith("#"):
                continue
            f = line.split("\t")
            if len(f) == 7:
                cookies.append("%s=%s" % (f[5], f[6]))
        self.cookie = "; ".join(cookies)

    def call(self, method, path, body=None, timeout=15):
        global CTX
        if CTX is None:
            CTX = _tls_context()
        h = {"Cookie": self.cookie, "Origin": self.base, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:  # connection refused, timeout: a probe result, not a crash
            return 0, "client-error: %r" % (e,)


def jload(s):
    try:
        return json.loads(s)
    except Exception:
        return None


def walk(o, key):
    """Every value stored under `key` anywhere in a JSON document."""
    out = []
    if isinstance(o, dict):
        for k, v in o.items():
            if k == key:
                out.append(v)
            out.extend(walk(v, key))
    elif isinstance(o, list):
        for v in o:
            out.extend(walk(v, key))
    return out


# ---- holders -------------------------------------------------------------------------------------
def cmd_holders(a):
    s1, s2 = Session(a.url1, a.cookies1), Session(a.url2, a.cookies2)
    listed = {}
    host = {}
    for n, s in ((1, s1), (2, s2)):
        st, body = s.call("GET", "/api/agents")
        d = jload(body)
        ids = set()
        if d is not None:
            for rec in (d if isinstance(d, list) else walk(d, "agents") and walk(d, "agents")[0] or []):
                if isinstance(rec, dict):
                    aid = rec.get("agent_id") or rec.get("id")
                    if aid:
                        ids.add(aid)
                        if rec.get("hostname"):
                            host[aid] = rec["hostname"]
        listed[n] = ids
        print("replica %d GET /api/agents -> http %d, %d agents listed" % (n, st, len(ids)))
        if st != 200 or not ids:
            sys.exit("holders: replica %d's agent listing failed (http %d, %d ids): refusing to attribute holders "
                     "from an empty set, which would count every agent as clean" % (n, st, len(ids)))
    log = {1: open(a.log1, errors="replace").read(), 2: open(a.log2, errors="replace").read()}
    rows = []
    for line in open(a.routes):
        line = line.strip()
        if not line:
            continue
        aid, node, sid = (line.split(",") + ["", ""])[:3]
        rows.append((aid, node, sid))
    os.makedirs(a.run, exist_ok=True)
    with open(os.path.join(a.run, "holders.csv"), "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["agent_id", "gateway_node", "hostname", "listed_on_1", "listed_on_2", "logged_on_1", "logged_on_2"])
        for aid, node, sid in sorted(rows):
            # attribution = the replica whose log holds the CURRENT session id
            w.writerow([aid, node, host.get(aid, ""), int(aid in listed[1]), int(aid in listed[2]),
                        int(bool(sid) and sid in log[1]), int(bool(sid) and sid in log[2])])
    both = len(listed[1] & listed[2])
    print("agents listed on both replicas: %d (the listing can carry a stale session, see the runner's note)" % both)


# ---- sample --------------------------------------------------------------------------------------
def cmd_sample(a):
    """Choose the agents attached to the victim gateway node and tag each with its holder replica and cohort.

    holder = the replica whose own log holds the agent's CURRENT session id (holders.csv logged_on_N).
    cohort = clean       no listing on the other replica (the non-holder has no local session for it, so a
                         non-holder dispatch goes through the route directory);
             stale_other the other replica ALSO lists the agent (a stale local session left by a first-enrolment
                         double registration): reported separately, never mixed into the trigger tally.
    """
    rows = list(csv.DictReader(open(os.path.join(a.run, "holders.csv"))))
    clean, stale = [], []
    for r in rows:
        if r["gateway_node"] != a.victim_node:
            continue
        h = "1" if r["logged_on_1"] == "1" and r["logged_on_2"] != "1" else "2" if r["logged_on_2"] == "1" and r["logged_on_1"] != "1" else ""
        if not h:
            continue
        other_listed = r["listed_on_2"] if h == "1" else r["listed_on_1"]
        (stale if other_listed == "1" else clean).append((r["agent_id"], "stale_other" if other_listed == "1" else "clean", h))
    pick = clean[:a.k] + stale[:a.stale]
    with open(os.path.join(a.run, "sample.txt"), "w") as f:
        for x in pick:
            f.write(",".join(x) + "\n")
    print("sample: %d clean + %d stale_other (of %d clean and %d stale_other on %s); holder replicas: %s" % (
        len(clean[:a.k]), len(stale[:a.stale]), len(clean), len(stale), a.victim_node,
        sorted(set(x[2] for x in pick))))


# ---- probe ---------------------------------------------------------------------------------------
def read_lines(p):
    return [l.strip() for l in open(p) if l.strip()] if os.path.exists(p) else []


def read_sample(run, path):
    """sample.txt lines: agent_id,cohort,holder  ->  [(agent_id, cohort, holder)]"""
    out = []
    for l in read_lines(path):
        f = (l.split(",") + ["", ""])[:3]
        out.append((f[0], f[1] or "unknown", f[2]))
    return out


def read_hosts(run):
    h = {}
    p = os.path.join(run, "holders.csv")
    if os.path.exists(p):
        for r in csv.DictReader(open(p)):
            if r.get("hostname"):
                h[r["agent_id"]] = r["hostname"]
    return h


def send_one(sess, replica, surface, arm, agent, scope, rec, meta=None):
    body = {"plugin": "os_info", "action": "os_name"}
    if arm == "scope":
        body["scope"] = scope
    else:
        body["agent_ids"] = [agent]
    path = "/api/v1/commands" if surface == "v1" else "/api/command"
    t = now_ms()
    st, txt = sess.call("POST", path, body)
    d = jload(txt) or {}
    data = d.get("data", d) if isinstance(d, dict) else {}
    cmd = (data.get("command_id") if isinstance(data, dict) else None) or (d.get("command_id") if isinstance(d, dict) else None)
    rec.update(meta or {})
    rec.update({
        "t_send_ms": t, "replica": replica, "surface": surface, "arm": arm, "agent_id": agent,
        "http": st, "command_id": cmd or "",
        "execution_id": (data.get("execution_id") if isinstance(data, dict) else "") or "",
        "agents_reached": data.get("agents_reached", d.get("agents_sent", "")) if isinstance(data, dict) else "",
        "reason": ((d.get("error") or {}).get("reason", "") if isinstance(d.get("error", None), dict) else ""),
        "body": txt[:400].replace("\n", " "),
    })


def responses_for(sess, cmd):
    """Response rows of one command id. Both surfaces store into the same response store."""
    st, txt = sess.call("GET", "/api/responses/" + cmd, timeout=10)
    d = jload(txt)
    if st != 200 or d is None:
        return None
    return d.get("responses", d.get("data", {}).get("responses", [])) if isinstance(d, dict) else None


def score(rec, rows):
    """Outcome class of one probe from what dispatch said and what the response store holds."""
    if rec["http"] == 0:
        return "rig_error", "client-error"
    if rec["http"] == 400 and "could not be parsed" in rec.get("body", ""):
        return "probe_invalid", "scope expression rejected (a caller error in the probe, not a dispatch result)"
    if rec["http"] == 503:
        return "refused", "http 503"
    if rec["http"] >= 300:
        # 401/403/429/500/...: the rig or the session is wrong, not a dispatch decision. Never scored as a refusal.
        return "rig_error", "http %d" % rec["http"]
    reached = rec["agents_reached"]
    if reached == 0 and reached != "":
        return "refused", "agents_reached=0"
    if not rows:
        return "accepted_no_result", ""
    for r in rows:
        err = (r.get("error_detail") or "") + " " + json.dumps(r.get("error", ""))
        if "[gateway_" in err:
            return "server_synthesised", err.strip()[:80]
    for r in rows:
        st = r.get("status")
        if st == 1 and r.get("output"):
            return "delivered", "SUCCESS"
    for r in rows:
        st = r.get("status")
        if st in (2, 4):
            return "delivered", STATUS.get(st, str(st)) + " (agent-reported)"
        if st == 3:
            return "timeout", "TIMEOUT"
    return "accepted_no_result", "status=" + ",".join(str(r.get("status")) for r in rows)


def cmd_probe(a):
    sess = {1: Session(a.url1, a.cookies1), 2: Session(a.url2, a.cookies2)}
    sample = read_sample(a.run, a.agents)
    agents = [x[0] for x in sample]
    meta_of = {x[0]: {"cohort": x[1], "holder": x[2]} for x in sample}
    hosts = read_hosts(a.run)
    t_round = now_ms()
    jobs = []
    for aid in agents:
        for replica in (1, 2):
            for surface in ("v1", "legacy"):
                jobs.append((replica, surface, "ids", aid, ""))
    # one scope-arm probe per replica (the presence merge can drop an agent from a scope arm before the
    # route lookup is reached): the first sampled agent that has a known hostname, v1 surface
    for aid in agents:
        if aid in hosts:
            for replica in (1, 2):
                jobs.append((replica, "v1", "scope", aid, "hostname == '%s'" % hosts[aid]))
            break
    recs = [dict() for _ in jobs]
    threads = []
    for (replica, surface, arm, aid, scope), rec in zip(jobs, recs):
        m = dict(meta_of.get(aid, {}))
        m["role"] = ("holder" if str(replica) == m.get("holder") else "non-holder") if m.get("holder") else "unknown"
        th = threading.Thread(target=send_one, args=(sess[replica], replica, surface, arm, aid, scope, rec, m))
        th.start(); threads.append(th)
    for th in threads:
        th.join()
    deadline = time.time() + a.deadline
    pending = [r for r in recs if r["command_id"] and r["http"] < 400]
    seen = {}
    while pending and time.time() < deadline:
        left = []
        for r in pending:
            rows = responses_for(sess[r["replica"]], r["command_id"])
            seen[r["command_id"] + str(r["replica"])] = rows
            cls, _ = score(r, rows or [])
            if cls == "accepted_no_result":
                left.append(r)
        pending = left
        if pending:
            time.sleep(2)
    out = []
    for r in recs:
        rows = seen.get(r.get("command_id", "") + str(r.get("replica", "")), [])
        cls, why = score(r, rows or [])
        r.update({"label": a.label, "rel_s": round((r["t_send_ms"] - a.t0) / 1000.0, 1) if a.t0 else "",
                  "deadline_s": a.deadline, "outcome": cls, "why": why, "final_outcome": cls})
        out.append(r)
    with open(os.path.join(a.run, "probes.jsonl"), "a") as f:
        for r in out:
            f.write(json.dumps(r) + "\n")
    tally = {}
    for r in out:
        tally.setdefault((r["replica"], r["arm"], r["outcome"]), 0)
        tally[(r["replica"], r["arm"], r["outcome"])] += 1
    print("probe %-16s %s" % (a.label, "  ".join("r%d/%s/%s=%d" % (k[0], k[1], k[2], v) for k, v in sorted(tally.items()))))


def latest_round(run):
    p = os.path.join(run, "probes.jsonl")
    rows = load_rows(p)
    if not rows:
        return []
    lab = rows[-1]["label"]
    return [r for r in rows if r["label"] == lab]


def cmd_recovered(a):
    rows = [r for r in latest_round(a.run) if r["arm"] == "ids" and r.get("cohort") == "clean"]
    sys.exit(0 if rows and all(r["outcome"] == "delivered" for r in rows) else 1)


# ---- resolve (late terminals) --------------------------------------------------------------------
def cmd_resolve(a):
    sess = {1: Session(a.url1, a.cookies1), 2: Session(a.url2, a.cookies2)}
    p = os.path.join(a.run, "probes.jsonl")
    rows = load_rows(p)
    changed = 0
    for r in rows:
        if r["outcome"] != "accepted_no_result" or not r["command_id"]:
            continue
        resp = responses_for(sess[1], r["command_id"]) or responses_for(sess[2], r["command_id"])
        cls, why = score(r, resp or [])
        if cls != "accepted_no_result":
            r["final_outcome"], r["why"] = cls, why + " (late)"
            changed += 1
    write_atomic(p, "".join(json.dumps(r) + "\n" for r in rows))
    print("resolve: %d accepted-no-result probes became terminal after the deadline" % changed)


# ---- analyse -------------------------------------------------------------------------------------
def agent_logs_with(run, cmd):
    hits = 0
    for p in glob.glob(os.path.join(run, "agentlog-*.txt")):
        try:
            if cmd in open(p, errors="replace").read():
                hits += 1
        except OSError:
            pass
    return hits


def route_timeline(run, agents):
    """Per sampled agent: the lease/route state around the fault and the undo, from routes.csv (1 Hz,
    every agent_routes column plus the DB's now()). Times are seconds relative to the fault."""
    def rd(name):
        p = os.path.join(run, name)
        return int(open(p).read()) if os.path.exists(p) else 0
    t0, tu = rd("fault_ms"), rd("undo_ms")
    first_nonroutable, first_unarmed, first_routable_after = {}, {}, {}
    p = os.path.join(run, "routes.csv")
    if not (t0 and os.path.exists(p)):
        return {}
    for line in open(p, errors="replace"):
        parts = line.rstrip("\n").split(",", 2)
        if len(parts) < 3:
            continue
        try:
            t = int(parts[0])
            j = json.loads(parts[2])
        except Exception:
            continue
        aid = j.get("agent_id")
        if aid not in agents or t < t0:
            continue
        routable = bool(j.get("session_id")) and (j.get("lease_until", "") >= parts[1].replace(" ", "T") if False else True)
        # lease comparison done by the database in the sampler would be better; here lease_until and now() are
        # both ISO timestamps from the same DB clock, so a string compare in UTC is exact
        lease, now = j.get("lease_until") or "", parts[1].strip()
        try:
            from datetime import datetime
            routable = bool(j.get("session_id")) and datetime.fromisoformat(lease) >= datetime.fromisoformat(now)
        except Exception:
            routable = False
        rel = (t - t0) / 1000.0
        if not routable and aid not in first_nonroutable and (not tu or t < tu):
            first_nonroutable[aid] = rel
        if not j.get("session_id") and aid not in first_unarmed and (not tu or t < tu):
            first_unarmed[aid] = rel
        if tu and t >= tu and routable and aid not in first_routable_after:
            first_routable_after[aid] = (t - tu) / 1000.0
    return {"first_nonroutable_s": first_nonroutable, "first_unarmed_s": first_unarmed,
            "first_routable_after_undo_s": first_routable_after}


def cmd_analyse(a):
    p = os.path.join(a.run, "probes.jsonl")
    rows = load_rows(p)
    inconclusive = classify_cohorts(rows)
    for r in rows:
        r["in_agent_log"] = agent_logs_with(a.run, r["command_id"]) if r["command_id"] else 0
        r.setdefault("role", "unknown"); r.setdefault("reason", "")
    with open(os.path.join(a.run, "probes.csv"), "w", newline="") as f:
        cols = ["label", "rel_s", "replica", "role", "cohort", "cohort_eff", "surface", "arm", "agent_id", "http", "command_id",
                "agents_reached", "outcome", "final_outcome", "reason", "why", "in_agent_log", "body"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    labels = []
    for r in rows:
        if r["label"] not in labels:
            labels.append(r["label"])
    meta = open(os.path.join(a.run, "meta.txt")).read().strip() if os.path.exists(os.path.join(a.run, "meta.txt")) else ""
    lines = ["# run summary", "", "`" + meta + "`", ""]
    inv = os.path.join(a.run, "INVALID")
    if os.path.exists(inv):
        lines += ["**INVALID RUN: %s**" % open(inv).read().strip(), ""]
    # control validity per clean agent: delivered through BOTH replicas, id arm, before the fault
    lines += ["control (clean cohort, id arm, both replicas, both surfaces): %s" % (
        "ALL DELIVERED" if not inconclusive else
        "FAILED for %d agent(s) (%s): they are INCONCLUSIVE for the whole run (own table below), never a pass and never a refusal" % (
            len(inconclusive), ", ".join(x[:8] for x in inconclusive))), ""]
    if any(r["cohort_eff"] == "unknown" for r in rows):
        lines += ["**%d probe rows carry no cohort tag (an early run): reported as cohort `unknown`, never as clean.**" % sum(
            1 for r in rows if r["cohort_eff"] == "unknown"), ""]
    for cohort in ("clean", "stale_other", "inconclusive", "unknown"):
        sub = [r for r in rows if r["cohort_eff"] == cohort]
        if not sub:
            continue
        lines += ["## cohort: %s" % cohort, "",
                  "| round | probed replica | role | arm | delivered | refused | server-synth | no result | timeout | invalid | rig error | total | refusal reasons |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for lab in labels:
            for rep in (1, 2):
                for arm in ("ids", "scope"):
                    sel = [r for r in sub if r["label"] == lab and r["replica"] == rep and r["arm"] == arm]
                    if not sel:
                        continue
                    c = lambda k: sum(1 for r in sel if r["final_outcome"] == k)
                    reasons = {}
                    for r in sel:
                        if r["final_outcome"] == "refused":
                            k = r["reason"] or ("legacy bare 503" if r["surface"] == "legacy" else "http %s" % r["http"])
                            reasons[k] = reasons.get(k, 0) + 1
                    lines.append("| %s | %d | %s | %s | %d | %d | %d | %d | %d | %d | %d | %d | %s |" % (
                        lab, rep, sel[0]["role"], arm, c("delivered"), c("refused"), c("server_synthesised"),
                        c("accepted_no_result"), c("timeout"), c("probe_invalid"), c("rig_error"), len(sel),
                        ", ".join("%s x%d" % kv for kv in sorted(reasons.items())) or "-"))
        lines.append("")
    agents = {r["agent_id"] for r in rows if r["cohort_eff"] == "clean"}
    tl = route_timeline(a.run, agents)
    if tl:
        def stat(d):
            v = sorted(d.values())
            return "n=%d min=%.0f s median=%.1f s max=%.0f s" % (len(v), v[0], median(v), v[-1]) if v else "none observed"
        lines += ["## route directory timeline (clean cohort, seconds)", "",
                  "- first non-routable (lease expired or session cleared) after the fault: " + stat(tl["first_nonroutable_s"]),
                  "- first sample with the session cleared (row unarmed/tombstoned) after the fault: " + stat(tl["first_unarmed_s"]),
                  "- first routable again after the fault was undone: " + stat(tl["first_routable_after_undo_s"]), ""]
    odd = [r for r in rows if r["final_outcome"] == "delivered" and r["command_id"] and not r["in_agent_log"]]
    lines += ["delivered rows whose command id appears in NO agent log: %d of %d "
              "(an unsynthesised failure that no agent produced would show here)" % (
                  len(odd), sum(1 for r in rows if r["final_outcome"] == "delivered"))]
    open(os.path.join(a.run, "summary.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


def cmd_export(a):
    """Summarise every run under --state into two CSVs for the committed record: probe-summary.csv (one row
    per run x round x cohort x role x arm) and run-timeline.csv (one row per run). Raw logs, cookies and
    secrets are NOT exported."""
    os.makedirs(a.out, exist_ok=True)
    runs = sorted(glob.glob(os.path.join(a.state, "run-*", "probes.jsonl")))
    if a.runs:
        want = set(x for x in a.runs.split(",") if x)
        missing = want - {os.path.basename(os.path.dirname(x)) for x in runs}
        if missing:
            sys.exit("export: no such run(s): %s" % ", ".join(sorted(missing)))
        runs = [x for x in runs if os.path.basename(os.path.dirname(x)) in want]
    with open(os.path.join(a.out, "probe-summary.csv"), "w", newline="") as f, \
            open(os.path.join(a.out, "run-timeline.csv"), "w", newline="") as g:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["run", "scenario", "victim", "holder_replica", "round", "cohort", "probed_replica", "role", "arm",
                    "delivered", "refused", "server_synthesised", "accepted_no_result", "timeout", "invalid", "rig_error",
                    "total", "refusal_reasons"])
        t = csv.writer(g, lineterminator="\n")
        t.writerow(["run", "scenario", "victim", "holder_replica", "agents_total", "clean_sampled", "stale_sampled",
                    "nonroutable_n", "nonroutable_min_s", "nonroutable_median_s", "nonroutable_max_s",
                    "unarmed_n", "unarmed_min_s", "unarmed_median_s", "unarmed_max_s",
                    "routable_after_undo_n", "routable_after_undo_min_s", "routable_after_undo_median_s",
                    "routable_after_undo_max_s", "inconclusive_agents", "valid", "invalid_reason", "probes_sha256"])
        for pj in runs:
            rd = os.path.dirname(pj)
            run = os.path.basename(rd)
            meta = open(os.path.join(rd, "meta.txt")).read() if os.path.exists(os.path.join(rd, "meta.txt")) else ""
            m = dict(x.split("=", 1) for x in meta.split() if "=" in x)
            rows = load_rows(pj)
            if any("cohort" not in r for r in rows):
                # an early shake-out run taken before probes carried a cohort and holder: its stale-session agents
                # cannot be told from clean ones, so it is not summarised (its raw data stays in the state dir)
                print("skipping %s: probes carry no cohort tag" % run)
                continue
            inconclusive = classify_cohorts(rows)
            for r in rows:
                r.setdefault("reason", "")
            holders = sorted({r.get("holder", "") for r in rows if r.get("holder")})
            labels = []
            for r in rows:
                if r["label"] not in labels:
                    labels.append(r["label"])
            for lab in labels:
                for cohort in ("clean", "stale_other", "inconclusive"):
                    for rep in (1, 2):
                        for arm in ("ids", "scope"):
                            sel = [r for r in rows if r["label"] == lab and r["cohort_eff"] == cohort and r["replica"] == rep and r["arm"] == arm]
                            if not sel:
                                continue
                            c = lambda k: sum(1 for r in sel if r["final_outcome"] == k)
                            reasons = {}
                            for r in sel:
                                if r["final_outcome"] == "refused":
                                    k = r["reason"] or ("legacy bare 503" if r["surface"] == "legacy" else "http %s" % r["http"])
                                    reasons[k] = reasons.get(k, 0) + 1
                            w.writerow([run, m.get("id", ""), m.get("victim", ""), "/".join(holders), lab, cohort, rep, sel[0]["role"], arm,
                                        c("delivered"), c("refused"), c("server_synthesised"), c("accepted_no_result"), c("timeout"),
                                        c("probe_invalid"), c("rig_error"), len(sel), "; ".join("%s x%d" % kv for kv in sorted(reasons.items()))])
            clean = {r["agent_id"] for r in rows if r["cohort_eff"] == "clean"}
            tl = route_timeline(rd, clean)
            def st(d):
                v = sorted(d.values()) if d else []
                return [len(v), "%.0f" % v[0], "%.1f" % median(v), "%.0f" % v[-1]] if v else [0, "", "", ""]
            samp = read_sample(rd, os.path.join(rd, "sample.txt")) if os.path.exists(os.path.join(rd, "sample.txt")) else []
            t.writerow([run, m.get("id", ""), m.get("victim", ""), "/".join(holders), m.get("total", ""),
                        sum(1 for x in samp if x[1] == "clean"), sum(1 for x in samp if x[1] != "clean"),
                        *st(tl.get("first_nonroutable_s")), *st(tl.get("first_unarmed_s")),
                        *st(tl.get("first_routable_after_undo_s")),
                        len(inconclusive),
                        "no" if os.path.exists(os.path.join(rd, "INVALID")) else "yes",
                        open(os.path.join(rd, "INVALID")).read().strip() if os.path.exists(os.path.join(rd, "INVALID")) else "",
                        hashlib.sha256(open(pj, "rb").read()).hexdigest()])
    print("exported %d runs to %s" % (len(runs), a.out))


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    pe = sp.add_parser("export")
    pe.add_argument("--state", required=True); pe.add_argument("--out", required=True)
    pe.add_argument("--runs", default="", help="comma list of run directory names to summarise (default: every tagged run)")
    for name in ("holders", "sample", "probe", "recovered", "resolve", "analyse"):
        p = sp.add_parser(name)
        p.add_argument("--run", required=True)
        if name in ("holders", "probe", "resolve"):
            p.add_argument("--url1", required=True); p.add_argument("--url2", required=True)
            p.add_argument("--cookies1", required=True); p.add_argument("--cookies2", required=True)
        if name == "sample":
            p.add_argument("--victim-node", required=True); p.add_argument("--k", type=int, default=10)
            p.add_argument("--stale", type=int, default=2)
        if name == "holders":
            p.add_argument("--routes", required=True); p.add_argument("--log1", required=True); p.add_argument("--log2", required=True)
        if name == "probe":
            p.add_argument("--label", required=True); p.add_argument("--t0", type=int, default=0)
            p.add_argument("--agents", required=True); p.add_argument("--deadline", type=int, default=30)
    a = ap.parse_args()
    {"holders": cmd_holders, "sample": cmd_sample, "probe": cmd_probe, "recovered": cmd_recovered, "resolve": cmd_resolve, "analyse": cmd_analyse, "export": cmd_export}[a.cmd](a)


if __name__ == "__main__":
    main()
