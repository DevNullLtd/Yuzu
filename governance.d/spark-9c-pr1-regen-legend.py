import sys,re
p=sys.argv[1]; lines=open(p).read().split("\n")
rows=[l for l in lines if l.startswith("| ") and not l.startswith("| # ") and not l.startswith("|---") and not l.startswith("| test |")]
nomatch=[l for l in rows if "no summary" in l and "rc=2" in l]  # ca-104: the literal used to miss "(no summary; crashed?)"
valid=[l for l in rows if l not in nomatch]
RED=re.compile(r"FAILED|SIGABRT|rc=42|sig=6|unexpected exception|rc=-11|died|terminate", re.I)
GRN=re.compile(r"All tests passed|green|rc=0|passed \(|\d+ passed", re.I)
red=[l for l in valid if RED.search(l)]; green=[l for l in valid if GRN.search(l)]
pairs=[l for l in valid if RED.search(l) and GRN.search(l)]
# co-1 / ca-104 (governance pass 4): the honest figure is DISTINCT MUTATIONS killed, not pair rows.
# A row whose `#` cell says "(observed)" records a flake seen in the wild, not a mutation; a
# re-run row repeats its first attempt's test AND mutation cells and must count once. Key = (test, mutation).
def cells(l): return [c.strip() for c in l.strip().strip("|").split("|")]
observed=[l for l in pairs if "(observed)" in cells(l)[0]]
# dw-201 (governance pass 5): count observed-flake rows among ALL valid rows, not only pair rows.
observed_all=[l for l in valid if "(observed)" in cells(l)[0]]
# ca-205 (pass 5): the RED/GRN regexes classify whole-row text (Catch2 output inside cells contains
# literal pipes), so a row is RED if ANY cell names a failure line and GREEN if ANY cell names a pass;
# a row that quotes a pass inside its "red output" cell would be misclassified - keep red-output cells
# to the failure lines only.
distinct=[]; seen=set()
for l in pairs:
    if l in observed: continue
    c=cells(l); k=(c[1],c[2]) if len(c)>2 else l  # (test, mutation): a re-run repeats both; one mutation killing two tests is two kills
    if k in seen: continue
    seen.add(k); distinct.append(l)
legend=(f"**Legend (computed from the rows below by `governance.d/spark-9c-pr1-regen-legend.py`; method: a data row is any `| ` line outside the header/separator rows, classified on its WHOLE text because Catch2 output inside cells contains literal pipes; "
        f"a no-match row reads `rc=2 (no summary)`; RED = the row names a FAILED / SIGABRT / rc=42 / unexpected-exception / rc=-11 line; GREEN = the row names a pass (`All tests passed`, `N passed`, `rc=0`, `green`); a completed pair is a row that is both):** "
        f"{len(rows)} data rows; {len(nomatch)} matched no test (Catch2 comma split, each superseded by its wildcard re-run row); "
        f"{len(valid)} valid rows; {len(red)} RED; {len(green)} GREEN; {len(pairs)} red-then-green pair rows, of which {len(observed)} observed-flake pair row(s) ({len(observed_all)} observed-flake rows in total) and {len(pairs)-len(observed)-len(distinct)} re-run duplicate(s); **{len(distinct)} completed (test, mutation) red-then-green pairs** (the honest figure: distinct mutations killed by a red-then-green run, NOT a count of mutations attempted) "
        f"(the figure the PR body quotes; governance pass-4 co-1/ca-104 rule: distinct (test, mutation) cells among red-then-green rows, observed-flake rows excluded, re-runs counted once; earlier legends counted pair rows; the {len(valid)-len(pairs)} non-pair rows are observed-only or first attempts that a later row completes).")
open(p,"w").write("\n".join(legend if l.startswith("**Legend (computed from the rows below") else l for l in lines))
print(f"rows={len(rows)} nomatch={len(nomatch)} valid={len(valid)} red={len(red)} green={len(green)} pairs={len(pairs)} observed={len(observed)} distinct={len(distinct)}")
