- **Reflex design contract, ADR-0021 amendment, and wire schema.** `docs/reflex-design.md` is now
  the canonical, implementation-citable contract for the Reflex agent-local automated-response
  system (Spark-bound Reaction chains, YAML-authoritative content, digest-bound two-person approval,
  the `device_class` consent gate). `proto/yuzu/reflex/v1/reflex.proto` defines the wire schema for
  Reflex Set deploy/status; `GuaranteedStateEvent` gains an additive `family` field so Reflex
  outcomes can reuse the existing Guardian event channel. No runtime behavior changes — this PR is
  documentation and schema only; nothing is wired up yet.
