/**
 * CURATION MANIFEST — the single source of truth for the docs site.
 *
 * Each entry maps a canonical Markdown file under repo `docs/` (path relative to
 * docs/, no extension) to its site section, order, slug, and title. Adding a doc
 * to the site means adding a line here; nothing else reads from disk to decide
 * inclusion. The diagram linter fails the build if an entry names a missing file.
 *
 * Plain ESM (not .ts) on purpose: imported by .astro pages, the content loader,
 * the remark link-rewriter, AND the standalone Node linter — one module, no
 * TS-from-mjs interop headaches.
 *
 * @typedef {{ file: string, slug: string, title: string }} NavEntry
 * @typedef {{ heading: string, entries: NavEntry[] }} NavSection
 */

import { PLUGIN_ENTRIES } from './nav.plugins.mjs';

/** @type {NavSection[]} */
export const NAV = [
  {
    heading: 'Start',
    entries: [
      { file: 'getting-started', slug: 'getting-started', title: 'Getting Started' },
    ],
  },
  {
    heading: 'Instructions & DSL',
    entries: [
      { file: 'Instruction-Engine', slug: 'instruction-engine', title: 'Instruction Engine' },
      { file: 'user-manual/instructions', slug: 'instructions', title: 'Instructions' },
      { file: 'yaml-dsl-spec', slug: 'yaml-dsl', title: 'YAML DSL' },
    ],
  },
  {
    heading: 'Targeting',
    entries: [
      { file: 'user-manual/scope-engine', slug: 'scope-engine', title: 'Scope Engine' },
      { file: 'scope-walking-design', slug: 'scope-walking', title: 'Scope Walking' },
      { file: 'asset-tagging-guide', slug: 'asset-tagging', title: 'Asset Tagging' },
      { file: 'user-manual/management-groups', slug: 'management-groups', title: 'Management Groups' },
      { file: 'user-manual/device-management', slug: 'device-management', title: 'Device Management' },
    ],
  },
  {
    heading: 'Policy & Guardian',
    entries: [
      { file: 'user-manual/policy-engine', slug: 'policy-engine', title: 'Policy Engine' },
      { file: 'user-manual/guaranteed-state', slug: 'guaranteed-state', title: 'Guaranteed State' },
      { file: 'yuzu-guardian-design-v1.1', slug: 'guardian-design', title: 'Guardian Design' },
    ],
  },
  {
    heading: 'Vulnerability Management',
    entries: [
      { file: 'vulnerability-graph-explained', slug: 'vulnerability-graph', title: 'Vulnerability Graph, Explained' },
    ],
  },
  {
    heading: 'Identity & Access',
    entries: [
      { file: 'user-manual/authentication', slug: 'authentication', title: 'Authentication' },
      { file: 'user-manual/rbac', slug: 'rbac', title: 'RBAC' },
      { file: 'auth-architecture', slug: 'auth-architecture', title: 'Auth Architecture' },
      { file: 'user-manual/security-hardening', slug: 'security-hardening', title: 'Security Hardening' },
    ],
  },
  {
    heading: 'Interfaces',
    entries: [
      { file: 'user-manual/rest-api', slug: 'rest-api', title: 'REST API' },
      { file: 'user-manual/mcp', slug: 'mcp', title: 'MCP' },
      { file: 'mcp-server', slug: 'mcp-server', title: 'MCP Server' },
      { file: 'user-manual/agent-plugins', slug: 'agent-plugins', title: 'Agent Plugins' },
      { file: 'user-manual/tar', slug: 'tar', title: 'TAR' },
      { file: 'tar-dashboard', slug: 'tar-dashboard', title: 'TAR Dashboard' },
      { file: 'fleet-viz-invariants', slug: 'fleet-viz', title: 'Fleet Visualization' },
    ],
  },
  {
    heading: 'Data & Observability',
    entries: [
      { file: 'user-manual/response-store', slug: 'response-store', title: 'Response Store' },
      { file: 'user-manual/audit-log', slug: 'audit-log', title: 'Audit Log' },
      { file: 'user-manual/metrics', slug: 'metrics', title: 'Metrics' },
      { file: 'observability-conventions', slug: 'observability-conventions', title: 'Observability Conventions' },
      { file: 'analytics-events', slug: 'analytics-events', title: 'Analytics Events' },
    ],
  },
  {
    heading: 'Operating Yuzu',
    entries: [
      { file: 'user-manual/server-admin', slug: 'server-admin', title: 'Server Administration' },
      { file: 'user-manual/gateway', slug: 'gateway', title: 'Gateway' },
      { file: 'user-manual/upgrading', slug: 'upgrading', title: 'Upgrading' },
      { file: 'user-manual/release-verification', slug: 'release-verification', title: 'Release Verification' },
      { file: 'operations/capacity-planning', slug: 'capacity-planning', title: 'Capacity Planning' },
      { file: 'operations/certificate-renewal', slug: 'certificate-renewal', title: 'Certificate Renewal' },
      { file: 'operations/disaster-recovery', slug: 'disaster-recovery', title: 'Disaster Recovery' },
      { file: 'operations/troubleshooting', slug: 'troubleshooting', title: 'Troubleshooting' },
    ],
  },
  {
    heading: 'Extending & Concepts',
    entries: [
      { file: 'data-architecture', slug: 'data-architecture', title: 'Data Architecture' },
      { file: 'enterprise-edition', slug: 'enterprise-edition', title: 'Enterprise Edition' },
      { file: 'enterprise-readiness-soc2-first-customer', slug: 'enterprise-readiness', title: 'Enterprise Readiness (SOC 2)' },
      { file: 'plugin-readme-standard', slug: 'plugin-readme-standard', title: 'Plugin README Standard' },
    ],
  },
  // Per-plugin pages: agents/plugins/<name>/README.md, one entry per plugin
  // that has adopted the standard. The list is GENERATED by
  // tools/plugin-doc-gen (src/nav.plugins.mjs) — edit the READMEs, not this.
  {
    heading: 'Plugins',
    entries: PLUGIN_ENTRIES,
  },
];

export const ENTRIES = NAV.flatMap((s) => s.entries);

/** docs-relative path (no .md) -> entry */
export const BY_FILE = new Map(ENTRIES.map((e) => [e.file, e]));
/** site slug -> entry */
export const BY_SLUG = new Map(ENTRIES.map((e) => [e.slug, e]));
