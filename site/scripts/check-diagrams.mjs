#!/usr/bin/env node
/**
 * ASCII-diagram alignment linter — the enforced guarantee from design Q8.
 *
 * Scans, for box-drawing diagrams:
 *   1. every in-scope doc (from the manifest, src/nav.mjs),
 *   2. every off-site Tier-A doc in the configured allow-list
 *      (scripts/diagram-lint-extra.mjs) — README, docs/architecture.md, etc.,
 *      so alignment + the retired-arrow rule are enforced repo-wide and not only
 *      for docs already on the site, and
 *   3. every <pre class="diagram"> in the site's .astro sources.
 *
 * Rule: every FRAME line — one that begins with a box-drawing character, i.e.
 * carries the left+right border — must have the same display width (East-Asian-
 * Width aware). Connector/arrow lines (which begin with spaces) are exempt, and
 * every line is right-trimmed first, so the check is immune to trailing-
 * whitespace stripping by editors or the pre-commit hook. Retired inline arrow
 * glyphs (►◄▶◀) are rejected.
 *
 * The pure-logic core (lintBlock, markdownBlocks, astroDiagramBlocks, width) is
 * exported and unit-tested in check-diagrams.test.mjs. Running this file as a
 * script lints the repo and exits non-zero on any violation. No dependencies.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const BOX = /[─-╿▀-▟■-◿]/; // box-drawing, blocks, geometric shapes
export const RETIRED = /[►◄▶◀]/; // ► ◄ ▶ ◀ — retired per design Q8
export const isFrameStart = (l) => l.length > 0 && l.codePointAt(0) >= 0x2500 && l.codePointAt(0) <= 0x257f;

/** East-Asian-Width-aware cell width. Ambiguous (▼ · etc.) counts as 1. */
export function charWidth(cp) {
  if (cp === 0) return 0;
  if (
    (cp >= 0x1100 && cp <= 0x115f) || cp === 0x2329 || cp === 0x232a ||
    (cp >= 0x2e80 && cp <= 0x303e) || (cp >= 0x3041 && cp <= 0x33ff) ||
    (cp >= 0x3400 && cp <= 0x4dbf) || (cp >= 0x4e00 && cp <= 0x9fff) ||
    (cp >= 0xa000 && cp <= 0xa4cf) || (cp >= 0xac00 && cp <= 0xd7a3) ||
    (cp >= 0xf900 && cp <= 0xfaff) || (cp >= 0xfe10 && cp <= 0xfe19) ||
    (cp >= 0xfe30 && cp <= 0xfe6f) || (cp >= 0xff00 && cp <= 0xff60) ||
    (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1faff) ||
    (cp >= 0x20000 && cp <= 0x3fffd)
  ) return 2;
  return 1;
}
export const width = (s) => [...s].reduce((w, ch) => w + charWidth(ch.codePointAt(0)), 0);

/**
 * Lint one diagram block. Returns an array of { line, message } problems, where
 * `line` is the 0-based offset within the block.
 */
export function lintBlock(rawLines) {
  const lines = rawLines.map((l) => l.replace(/[ \t]+$/, '')); // right-trim: never depend on trailing WS
  const problems = [];

  lines.forEach((l, i) => {
    const m = l.match(RETIRED);
    if (m) problems.push({ line: i, message: `retired arrow glyph "${m[0]}" in diagram — normalise it` });
  });

  const frame = [];
  lines.forEach((l, i) => { if (isFrameStart(l)) frame.push({ i, w: width(l) }); });
  if (frame.length >= 2) {
    const target = Math.max(...frame.map((o) => o.w));
    for (const o of frame) {
      if (o.w !== target) {
        problems.push({ line: o.i, message: `frame edge misaligned: width ${o.w} ≠ ${target} (Δ${o.w - target})` });
      }
    }
  }
  return problems;
}

/** Extract diagram blocks (those containing box-drawing) from Markdown text. */
export function markdownBlocks(src) {
  const lines = src.split('\n');
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    const fence = lines[i].match(/^(\s*)(`{3,}|~{3,})/);
    if (!fence) continue;
    const marker = fence[2][0];
    const block = [];
    const start = i + 1;
    i++;
    while (i < lines.length && !lines[i].trimStart().startsWith(marker.repeat(3))) {
      block.push(lines[i]);
      i++;
    }
    if (block.some((l) => BOX.test(l))) blocks.push({ firstLineNo: start + 1, lines: block });
  }
  return blocks;
}

/** Extract <pre class="diagram"> blocks from .astro source. */
export function astroDiagramBlocks(src) {
  const re = /<pre[^>]*class="[^"]*\bdiagram\b[^"]*"[^>]*>([\s\S]*?)<\/pre>/g;
  const blocks = [];
  let m;
  while ((m = re.exec(src))) {
    const inner = m[1]
      .replace(/<\/?[a-zA-Z][^>]*>/g, '')
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
    const block = inner.replace(/^\n/, '').split('\n');
    while (block.length && block[block.length - 1].trim() === '') block.pop();
    if (block.some((l) => BOX.test(l))) blocks.push({ firstLineNo: 1, lines: block });
  }
  return blocks;
}

async function main() {
  const repoRoot = path.resolve(process.cwd(), '..');
  const docsRoot = path.join(repoRoot, 'docs');
  const srcRoot = path.join(process.cwd(), 'src');
  const { ENTRIES } = await import('../src/nav.mjs');
  const { EXTRA_DOCS } = await import('./diagram-lint-extra.mjs');

  const failures = [];
  const rel = (fp) => path.relative(repoRoot, fp);
  const lintFile = (label, src, kind) => {
    const blocks = kind === 'astro' ? astroDiagramBlocks(src) : markdownBlocks(src);
    for (const b of blocks) {
      for (const p of lintBlock(b.lines)) failures.push(`${label}:${b.firstLineNo + p.line}  ${p.message}`);
    }
  };

  let scanned = 0;
  for (const e of ENTRIES) {
    // Plugin READMEs are manifest entries keyed by repo-relative path
    // (agents/plugins/<name>/README); everything else is docs-relative.
    const fp = e.file.startsWith('agents/')
      ? path.join(repoRoot, `${e.file}.md`)
      : path.join(docsRoot, `${e.file}.md`);
    if (!fs.existsSync(fp)) { failures.push(`manifest entry "${e.file}" -> ${rel(fp)} does not exist`); continue; }
    lintFile(rel(fp), fs.readFileSync(fp, 'utf8'), 'md');
    scanned++;
  }
  for (const d of EXTRA_DOCS) {
    const fp = path.join(repoRoot, d);
    if (!fs.existsSync(fp)) { failures.push(`extra-doc allow-list entry "${d}" does not exist`); continue; }
    lintFile(d, fs.readFileSync(fp, 'utf8'), 'md');
    scanned++;
  }
  const walk = (dir, fn) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const fp = path.join(dir, e.name);
      if (e.isDirectory()) walk(fp, fn); else fn(fp);
    }
  };
  if (fs.existsSync(srcRoot)) walk(srcRoot, (fp) => { if (fp.endsWith('.astro')) lintFile(rel(fp), fs.readFileSync(fp, 'utf8'), 'astro'); });

  if (failures.length) {
    console.error(`\n✗ diagram linter: ${failures.length} problem(s)\n`);
    for (const f of failures) console.error('  ' + f);
    console.error('');
    process.exit(1);
  }
  console.log(`✓ diagram linter: ${scanned} doc(s) (${EXTRA_DOCS.length} off-site) + .astro sources — all frame edges aligned, no retired glyphs.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
