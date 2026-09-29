import { visit } from 'unist-util-visit';
import path from 'node:path';
import { BY_FILE } from '../nav.mjs';

// Manifest-driven link rewriting. For every relative `*.md` link in a doc:
//   • target is in the manifest  -> rewrite to the site route   (/Yuzu/manual/<slug>/)
//   • target is a real repo file -> rewrite to the GitHub blob  (so it still works)
// Absolute URLs, anchors, and non-.md links are left untouched.
const REPO_BLOB = 'https://github.com/DevNullLtd/Yuzu/blob/main';
const BASE = '/Yuzu';

export default function rewriteLinks() {
  const repoRoot = path.resolve(process.cwd(), '..');
  const docsRoot = path.join(repoRoot, 'docs');

  return (tree, file) => {
    const srcPath = file?.path || file?.history?.[0] || '';
    const srcDir = srcPath ? path.dirname(srcPath) : docsRoot;

    visit(tree, 'link', (node) => {
      const url = node.url || '';
      if (/^([a-z]+:|\/\/|#|\/)/i.test(url)) return; // skip absolute / protocol / anchor / root
      const hashIdx = url.indexOf('#');
      const target = hashIdx === -1 ? url : url.slice(0, hashIdx);
      const hash = hashIdx === -1 ? '' : url.slice(hashIdx);
      if (!target.endsWith('.md')) return;

      const abs = path.resolve(srcDir, target);

      // In-scope?  (must live under docs/ and be named in the manifest)
      if (abs === docsRoot || abs.startsWith(docsRoot + path.sep)) {
        const rel = path.relative(docsRoot, abs).split(path.sep).join('/');
        const entry = BY_FILE.get(rel.replace(/\.md$/, ''));
        if (entry) {
          node.url = `${BASE}/manual/${entry.slug}/${hash}`;
          return;
        }
      }

      // Plugin READMEs (agents/plugins/<name>/README.md) are manifest entries
      // too, keyed by their repo-relative path and routed under /plugins/.
      const pluginsRoot = path.join(repoRoot, 'agents', 'plugins');
      if (abs.startsWith(pluginsRoot + path.sep)) {
        const rel = path.relative(repoRoot, abs).split(path.sep).join('/');
        const entry = BY_FILE.get(rel.replace(/\.md$/, ''));
        if (entry) {
          node.url = `${BASE}/${entry.slug}/${hash}`;
          return;
        }
      }

      // Out of scope -> point at GitHub so the link still resolves.
      const repoRel = path.relative(repoRoot, abs).split(path.sep).join('/');
      node.url = `${REPO_BLOB}/${repoRel}${hash}`;
    });
  };
}
