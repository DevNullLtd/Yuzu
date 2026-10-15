// @ts-check
import { defineConfig } from 'astro/config';
import { unified } from '@astrojs/markdown-remark';
import rewriteLinks from './src/remark/rewrite-links.mjs';
import stripFirstH1 from './src/remark/strip-first-h1.mjs';

// GitHub Pages project site: served under /Yuzu/. Change `site` if a custom
// domain is added later (then drop `base`).
//
// The host tracks the repo OWNER and GitHub does NOT redirect Pages on a repo
// transfer the way it redirects repo URLs — a stale host here silently emits
// wrong canonical URLs and a wrong sitemap. Updated for the DevNullLtd org
// transfer (2026-09-28).
export default defineConfig({
  site: 'https://devnullltd.github.io',
  base: '/Yuzu',
  trailingSlash: 'always',
  markdown: {
    // Astro 7: remark plugins ride the explicit unified() processor —
    // markdown.remarkPlugins is deprecated (shikiConfig is not; it stays
    // a sibling option). Manifest-driven link rewriting: in-scope .md
    // links -> site routes, out-of-scope -> GitHub blob URLs, dangling ->
    // build failure.
    processor: unified({
      remarkPlugins: [rewriteLinks, stripFirstH1],
    }),
    shikiConfig: { theme: 'night-owl', wrap: false },
  },
});
