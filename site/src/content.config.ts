import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { ENTRIES } from './nav.mjs';

// Read the canonical Markdown DIRECTLY from the repo's docs/ tree — no copy,
// single source of truth, drift impossible. The glob is scoped to exactly the
// files named in the curation manifest (src/nav.mjs), so inclusion is
// manifest-driven and unrelated docs are never parsed.
const manual = defineCollection({
  loader: glob({
    base: '../docs',
    pattern: ENTRIES.filter((e) => !e.file.startsWith('agents/')).map((e) => `${e.file}.md`),
  }),
});

// Plugin READMEs live beside their code (docs/plugin-readme-standard.md rule 1)
// and are read from there for the same drift-impossible reason. Which plugins
// appear is decided by the generated fragment src/nav.plugins.mjs — every
// plugin that has adopted the standard — so this glob is manifest-driven too.
const plugins = defineCollection({
  loader: glob({
    base: '../agents/plugins',
    pattern: ENTRIES.filter((e) => e.file.startsWith('agents/plugins/')).map(
      (e) => `${e.file.replace(/^agents\/plugins\//, '')}.md`,
    ),
  }),
});

export const collections = { manual, plugins };
