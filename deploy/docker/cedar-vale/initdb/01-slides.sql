-- Cedar & Vale demo — presentation content store.
--
-- This is the "db" tier of the three-tier viz demo. The node "app" tier reads
-- these rows on each page load and renders them as impress.js steps, so the
-- presentation's content genuinely lives in Postgres (per the demo's design):
-- editing a row here changes the live deck on the next reload.
--
-- Runs automatically on first boot via the official postgres image's
-- /docker-entrypoint-initdb.d hook. DROP + CREATE makes a re-seed (or a schema
-- change like data_scale INT->REAL) deterministic on any reused data dir.
--
-- Each row is one impress.js step. The data_* columns are the impress.js
-- canvas transform (https://github.com/impress/impress.js): x/y position the
-- step on the infinite canvas, z dollies in 3D, scale zooms, rotate tilts —
-- together they make the Prezi-style fly-through. Big x/y jumps + z-dolly +
-- rotation here are what make the slide-to-slide motion dramatic; data_scale is
-- REAL so mid-deck zooms can be fractional (1.15, 1.25). body_html is the
-- slide's inner markup, styled by app/public/deck.css.

DROP TABLE IF EXISTS slides;

CREATE TABLE slides (
    position    INT  PRIMARY KEY,
    slug        TEXT NOT NULL,
    title       TEXT NOT NULL,
    body_html   TEXT NOT NULL,
    data_x      INT  NOT NULL,
    data_y      INT  NOT NULL,
    data_z      INT  NOT NULL DEFAULT 0,
    data_rotate INT  NOT NULL DEFAULT 0,
    data_scale  REAL NOT NULL DEFAULT 1
);

INSERT INTO slides (position, slug, title, body_html, data_x, data_y, data_z, data_rotate, data_scale) VALUES
(1, 'title', 'Agentic Colleagues',
 '<p class="eyebrow">Yuzu</p>'
 '<h1>Agentic Colleagues</h1>'
 '<h2>IT''s force multiplier &amp; thinking partner</h2>'
 '<p class="footnote">A presentation about agentic IT &mdash; served by a three-tier app, on a fleet managed by Yuzu, drawn live in Yuzu''s own fleet view.</p>',
 -- transform below each row: data_x, data_y, data_z, data_rotate, data_scale
 0, 0, 0, 0, 2),

(2, 'strain', 'The strain is structural',
 '<h2>The strain is structural</h2>'
 '<ul>'
 '<li><b>Ticket backlog</b> grows faster than headcount.</li>'
 '<li><b>Fleet sprawl</b> &mdash; more endpoints, OSes, and edge than any team can hold in its head.</li>'
 '<li><b>Alert fatigue</b> buries the signal that matters.</li>'
 '<li><b>Tribal knowledge</b> walks out the door with every departure.</li>'
 '</ul>'
 '<p class="footnote">You can''t hire your way out of an exponential.</p>',
 2700, 300, -500, 6, 1),

(3, 'what', 'What an Agentic Colleague is',
 '<h2>What an Agentic Colleague <em>is</em></h2>'
 '<p>Not a chatbot. Not autocomplete for runbooks.</p>'
 '<p>An <b>operator</b> that can, across the whole fleet, in real time:</p>'
 '<ul>'
 '<li><b>Query</b> &mdash; ask the fleet anything and get a live answer.</li>'
 '<li><b>Command</b> &mdash; act on the answer at scale.</li>'
 '<li><b>Scan &amp; patch</b> &mdash; find exposure, close it.</li>'
 '<li><b>Enforce</b> &mdash; hold desired state, continuously.</li>'
 '</ul>',
 4900, 1700, 700, -10, 1.25),

(4, 'force', 'Force multiplier',
 '<h2>Force multiplier</h2>'
 '<p>One human + agentic colleagues = <b>fleet-wide action from a single intent</b>.</p>'
 '<ul>'
 '<li><b>Scope engine</b> targets the right machines by expression, not by spreadsheet.</li>'
 '<li><b>Instructions</b> turn intent into a typed, auditable command.</li>'
 '<li><b>Guaranteed-state policy</b> makes "stay fixed" the default, not a follow-up ticket.</li>'
 '</ul>'
 '<p class="footnote">The human sets direction. The colleagues cover the distance.</p>',
 4400, 3800, -700, 92, 1),

(5, 'thinking', 'Thinking partner',
 '<h2>Thinking partner</h2>'
 '<p>A multiplier executes. A <em>colleague</em> reasons.</p>'
 '<ul>'
 '<li><b>Scope-walking</b> &mdash; one query''s results become the next query''s target.</li>'
 '<li><b>Echo</b> &mdash; time-aware retention to ask "what changed, and when?"</li>'
 '<li><b>Reasoning over live inventory</b> &mdash; correlate, hypothesise, propose &mdash; not just run.</li>'
 '</ul>'
 '<p class="footnote">It brings you the question behind the question.</p>',
 2100, 4400, 600, 9, 1.15),

(6, 'how', 'How it runs',
 '<h2>How it runs</h2>'
 '<p>A single control plane, built for both humans and agents:</p>'
 '<ul>'
 '<li><b>Server / Gateway / Agent</b> &mdash; one control plane, millions of endpoints.</li>'
 '<li><b>MCP + REST + dashboard</b> &mdash; every surface an agent can drive, a human can too.</li>'
 '</ul>'
 '<p class="callout">&mdash; and this very deck is running on it: Envoy &rarr; node &rarr; Postgres, three managed agents, drawn live in the fleet view you''re about to see.</p>',
 -400, 3900, -600, -6, 1),

(7, 'trust', 'Trust &amp; governance',
 '<h2>Trust &amp; governance</h2>'
 '<p>Agentic-first <b>without</b> losing control:</p>'
 '<ul>'
 '<li><b>RBAC</b> &mdash; tier-before-permission, least privilege by default.</li>'
 '<li><b>Audit trail</b> &mdash; who did what, when, on which devices.</li>'
 '<li><b>Guardrails &amp; kill switches</b> &mdash; bounded autonomy, reversible by design.</li>'
 '<li><b>SOC 2 path</b> &mdash; evidence generated as a by-product of doing the work.</li>'
 '</ul>',
 -2400, 2200, 800, -34, 1.2),

(8, 'vision', 'Your fleet, with colleagues',
 '<h1>Your fleet, with colleagues</h1>'
 '<h2>Today.</h2>'
 '<p class="footnote">Yuzu &mdash; agentic endpoint management.</p>',
 1100, 1700, -300, 0, 5);
