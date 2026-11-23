// Generates the three documentation endpoints from one place so they cannot drift from the tool:
//   how-to/index.html      how to use the tool
//   what-is/index.html     what STRIDE is and why it matters
//   how-to-max/index.html  worked threat models (web app, microservices, input→process→store, IVR)
// The worked examples embed the real spec files in how-to-max/specs/*.json.
//
//   node scripts/build-docs.mjs          write the pages
//   node scripts/build-docs.mjs --check  fail if the committed pages are out of date

import fs from 'node:fs';
import path from 'node:path';
import { ROOT } from './static-server.mjs';

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const spec = (name) => fs.readFileSync(path.join(ROOT, 'how-to-max/specs', `${name}.json`), 'utf8');

const NAV = [
  ['../index.html', 'Open the app'],
  ['../how-to/index.html', 'How to use it'],
  ['../what-is/index.html', 'What is STRIDE'],
  ['../how-to-max/index.html', 'Worked examples'],
];

function page({ slug, title, lead, toc, body }) {
  const nav = NAV.map(([href, label]) => `<a href="${href}"${href.includes(`/${slug}/`) ? ' aria-current="page"' : ''}>${esc(label)}</a>`).join('');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · STRIDE Threat Modeler</title>
<meta name="description" content="${esc(lead)}">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'">
<link rel="icon" type="image/png" sizes="32x32" href="../assets/favicon-32.png">
<link rel="stylesheet" href="../assets/docs.css">
</head>
<body>
<header class="top"><a class="brand" href="../index.html"><img src="../assets/logo-64.png" alt="" width="28" height="28"><span>STRIDE</span></a><nav aria-label="Documentation">${nav}</nav></header>
<div class="wrap">
<aside class="toc" aria-label="On this page"><b>On this page</b><ul>${toc.map(([id, t]) => `<li><a href="#${id}">${esc(t)}</a></li>`).join('')}</ul></aside>
<main>
<h1>${esc(title)}</h1>
<p class="lead">${lead}</p>
${body}
<footer>STRIDE Threat Modeler. Generated threats are a starting point for expert review, not a guarantee of security.</footer>
</main>
</div>
</body>
</html>
`;
}

const table = (head, rows) => `<div class="tw"><table><thead><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
const note = (kind, html) => `<div class="note ${kind}">${html}</div>`;
const kbd = (s) => `<kbd>${s}</kbd>`;

// ====================================================================== how-to
const howTo = () => {
  const toc = [
    ['start', 'Start in two minutes'],
    ['screen', 'The screen'],
    ['parts', 'What each building block means'],
    ['draw', 'Drawing a diagram'],
    ['boundaries', 'Trust boundaries'],
    ['threats', 'How threats are generated'],
    ['triage', 'Working through threats'],
    ['look', 'Colours, groups and focus mode'],
    ['reports', 'Reports and fonts'],
    ['files', 'Saving, opening, templates'],
    ['auto', 'Building models from code (CLI and MCP)'],
    ['keys', 'Keyboard shortcuts'],
    ['trouble', 'If something looks wrong'],
  ];
  const body = `
<section id="start"><h2>Start in two minutes</h2>
<ol class="steps">
<li><b>Open the example.</b> Choose <i>File → Open example model</i>. It is a small online shop, already drawn, with its threats generated.</li>
<li><b>Look at the picture.</b> Boxes and ovals are parts of the system, arrows are information moving between them, red dashed lines are trust boundaries.</li>
<li><b>Open the <i>Analyze</i> view</b> (top right). The threat list appears at the bottom, best findings first.</li>
<li><b>Open a threat.</b> Read what could go wrong, where, and the suggested mitigation. Set its state and add a justification.</li>
<li><b>Start your own</b> with <i>File → New model</i>, then follow “Drawing a diagram” below.</li>
</ol>
${note('tip', 'Everything runs in your browser. Nothing is uploaded. Your work is autosaved in this browser; use <i>File → Save</i> to keep a file.')}
</section>

<section id="screen"><h2>The screen</h2>
${table(
  ['Area', 'What it does'],
  [
    ['<b>Top bar</b>', 'File menu, diagram tabs, <i>Design / Analyze</i> switch, undo and redo, <i>Report</i> menu, buttons to hide the stencil pane, the threat model panel and the threat list, settings.'],
    ['<b>Stencils</b> (left)', 'The parts you can draw. Click one then click the canvas, or drag it in. Type in the search box, or press ' + kbd('/') + ' anywhere to search; with nothing typed it lists the most used stencils (trust boundaries, Web Service, data store).'],
    ['<b>Canvas</b> (middle)', 'The diagram. Floating tool bar on top, zoom controls bottom-left, element and open-threat count bottom-right.'],
    ['<b>Threat model panel</b> (right)', 'With nothing selected it shows model details (name, owner, description, assumptions) and counts by state. Select an element and it shows that element’s properties, colour and the threats that apply to it.'],
    ['<b>Threat list</b> (bottom)', 'Tabs for <i>Threats</i>, <i>Messages</i> (problems with your diagram) and <i>Notes</i>.'],
  ],
)}
<p><b>Design</b> is for drawing and editing. <b>Analyze</b> is look-only: the tool bar is hidden and you can only pan and zoom, so you can study threats without moving anything by accident.</p>
</section>

<section id="parts"><h2>What each building block means</h2>
<p>A diagram in this tool is a <b>data flow diagram</b>: who and what is involved, and how information moves between them.</p>
${table(
  ['Block', 'Drawn as', 'Meaning', 'Examples'],
  [
    ['<b>Process</b>', 'Oval', 'Code that runs and handles data. It receives input, does something and sends output.', 'Web application, API, background worker, mobile app, IVR platform'],
    ['<b>External interactor</b>', 'Rectangle', 'A person or system <i>outside</i> your control that talks to yours. You cannot fix it, only defend against it.', 'Customer, payment provider, partner API, phone carrier'],
    ['<b>Data store</b>', 'Two horizontal lines', 'Anything that keeps data at rest.', 'SQL database, file share, object storage, queue, cache, log files'],
    ['<b>Data flow</b>', 'Arrow', 'Information moving from one element to another. Direction matters: draw one arrow per direction if both ways carry data.', 'HTTPS request, SQL query, message on a queue, file upload'],
    ['<b>Trust boundary</b>', 'Red dashed box or line', 'Where the level of trust changes: who controls what is on each side. Threats are generated mainly where a flow crosses one.', 'Internet ↔ your network, user device ↔ server, app ↔ database tier, your system ↔ a vendor'],
    ['<b>Annotation</b>', 'Faint note box', 'A comment for readers. It never produces threats.', 'Assumptions, “payments handled by provider”'],
  ],
)}
<p>Each stencil has a <b>type</b> (for example <i>Web Service</i> or <i>SQL Database</i>). The type matters: it carries <b>properties</b> such as “implements authentication”, and the threat rules read those properties. Pick the most specific type you can, and fill in the properties in the right-hand panel.</p>
</section>

<section id="draw"><h2>Drawing a diagram</h2>
<ol class="steps">
<li><b>Place elements.</b> Press ${kbd('P')} (process), ${kbd('E')} (external), ${kbd('D')} (data store), click the canvas, then type a name. Names appear in the generated threats, so use real names (“Orders API”, not “Service 2”).</li>
<li><b>Connect them.</b> Press ${kbd('F')} and drag from the source element to the target. The arrow snaps to both ends. Name it after what it carries (“Card payment”, “Order JSON”).</li>
<li><b>Set types and properties.</b> Select an element, choose its <i>Type</i>, and answer its properties. Answer honestly, “unknown” is better than a guess.</li>
<li><b>Draw trust boundaries</b> (next section).</li>
<li><b>Check the Messages tab.</b> It tells you about unconnected flows, missing boundaries and other gaps.</li>
</ol>
<p>Handy: double-click a name to rename, drag corners to resize, drag the small circle on a selected arrow to bend it, hold ${kbd('Alt')} while dragging to duplicate, and double-click empty canvas to drop a note.</p>
</section>

<section id="boundaries"><h2>Trust boundaries</h2>
<p>A trust boundary separates things that trust each other differently. Draw one wherever control, network, identity or privilege changes.</p>
<ul>
<li><b>Box boundary</b> (${kbd('B')}): drag a rectangle around the elements that live together, for example “Internal network”. Any flow that goes in or out crosses it.</li>
<li><b>Arc boundary</b> (${kbd('L')}): drag a line across the flows that change trust, for example between a user device and the internet.</li>
</ul>
${note('tip', 'Crossing is geometric: a flow crosses a boundary if the drawn arrow actually cuts the boundary line. If an expected threat is missing, check that the arrow really crosses the boundary.')}
</section>

<section id="threats"><h2>How threats are generated</h2>
<p>Threats appear automatically a moment after you change the diagram (switch it off with <i>Generate threats automatically</i> in the threat model panel). For every data flow the tool looks at the source, the target, the flow type, their properties and which boundaries the flow crosses, then applies the rules of the <b>template</b> (default: <i>STRIDE Core</i>). Each match becomes a threat in one of the six STRIDE categories: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege.</p>
<p>So more detail gives better threats: connect every element, name every flow, set types and properties, and draw the boundaries.</p>
<h3>High-signal threats</h3>
<p>A big model can produce many generic threats. Each threat is scored; the <b>High signal</b> ones are backed by something concrete: source-code evidence, a dangerous call such as running a shell command, a weak control, or sensitive data. The <i>High-signal view</i> in the threat list shows only those, best first. Similar threats across many flows are collapsed into one with “Related flows: N”.</p>
</section>

<section id="triage"><h2>Working through threats</h2>
<p>Open a threat from the list. For each one decide:</p>
${table(
  ['State', 'Use when'],
  [
    ['Not Started', 'Nobody has looked at it yet (all new threats start here).'],
    ['Needs Investigation', 'It may be real; someone has to find out.'],
    ['Mitigation Implemented', 'A control already exists or has been built. Say which one in the justification.'],
    ['Not Applicable', 'It cannot happen here. Write why.'],
  ],
)}
<p>Set a <b>priority</b> (High / Medium / Low) and write a <b>justification</b>. Your decisions are kept when threats regenerate. You can edit a threat’s title, description and mitigation, and use <i>Add threat</i> on a flow for something the rules did not find. Threats whose flow was deleted are shown as “no longer present” so your triage is never silently lost.</p>
</section>

<section id="look"><h2>Colours, groups and focus mode</h2>
<ul>
<li><b>Line colours.</b> Every element gets its own colour and all arrows leaving it use that colour, so arrows entering an element are told apart by where they come from. Select an element to change its <i>Egress colour</i>, or select one arrow to change just that <i>Line colour</i>. <i>Reset</i> returns to the default.</li>
<li><b>Clean routing.</b> Arrows leaving an element share one exit point and fan out; each arrow entering an element gets its own entry point; arrows from different elements avoid running over each other.</li>
<li><b>Groups.</b> Select several elements and press ${kbd('G')} (or <i>Group</i> in the panel). They now select and move as one. ${kbd('Shift+G')} ungroups. Groups show a faint dashed outline.</li>
<li><b>Focus mode.</b> ${kbd('Ctrl/⌘+.')} hides every menu and panel so only the diagram remains; ${kbd('Esc')} brings them back. Press ${kbd('H')} for hand mode to pan around, and ${kbd('/')} to search stencils.</li>
</ul>
</section>

<section id="reports"><h2>Reports and fonts</h2>
<p>Open the <b>Report</b> menu and choose <i>Download report…</i> to pick the report type and the font, then <i>Open in new tab</i> or <i>Download</i>.</p>
${table(
  ['Report', 'For', 'What is in it'],
  [
    ['<b>Executive summary</b>', 'Senior management, sponsors, auditors who want the answer', 'One page of large, plain-language text: overall status, four headline numbers, the system picture, the five risks that matter most with a recommended action, and suggested next steps. No rule names, file paths or per-flow detail.'],
    ['<b>Technical report</b>', 'Engineers and security reviewers', 'Executive summary, high-signal findings table with evidence, every diagram, every threat grouped by interaction, validation messages.'],
    ['Markdown summary', 'Pull requests, chat, agents', 'The same stakeholder-first content as plain text.'],
    ['Threat list (CSV)', 'Spreadsheets and trackers', 'One row per threat, with spreadsheet-formula protection.'],
    ['Diagram (SVG)', 'Slides and documents', 'The current diagram as a vector image.'],
  ],
)}
<p><b>Fonts.</b> HTML reports can use any font that is installed on the computer that opens them: System default, Arial, Verdana (very clear, wide letters), Tahoma, Trebuchet MS, Calibri, Georgia, Times New Roman, Monospace, or type the name of any other installed font. The report uses your choice for all text including the diagram labels. Open the report on a machine without that font and the browser falls back to a default. Use the browser’s print dialog to save a report as PDF.</p>
</section>

<section id="files"><h2>Saving, opening, templates</h2>
<ul>
<li><b>Save / Open</b> (${kbd('Ctrl/⌘+S')}, ${kbd('Ctrl/⌘+O')}) work with a <code>.stride.json</code> file. The model is also autosaved in this browser, but a saved file is the only copy you control.</li>
<li><b>Templates</b> define the element types and the threat rules. Import a Microsoft Threat Modeling Tool template (<code>.tb7</code>) from <i>File → Import template</i>, or open <i>Template &amp; rules…</i> to read and edit the rules. Threats are regenerated and your triage is kept.</li>
<li><b>Multiple diagrams.</b> Use the <b>+</b> next to the tabs. Double-click a tab to rename it.</li>
</ul>
</section>

<section id="auto"><h2>Building models from code (CLI and MCP)</h2>
<p>The same engine runs without the browser, which is useful for CI and for AI agents that read a repository.</p>
<pre><code>stride sync threatmodel/model.json threatmodel/spec.json   # build or update a model from a spec
stride report model.json --format exec --font verdana -o summary.html   # executive report
stride report model.json -o report.html                    # technical report
stride mcp                                                  # Model Context Protocol server</code></pre>
<p>A spec lists trust <i>zones</i>, <i>elements</i> and <i>flows</i>; sync lays the diagram out so every flow crosses exactly the right boundaries. See the <a href="../how-to-max/index.html">worked examples</a> for four complete specs you can run as they are.</p>
</section>

<section id="keys"><h2>Keyboard shortcuts</h2>
${table(
  ['Key', 'Action'],
  [
    [kbd('V') + ' / ' + kbd('1'), 'Select'],
    [kbd('H'), 'Hand (pan). Space+drag also pans'],
    [kbd('P') + ' ' + kbd('E') + ' ' + kbd('D'), 'Process, external interactor, data store (also 2, 3, 4)'],
    [kbd('F'), 'Data flow: drag from source to target (5)'],
    [kbd('L') + ' ' + kbd('B') + ' ' + kbd('T'), 'Arc boundary, box boundary, annotation (6, 7, 8)'],
    [kbd('G') + ' / ' + kbd('Shift+G'), 'Group / ungroup (also Ctrl/⌘+G, Ctrl/⌘+Shift+G)'],
    [kbd('/'), 'Search stencils'],
    [kbd('Ctrl/⌘+.'), 'Focus mode on/off (Esc leaves it)'],
    [kbd('Enter') + ' / double-click', 'Rename'],
    [kbd('Delete'), 'Delete selection'],
    [kbd('Ctrl/⌘+C') + ' ' + kbd('V') + ' ' + kbd('D'), 'Copy, paste, duplicate'],
    [kbd('Ctrl/⌘+Z') + ' / ' + kbd('Shift+Z'), 'Undo / redo'],
    [kbd('Ctrl/⌘+A'), 'Select all'],
    ['Arrows (' + kbd('Shift') + ' = 20px)', 'Nudge'],
    ['Wheel, ' + kbd('Ctrl/⌘') + '+wheel, ' + kbd('+') + ' ' + kbd('−') + ', ' + kbd('Shift+1'), 'Pan, zoom, zoom, fit to screen'],
    [kbd('Ctrl/⌘+S'), 'Save'],
    [kbd('?'), 'Show this list in the app'],
  ],
)}
<p>In the Analyze view only pan, zoom and fit work, by design.</p>
</section>

<section id="trouble"><h2>If something looks wrong</h2>
${table(
  ['You see', 'Try'],
  [
    ['No threats appear', 'Connect elements with data flows (' + kbd('F') + ') and check <i>Generate threats automatically</i> is on. A diagram with no flows has nothing to analyse.'],
    ['A boundary-related threat is missing', 'Make sure a flow arrow truly crosses the boundary line, and that the right elements are inside the box.'],
    ['Messages tab shows warnings', 'Each message names the element. The common ones: unconnected flow, flow between two external interactors (usually out of scope), no trust boundary.'],
    ['The tool bar is missing', 'You are in Analyze view or focus mode. Switch to Design, or press Esc.'],
    ['The stencil pane is hidden', 'Use the first button in the top bar, or press / to search without it.'],
    ['Autosave warning', 'The browser blocked storage. Save to a file.'],
  ],
)}
</section>`;
  return page({ slug: 'how-to', title: 'How to use STRIDE Threat Modeler', lead: 'A practical guide for everyone who uses the tool: what each part of the screen and each building block means, how to draw a diagram, how threats are generated and how to work through them, and how to produce reports.', toc, body });
};

// ====================================================================== what-is
const whatIs = () => {
  const toc = [
    ['short', 'In one minute'],
    ['model', 'What a threat model is'],
    ['stride', 'The six STRIDE threats'],
    ['why', 'Why it matters'],
    ['who', 'What it means for your role'],
    ['when', 'When to do it'],
    ['limits', 'What STRIDE does not do'],
    ['words', 'Words you will hear'],
  ];
  const body = `
<section id="short"><h2>In one minute</h2>
<p><b>STRIDE</b> is a checklist for finding security problems in a design <i>before</i> the software is built (or while it is changed). It names six kinds of attack, one per letter, and you ask of every part of your system: “could this happen here?” It was created at Microsoft in the late 1990s (Loren Kohnfelder and Praerit Garg) and is now one of the most widely used threat-modeling methods.</p>
<p>The process is: <b>draw</b> how the system works, <b>ask</b> the six questions at every place information moves or is stored, <b>decide</b> what to do about each answer, and <b>write it down</b>. This tool automates the asking and the bookkeeping so people can spend their time on the deciding.</p>
</section>

<section id="model"><h2>What a threat model is</h2>
<p>A threat model answers four questions:</p>
<ol class="steps">
<li><b>What are we building?</b> A simple diagram of the parts and the information flowing between them.</li>
<li><b>What can go wrong?</b> The six STRIDE questions, applied to each part and flow.</li>
<li><b>What are we going to do about it?</b> Fix it, reduce it, accept it knowingly, or hand it to someone else (for example a vendor).</li>
<li><b>Did we do a good job?</b> Review it, and revisit when the design changes.</li>
</ol>
<p>It is a living document, not a one-off report. Small and honest beats big and abandoned.</p>
</section>

<section id="stride"><h2>The six STRIDE threats</h2>
${table(
  ['', 'Threat', 'Plain meaning', 'Property it breaks', 'Everyday example', 'Typical defence'],
  [
    ['<b>S</b>', 'Spoofing', 'Pretending to be someone or something else', 'Authenticity', 'A caller fakes the number of a real customer; a stolen session cookie', 'Strong authentication, signed tokens, mutual TLS, caller verification'],
    ['<b>T</b>', 'Tampering', 'Changing data or code without permission', 'Integrity', 'Editing a price in a request; altering a file in storage', 'Input validation, signatures, access control, checksums'],
    ['<b>R</b>', 'Repudiation', 'Denying you did something, with no way to prove otherwise', 'Non-repudiation', 'A refund issued and nobody can say by whom', 'Audit logs that cannot be edited, signed records'],
    ['<b>I</b>', 'Information disclosure', 'Exposing data to people who should not see it', 'Confidentiality', 'A database backup left public; secrets in logs; call recordings with card numbers', 'Encryption, least privilege, data minimisation, masking'],
    ['<b>D</b>', 'Denial of service', 'Making the service slow or unavailable', 'Availability', 'Flooding a login page; one huge upload that exhausts disk', 'Rate limits, quotas, timeouts, scaling, queues'],
    ['<b>E</b>', 'Elevation of privilege', 'Getting more power than intended', 'Authorization', 'A normal user reaching an admin function; code execution through unsafe input', 'Server-side authorization checks, sandboxing, least privilege'],
  ],
)}
<p>A quick way to remember it: <b>S</b>, <b>T</b>, <b>R</b> are about <i>who did what and whether we can trust it</i>; <b>I</b>, <b>D</b> are about <i>data and service being there for the right people</i>; <b>E</b> is about <i>how far an attacker can get</i>.</p>
</section>

<section id="why"><h2>Why it matters</h2>
<ul>
<li><b>Cheaper.</b> A design flaw found on a whiteboard costs a conversation. The same flaw found in production costs an incident, a fix, a release and sometimes a notification to customers.</li>
<li><b>It finds what scanners cannot.</b> Scanners find bugs in code that exists. A threat model finds missing controls: the service that trusts any caller, the queue nobody authenticates, the recording that keeps card numbers.</li>
<li><b>One shared language.</b> Developers, operations, security and managers can point at the same diagram and the same six words.</li>
<li><b>Focus.</b> Not everything is equally risky. The model shows where data crosses trust boundaries, which is where attackers operate, so limited review time goes there first.</li>
<li><b>Evidence.</b> Customers, auditors and regulators increasingly ask for one. A maintained model with decisions and reasons is that evidence.</li>
<li><b>Fewer surprises later.</b> Third-party dependencies, new integrations and new data types get a deliberate look instead of an accidental one.</li>
</ul>
</section>

<section id="who"><h2>What it means for your role</h2>
<div class="cols">
<div class="card"><h3>Developers</h3>
<p>You know how the system really works, so you are the best person to draw it. Use the model to:</p>
<ul><li>Decide where input must be validated and where authorization must be checked.</li><li>Turn a threat into a concrete task or test (“every endpoint rejects a user without the role”).</li><li>Attach <code>file:line</code> evidence so findings point at code.</li><li>Update it in the same pull request that changes the architecture.</li></ul></div>
<div class="card"><h3>IT and operations</h3>
<p>You own the network, the platform and the secrets. Use the model to:</p>
<ul><li>Confirm that trust boundaries match reality (network segments, VPCs, accounts).</li><li>Check logging, monitoring and backups against the Repudiation and Denial-of-service threats.</li><li>Find where credentials and keys travel and who can read them.</li><li>Plan capacity and rate limits where flows are exposed to the internet.</li></ul></div>
<div class="card"><h3>Security engineers</h3>
<p>You review many systems. Use the model to:</p>
<ul><li>Review a design in minutes instead of reading code for days.</li><li>Rank findings: high-signal first, generic ones for architectural review.</li><li>Spot patterns that repeat across services and fix them once.</li><li>Keep a record of decisions, accepted risks and their reasons.</li></ul></div>
<div class="card"><h3>Product and management</h3>
<p>You decide how much risk is acceptable. Use the model to:</p>
<ul><li>Read the <b>executive summary</b>: status, headline numbers, the risks that matter most.</li><li>Ask for an owner and a date for each high-priority risk.</li><li>Make accept/fix decisions knowingly and have them recorded.</li></ul></div>
</div>
</section>

<section id="when"><h2>When to do it</h2>
<ul>
<li>Before building a new system or a big feature, when changes are cheap.</li>
<li>When the architecture changes: a new integration, a new data type, a move to the cloud, a new vendor.</li>
<li>After an incident or a penetration test, to see what the model missed.</li>
<li>On a schedule for important systems, because systems drift.</li>
</ul>
<p>A first pass of a typical service takes an hour or two with the people who know it. The <a href="../how-to-max/index.html">worked examples</a> show what the diagram should look like for common systems.</p>
</section>

<section id="limits"><h2>What STRIDE does not do</h2>
<ul>
<li><b>It does not find code bugs.</b> It tells you where to look and what to demand; it does not read your source for injection flaws.</li>
<li><b>It does not rate business impact for you.</b> Priority here is a starting guess. People who know the business should set it.</li>
<li><b>It is only as good as the diagram.</b> A missing flow means missing threats. Review the diagram with someone who did not draw it.</li>
<li><b>Generated threats are prompts, not verdicts.</b> Some will not apply; some real threats will not be generated. Expert judgment stays in the loop.</li>
<li><b>It is not a one-time certificate.</b> A model that is not kept current gives false comfort.</li>
</ul>
</section>

<section id="words"><h2>Words you will hear</h2>
${table(
  ['Term', 'Meaning'],
  [
    ['Data flow diagram (DFD)', 'The picture: processes, external interactors, data stores, data flows and trust boundaries.'],
    ['Trust boundary', 'A line where the level of trust changes, such as internet to internal network.'],
    ['Attack surface', 'Every place an attacker can reach or influence: endpoints, inputs, file uploads, integrations.'],
    ['Mitigation', 'A control that reduces a threat: validation, encryption, authorization check, rate limit.'],
    ['Residual risk', 'What is left after mitigation. It is accepted explicitly by someone with the authority to do so.'],
    ['Template', 'The set of element types and threat rules the tool applies. The default is STRIDE Core; Microsoft’s <code>.tb7</code> templates can be imported.'],
    ['High signal', 'A threat backed by concrete evidence such as a dangerous code path or sensitive data, as opposed to a generic architectural prompt.'],
  ],
)}
<p>Ready to try it? Read <a href="../how-to/index.html">How to use the tool</a>, or open the <a href="../index.html">app</a> and choose <i>File → Open example model</i>.</p>
</section>`;
  return page({ slug: 'what-is', title: 'What is STRIDE, and why it matters', lead: 'An introduction for developers, IT and operations, security engineers and managers: what STRIDE is, what a threat model is, why teams do it, and what it means for your role.', toc, body });
};

// ====================================================================== how-to-max
const rows = (list) => list.map(([a, b, c]) => [esc(a), esc(b), c ? esc(c) : '']);

function scenario({ id, title, when, goal, boundaries, elements, flows, look, mistakes, name, steps }) {
  const s = spec(name);
  return `<section id="${id}"><h2>${esc(title)}</h2>
<p><b>Use this when:</b> ${when}</p>
<p>${goal}</p>
<h3>1. Draw it</h3>
<p><b>Trust boundaries (box):</b> ${boundaries}</p>
${table(['Element', 'Stencil type', 'Where / notes'], rows(elements))}
${table(['Data flow (from → to)', 'Carries', 'Crosses'], rows(flows))}
<h3>2. What to look for</h3>
${table(['STRIDE', 'Where', 'Question to ask', 'Typical fix'], look.map(([a, b, c, d]) => [`<b>${a}</b>`, esc(b), esc(c), esc(d)]))}
<h3>3. Mistakes to avoid</h3>
<ul>${mistakes.map((m) => `<li>${m}</li>`).join('')}</ul>
<h3>4. Build it automatically</h3>
<p>${steps}</p>
<pre><code>stride sync ${name}.model.json how-to-max/specs/${name}.json
stride report ${name}.model.json --format exec -o ${name}-summary.html</code></pre>
<details><summary>Show the spec (<a href="specs/${name}.json" download>download ${name}.json</a>)</summary><pre><code>${esc(s)}</code></pre></details>
</section>`;
}

const howToMax = () => {
  const toc = [
    ['recipe', 'The recipe'],
    ['web-app', 'A normal web app'],
    ['microservices', 'Microservices'],
    ['intake', 'Input → process → store → retrieve'],
    ['ivr', 'IVR with a support portal'],
    ['review', 'Reviewing any model'],
  ];
  const recipe = `<section id="recipe"><h2>The recipe (works for any system)</h2>
<ol class="steps">
<li><b>List the actors.</b> Every person and outside system that touches yours becomes an <i>external interactor</i>.</li>
<li><b>List the code that runs.</b> Each deployable thing becomes a <i>process</i>. If two things are deployed and secured separately, draw two.</li>
<li><b>List where data rests.</b> Databases, buckets, queues, caches, logs, recordings: each is a <i>data store</i>.</li>
<li><b>Draw every data flow, one arrow per direction,</b> named after what it carries. Include the boring ones (logging, monitoring, backups); attackers do.</li>
<li><b>Draw trust boundaries</b> where control, network or identity changes. Put a vendor on the far side of a boundary.</li>
<li><b>Set types and properties</b>, then read the high-signal threats first and triage.</li>
<li><b>Write down assumptions</b> in the model details (“traffic inside the cluster is mutually authenticated”). An unchecked assumption is where most real incidents hide.</li>
</ol>
<p>Each example below can be built in one command from the spec shown. Run it, open the result in the app, then change it to match your own system.</p>
</section>`;

  const web = scenario({
    id: 'web-app', title: 'A normal web app', name: 'web-app',
    when: 'a browser-based product: public pages, logins, a database behind it.',
    goal: 'The most common shape: a user, a browser, a public web server, an application, a database, and one outside service (email).',
    boundaries: '<i>User device</i> (the browser is not under your control), <i>Public zone (DMZ)</i>, <i>Internal network</i>.',
    elements: [['Visitor', 'Human User (external)', 'The person using the site'], ['Browser', 'Browser Client (process)', 'In “User device”: you do not control it'], ['Web server', 'Web Server (process)', 'In the public zone: terminates TLS, proxies'], ['Web application', 'Web Application (process)', 'Internal: business logic, sessions'], ['Database', 'SQL Database (store)', 'Internal: accounts and orders'], ['Email provider', 'External Web Service', 'Outside: sends reset emails']],
    flows: [['Visitor → Browser, Browser → Web server', 'Clicks, typing, page and API requests (HTTPS)', 'User device → Public zone'], ['Web server → Web application and back', 'Forwarded requests, rendered responses', 'Public zone → Internal'], ['Web application ↔ Database', 'SQL queries and results', 'Inside Internal'], ['Web application → Email provider', 'Password-reset emails', 'Internal → outside']],
    look: [['S', 'Browser → Web server', 'Can someone reuse or forge a session? Is login protected against guessing?', 'Strong sessions, MFA, lockout, secure cookies'], ['T', 'Browser → Web application', 'Is every field validated on the server? Can a user change a price or role in the request?', 'Server-side validation, parameterised queries'], ['I', 'Web application → Database', 'Is the database reachable from anywhere else? Are secrets or personal data logged?', 'Network rules, least-privilege DB account, encryption at rest'], ['D', 'Public zone', 'What stops one client from flooding login or search?', 'Rate limits, timeouts, caching'], ['E', 'Web application', 'Is authorization checked on the server for every action, not just hidden in the UI?', 'Deny-by-default checks and tests per role'], ['R', 'Web application', 'Can an admin action be traced to a person?', 'Audit log with user, time, action']],
    mistakes: ['Drawing only “the website” as one oval. Split web server, application and database so boundaries have something to cross.', 'Forgetting the reverse flows (responses, query results). Data leaves on them.', 'Leaving out the email provider and other third parties: they hold your users’ data too.'],
    steps: 'This spec has 6 elements, 8 flows and 3 zones and produces about 50 threats with no validation warnings.',
  });
  const micro = scenario({
    id: 'microservices', title: 'Microservices', name: 'microservices',
    when: 'several small services behind an API gateway, talking to each other and through a message broker.',
    goal: 'The risk moves inside: many internal calls, each a chance for a missing check. Model every service-to-service call.',
    boundaries: '<i>Public edge</i> (gateway), <i>Service cluster</i>, <i>Data tier</i>. Add a boundary per team or per sensitivity (for example around payments) as the system grows.',
    elements: [['Customer client', 'Browser (external)', 'Web or mobile client'], ['API gateway', 'Web Server (process)', 'The only public entry point'], ['Identity service', 'Web Service (process)', 'Issues and validates tokens'], ['Orders / Inventory / Payments service', 'Web Service (process) ×3', 'One process per deployable service'], ['Message broker', 'Generic Data Store', 'Queue or topics: it stores messages'], ['Orders DB, Inventory DB', 'SQL Database (store) ×2', 'One database per service'], ['Payment provider', 'External Web Service', 'Outside']],
    flows: [['Customer client ↔ API gateway', 'API requests and responses', 'Internet → Public edge'], ['API gateway → Identity / Orders', 'Token validation, order requests', 'Edge → Cluster'], ['Orders → Inventory, Payments', 'Reserve stock, charge request', 'Inside Cluster'], ['Orders ↔ Message broker ↔ Inventory', 'Order events', 'Inside Cluster'], ['Orders / Inventory → their DBs', 'Reads and writes', 'Cluster → Data tier'], ['Payments → Payment provider', 'Card charge', 'Cluster → outside']],
    look: [['S', 'Service → service', 'Does a service verify who is calling it, or does it trust anything inside the network?', 'Mutual TLS, service identities, signed tokens'], ['T', 'Message broker', 'Can any service publish any event? Are messages validated by the consumer?', 'Per-topic permissions, schema validation'], ['I', 'Services → DBs', 'Can the Orders service read the Inventory database? Do tokens carry more than needed?', 'One credential per service, scoped tokens'], ['D', 'Gateway, broker', 'What happens when one service is slow: do callers pile up?', 'Timeouts, circuit breakers, queue limits'], ['E', 'API gateway → Orders', 'Is the end user’s identity passed on and checked again behind the gateway?', 'Re-check authorization in each service'], ['R', 'Payments', 'Is each charge traceable end to end?', 'Correlation ids, immutable audit trail']],
    mistakes: ['Assuming “inside the cluster” means trusted. Draw the flows and ask who authenticates them.', 'One diagram for 40 services. Make one diagram per business flow (checkout, signup) and reuse the element names.', 'Forgetting the broker is a data store: it holds data and needs access control and retention rules.'],
    steps: 'Spec: 10 elements, 11 flows, 3 zones; about 56 threats.',
  });
  const intake = scenario({
    id: 'intake', title: 'A complex application: input → process → store → retrieve', name: 'intake-platform',
    when: 'the app accepts content or data from users, processes it (parsing, scanning, converting, enriching), stores it, and later retrieves it for the same or other users.',
    goal: 'Examples: document upload, claims intake, media processing, form builders, data import. The core idea: <b>everything that arrives is hostile until proven otherwise, and everything stored may later be shown to someone else.</b>',
    boundaries: '<i>Public</i> (uploaders and readers), <i>Application and processing</i>, <i>Data tier</i>. If processing runs with different privileges, split it into its own zone in the real system and separate credentials.',
    elements: [['Uploader, Reader', 'Human User (external) ×2', 'Often different roles'], ['Portal', 'Web Application (process)', 'Upload form, search, downloads'], ['Upload API', 'Web Service (process)', 'Validates and routes'], ['Malware scanner', 'Generic Process', 'Scans before anything else touches the file'], ['Job queue', 'Cache (store)', 'Work waiting to be processed'], ['Processing worker', 'Win32 Service (process)', 'Parses and extracts: the riskiest code'], ['Object storage', 'Cloud Storage (store)', 'The files'], ['Metadata DB', 'SQL Database (store)', 'Extracted data'], ['Search index', 'Non Relational Database (store)', 'Searchable copy']],
    flows: [['Uploader → Portal → Upload API', 'File and metadata', 'Public → Application'], ['Upload API ↔ Malware scanner', 'File to scan, verdict', 'Inside Application'], ['Upload API → Job queue → Worker', 'Processing job, job and file reference', 'Inside Application'], ['Worker → Object storage / Metadata DB / Search index', 'Processed file, extracted data, index entries', 'Application → Data tier'], ['Reader → Portal → Upload API → stores', 'Search, download, lookups, fetch file', 'Public → Application → Data tier'], ['Portal → Reader', 'Results and files', 'Application → Public']],
    look: [['T', 'Uploader → Upload API', 'Is file type checked by content, not name? Size, count and nesting limits? Can a crafted file crash or exploit the parser?', 'Content sniffing, limits, parsers in a sandbox'], ['E', 'Worker', 'If the parser is compromised, what can the worker reach? Does it hold keys to every store?', 'Least privilege, separate identity, no network egress'], ['I', 'Portal → Reader', 'Can one user fetch another user’s file by changing an id? Are stored values escaped when shown (stored XSS)?', 'Per-object authorization, output encoding, signed URLs'], ['T', 'Job queue', 'Can someone put a job on the queue directly? Are jobs idempotent and validated?', 'Authenticated producers, validated payloads'], ['D', 'Upload API, worker', 'Can one huge or malicious file starve everyone else (zip bombs, endless loops)?', 'Quotas, timeouts, per-tenant queues'], ['R', 'Upload API', 'Can you tell who uploaded, who read, who deleted?', 'Audit log of every upload, read and delete'], ['I', 'Object storage', 'Is the bucket public or are links guessable? Are files encrypted and retained longer than needed?', 'Private buckets, expiring signed URLs, retention policy']],
    mistakes: ['Validating only in the browser. The attacker never uses your form.', 'Treating stored data as trusted when it is read back. It was input once; it is output now: encode it for where it is shown.', 'Giving the processing worker admin rights “for simplicity”.', 'Forgetting derived copies: the search index, caches and thumbnails hold the same sensitive data as the original.'],
    steps: 'Spec: 10 elements, 14 flows, 3 zones; about 70 threats. Read the Worker and Portal findings first.',
  });
  const ivr = scenario({
    id: 'ivr', title: 'An IVR system integrated into a customer support portal', name: 'ivr-support-portal',
    when: 'customers phone a company, an automated voice menu (IVR) identifies them and handles simple tasks, and the call can be passed to an agent who works in a support portal backed by customer records.',
    goal: 'This mixes telephony and web: voice and keypad input, speech services, one-time codes, card payments, call recording, and an agent desktop. Callers are anonymous and phone numbers can be forged, so <b>never treat the caller as authenticated just because of the number</b>.',
    boundaries: '<i>Contact centre</i> (IVR platform and agent desktop) and <i>Back office and data</i> (portal, records API, customer database, recordings). The carrier, speech service, code provider and payment processor are outside parties, drawn as external interactors. The phone carrier is folded into the call flow; draw it as its own element if you want to model carrier-side threats such as SIP hijacking.',
    elements: [['Caller', 'Human User (external)', 'Anonymous until verified'], ['IVR platform', 'Web Service (process)', 'Call flow, speech and keypad handling'], ['Speech service', 'External Web Service', 'Speech-to-text / text-to-speech vendor'], ['One-time-code provider', 'External Web Service', 'Sends SMS or voice codes'], ['Payment processor', 'External Web Service', 'Takes card details'], ['Agent desktop', 'Browser Client (process)', 'Screen with caller details'], ['Support agent', 'Human User (external)', 'Insider: can see customer data'], ['Support portal', 'Web Application (process)', 'Cases and customer views'], ['Customer records API', 'Web Service (process)', 'One front door to customer data'], ['Customer DB', 'SQL Database (store)', 'Personal data'], ['Call recordings', 'Cloud Storage (store)', 'Voice, often with personal data']],
    flows: [['Caller ↔ IVR platform', 'Voice and keypad tones; prompts and transfer (via the carrier)', 'Phone network → Contact centre'], ['IVR ↔ Speech service', 'Audio out, transcript back', 'Contact centre → outside'], ['IVR ↔ Customer records API', 'Caller lookup and PIN check, account details', 'Contact centre → Back office'], ['IVR → One-time-code provider', 'Send one-time code', 'Contact centre → outside'], ['IVR → Payment processor', 'Card payment (keypad entry)', 'Contact centre → outside'], ['IVR → Call recordings', 'Call recording', 'Contact centre → Back office'], ['IVR → Agent desktop; Agent → Agent desktop', 'Caller details, agent actions', 'Inside Contact centre'], ['Agent desktop → Support portal → Records API → Customer DB', 'Case updates, customer data requests, reads and writes', 'Contact centre → Back office'], ['Agent desktop → Call recordings', 'Recording playback', 'Contact centre → Back office']],
    look: [['S', 'Caller → IVR', 'Can the caller ID be faked? Can someone pass “verification” by guessing a PIN or date of birth? Can a cloned voice pass a voice-print check?', 'Do not rely on caller ID; one-time codes; lockout; step-up checks for sensitive actions'], ['S', 'Webhooks / carrier → IVR', 'Are call-event callbacks signed? Can anyone post fake “call ended” events?', 'Verify signatures, allow-list sources'], ['I', 'IVR → Call recordings', 'Do recordings capture card numbers or one-time codes? Who can replay them? How long are they kept?', 'Pause recording during payment, encrypt, role-limited access, retention limits'], ['I', 'IVR → Payment processor', 'Do card tones ever touch your systems or logs?', 'Send tones straight to the processor (DTMF masking), never store or log them'], ['T', 'Caller → IVR', 'Can spoken or typed input change the call flow, inject into lookups, or break the speech parser?', 'Validate all input, parameterised lookups, limit retries'], ['D', 'Carrier → IVR', 'Can attackers flood the lines or run up costs (toll fraud, premium-rate dialling)?', 'Call rate limits, destination allow-lists, spend alerts'], ['E', 'Agent desktop / portal', 'Can an agent see more than the current caller’s data? Is lookup of any customer logged?', 'Least privilege, screen-pop only the active caller, audit every access'], ['R', 'Records API', 'Can you prove who changed an address or reset a PIN, and after what verification?', 'Audit trail linking change, agent and verification result']],
    mistakes: ['Skipping the telephony side because “it’s the carrier’s problem”. Your IVR still decides what a caller may do.', 'Recording everything, always. Recordings are your largest store of personal data and, if you take card payments, may put you in scope of payment-card rules.', 'Trusting the phone number to identify a customer.', 'Drawing the agent as part of “the system” only. Agents are insiders: model their access and log it.', 'Forgetting the speech and code vendors. Audio and personal data go to them; they belong outside a trust boundary.'],
    steps: 'Spec: 11 elements, 15 flows, 2 zones; about 85 threats with no validation warnings.',
  });
  const review = `<section id="review"><h2>Reviewing any model</h2>
<ul>
<li>Does every process, store and external have at least one flow in and one flow out?</li>
<li>Does every arrow that crosses a boundary appear to cross it on the picture?</li>
<li>Can a stranger point at any arrow and be told what it carries and how it is protected?</li>
<li>Are the assumptions written down, and has someone checked at least the three most important?</li>
<li>Has every high-priority threat got an owner, a state and a justification?</li>
<li>Will someone update this when the architecture changes? Put it in the definition of done.</li>
</ul>
<p>For management, produce the <b>executive summary</b> (<i>Report → Download report…</i>, or <code>--format exec</code>) and pick a clear font such as Verdana. See <a href="../how-to/index.html#reports">Reports and fonts</a>.</p>
</section>`;
  return page({ slug: 'how-to-max', title: 'Worked examples: building real threat models', lead: 'Step-by-step threat models for a typical web app, a microservices system, an application that takes input, processes it, stores it and retrieves it, and an IVR system integrated with a customer support portal. Each comes with a ready-to-run spec.', toc, body: recipe + web + micro + intake + ivr + review });
};

// ====================================================================== write
const OUT = { 'how-to/index.html': howTo, 'what-is/index.html': whatIs, 'how-to-max/index.html': howToMax };

export function buildDocs({ check = false } = {}) {
  const stale = [];
  for (const [rel, make] of Object.entries(OUT)) {
    const file = path.join(ROOT, rel);
    const html = make();
    if (check) {
      if (!fs.existsSync(file) || fs.readFileSync(file, 'utf8') !== html) stale.push(rel);
    } else {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, html);
    }
  }
  return stale;
}

if (process.argv[1]?.endsWith('build-docs.mjs')) {
  const check = process.argv.includes('--check');
  const stale = buildDocs({ check });
  if (check && stale.length) {
    console.error(`Out of date: ${stale.join(', ')}. Run: node scripts/build-docs.mjs`);
    process.exit(1);
  }
  console.log(check ? 'Docs are up to date' : `Wrote ${Object.keys(OUT).join(', ')}`);
}
