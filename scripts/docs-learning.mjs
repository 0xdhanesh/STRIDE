// Learning pages: /learn (path, guided tutorial, quiz, glossary, reading), /practice (scenarios with model answers),
// /think (attacker thinking, risk rating, decisions). Helpers come from build-docs.mjs.

export function learningPages({ page, table, note, kbd, esc, spec }) {
  const ul = (items) => `<ul>${items.map((i) => `<li>${i}</li>`).join('')}</ul>`;
  const ol = (items) => `<ol class="steps">${items.map((i) => `<li>${i}</li>`).join('')}</ol>`;
  const answer = (summary, html) => `<details class="answer"><summary>${summary}</summary>${html}</details>`;
  const specBlock = (dir, name) => `<details><summary>Spec for this scenario (<a href="specs/${name}.json" download>download ${name}.json</a>)</summary><pre><code>${esc(spec(dir, name))}</code></pre></details>`;

  // ================================================================== /learn
  const learn = () => {
    const toc = [
      ['path', 'The learning path'],
      ['tutorial', 'Guided tutorial: cinema booking'],
      ['quiz', 'Check yourself: 10 questions'],
      ['glossary', 'Glossary'],
      ['reading', 'Where to go next'],
    ];
    const body = `
<section id="path"><h2>The learning path</h2>
<p>Learning threat modeling is mostly <b>doing it on real examples and getting feedback</b>. Read a little, then practice. This path takes about two working days spread over a week or two, and ends with a real model of your own system.</p>
${table(
  ['Step', 'Do this', 'Time', 'You are done when you can…'],
  [
    ['1. Understand', 'Read <a href="../what-is/index.html">What is STRIDE</a>', '20 min', 'explain the six threats to a colleague with one example each'],
    ['2. Learn the tool', 'Read <a href="../how-to/index.html">How to use it</a> and open the example model', '30 min', 'name the five building blocks and say what a trust boundary is'],
    ['3. Build one with guidance', 'The <a href="#tutorial">guided tutorial</a> below', '45 min', 'draw a small system, read its threats and triage three of them'],
    ['4. Study a full example', '<a href="../how-to-max/index.html">Worked examples</a>: start with the web app', '30 min', 'point out where each boundary goes and why'],
    ['5. Practice, then compare', '<a href="../practice/index.html">Practice scenarios</a>: try two before opening the answers', '2 hours', 'find most of the model answer’s threats and a few it missed'],
    ['6. Think like an attacker', '<a href="../think/index.html">Thinking like an attacker, and deciding what to do</a>', '45 min', 'rate a threat and choose fix, avoid, transfer or accept with a reason'],
    ['7. Check yourself', 'The <a href="#quiz">quiz</a> below', '15 min', 'answer at least 8 of 10 before looking'],
    ['8. Do it for real', 'Model one real system with a teammate who knows it', '2 hours', 'hand a management summary to a decision-maker'],
    ['9. Keep it alive', 'Update the model in the same change that alters the design', 'ongoing', 'show when each assumption was last checked'],
  ],
)}
${note('tip', 'Learning alone? Do step 8 with someone who did not draw the diagram. A second person finds the missing arrows within minutes, and that is the fastest way to improve.')}
</section>

<section id="tutorial"><h2>Guided tutorial: cinema booking</h2>
<p><b>The system:</b> customers pick seats and pay for cinema tickets on a website. The site keeps bookings in a database and takes payment through an outside payment provider. Small enough to finish in 45 minutes, real enough to show every idea.</p>
<p><b>Before you start,</b> open the <a href="../index.html">app</a> and choose <i>File → New model</i>. Do not open the answer yet.</p>

<h3>Part 1. Draw it</h3>
${ol([
  `<b>Who is outside?</b> Press ${kbd('E')}, click the canvas, type <code>Customer</code> and press Enter. In the right panel set <i>Type</i> to <i>Human User</i>. Press ${kbd('E')} again and add <code>Payment provider</code> with type <i>External Web Service</i>. Why external? You do not control either of them.`,
  `<b>What code runs?</b> Press ${kbd('P')}, place <code>Booking web app</code>, set type <i>Web Application</i>.`,
  `<b>Where is data kept?</b> Press ${kbd('D')}, place <code>Bookings DB</code>, set type <i>SQL Database</i>.`,
  `<b>How does information move?</b> Press ${kbd('F')} and drag from one element to another. Draw <b>six</b> flows, one per direction, and name each one:
   <br>Customer → Booking web app: <i>Seat selection and details</i>
   <br>Booking web app → Customer: <i>Booking confirmation</i>
   <br>Booking web app → Bookings DB: <i>Booking reads and writes</i>
   <br>Bookings DB → Booking web app: <i>Booking data</i>
   <br>Booking web app → Payment provider: <i>Card payment request</i>
   <br>Payment provider → Booking web app: <i>Payment result</i>`,
  `<b>Where does trust change?</b> Press ${kbd('B')} and drag a box around the web app and the database. Double-click its label and call it <code>Our systems</code>. Customer and payment provider stay outside: you cannot control them.`,
])}
${answer('Check: what should the picture look like?', `<p>Two elements outside the box (Customer, Payment provider), two inside (Booking web app, Bookings DB), six arrows, and every arrow to or from an outside element crosses the box. The arrows between the web app and the database do not cross it.</p><p>Compare with the reference: download <a href="specs/cinema-booking.json" download>cinema-booking.json</a> and in the app choose <i>File → Open…</i>, which accepts it directly and builds the diagram for you. Yours does not have to look identical; the elements, flows and boundary should match.</p>`)}

<h3>Part 2. Read the threats</h3>
${ol([
  `Check the <i>Messages</i> tab at the bottom: it should have no errors. Fix anything it reports.`,
  `Open the <i>Analyze</i> view (top right). With these types you should see roughly <b>30 threats</b> (the reference produces 29). If you see none, check that the flows really connect to the elements.`,
  `Find a <b>Spoofing</b> threat on <i>Seat selection and details</i>. In your own words: who could pretend to be whom, and what would they gain?`,
  `Find a <b>Tampering</b> threat on <i>Card payment request</i>. What could an attacker change between the app and the provider, and what stops them?`,
  `Find an <b>Information disclosure</b> threat on <i>Bookings DB</i>. What is in there that would hurt if it leaked?`,
])}

<h3>Part 3. Decide</h3>
${ol([
  `For each of the three threats set a <b>state</b> (for example <i>Needs Investigation</i>), a <b>priority</b> and a <b>justification</b> that names a specific control: <i>“Stripe Checkout hosts the card form, so card numbers never reach us”</i> beats <i>“handled”</i>.`,
  `<b>Add a threat the tool did not find.</b> Think about booking: two customers choose the last seat at the same moment. That is Tampering with the booking data through a race condition. Select the flow <i>Seat selection and details</i> and use <i>Add threat</i> in the right panel. Write the title, description and a mitigation (for example a database uniqueness constraint on seat and showing).`,
  `Set the <i>Name</i>, <i>Owner</i> and <i>Assumptions</i> in the model details (select nothing to see them). Write down one assumption you are relying on.`,
])}

<h3>Part 4. Report it</h3>
${ol([
  `Choose <i>Report → Download report…</i>, pick <b>Executive summary</b> and a clear font such as Verdana, then <i>Open in new tab</i>.`,
  `Read it as the owner of the business would. Is the status clear? Would they know what you are asking them to do?`,
  `Now open the <b>Technical report</b> and compare what changed: the evidence, interactions and every threat appear there.`,
])}

<h3>Part 5. Stretch</h3>
${ul([
  'Add a <b>refund</b> flow and an <b>email confirmation</b> flow. What new threats appear? Who is the new outside party?',
  'Add an <b>admin</b> who can cancel bookings. Where does the admin connect, and what boundary do they cross?',
  'Press ' + kbd('G') + ' with several elements selected to group them, change a line colour, and try focus mode (' + kbd('Ctrl/⌘+.') + ').',
])}
${answer('What most people forget in this tutorial', ul(['The <b>reverse flows</b> (confirmation, query results, payment result). Data leaves on those too.', 'The <b>admin and support staff</b>: insiders are a threat source and an access path.', 'A <b>log</b> or analytics store, which often holds names and emails.', 'The <b>email</b> that confirms the booking: an unauthenticated channel with personal data in it.', '<b>Seat holds that expire</b>: a denial-of-service lever (someone reserves every seat and never pays).']))}
</section>

<section id="quiz"><h2>Check yourself: 10 questions</h2>
<p>Answer in your head or on paper, then open the answer.</p>
<ol class="quiz">
<li>A customer says “I never approved that refund” and nothing in the logs can prove otherwise. Which STRIDE threat is this?${answer('Answer', '<b>Repudiation.</b> There is no reliable record tying the action to a person. Fix: audit logs of who did what and when, protected from editing.')}</li>
<li>An attacker changes <code>price=100</code> to <code>price=1</code> in a request and the server accepts it.${answer('Answer', '<b>Tampering.</b> The server trusted data it should have computed itself. Fix: take prices from the server, never from the request.')}</li>
<li>Changing <code>/invoice/1001</code> to <code>/invoice/1002</code> shows someone else’s invoice.${answer('Answer', '<b>Information disclosure</b>, caused by a missing authorization check (which is also the root of Elevation of privilege). Fix: check on the server that the invoice belongs to the caller.')}</li>
<li>One user repeatedly uploads a 10 GB file and the site slows to a crawl for everyone.${answer('Answer', '<b>Denial of service.</b> Fix: size limits, quotas, rate limits, processing in a separate queue.')}</li>
<li>A stolen session cookie lets someone act as another user.${answer('Answer', '<b>Spoofing.</b> Fix: short-lived sessions, secure cookie flags, re-authentication for sensitive actions, session revocation.')}</li>
<li>An ordinary user calls an admin-only URL and it works.${answer('Answer', '<b>Elevation of privilege.</b> Fix: deny-by-default authorization on the server for every function, with a test per role.')}</li>
<li>Is a message queue a process, an external interactor or a data store?${answer('Answer', '<b>Data store.</b> It holds data at rest, even briefly, so it needs access control, retention rules and monitoring like any store.')}</li>
<li>Your app calls a third-party SaaS. External interactor or process?${answer('Answer', '<b>External interactor.</b> You do not control its code or its security. Put it on the far side of a trust boundary and defend what you send and what you accept back.')}</li>
<li>You only drew arrows from the user to the server. What did you miss?${answer('Answer', '<b>The reverse flows.</b> Responses carry data out. Draw one arrow per direction, named after what it carries.')}</li>
<li>A threat is marked <i>Not Applicable</i> with the justification “handled”. What is wrong with that?${answer('Answer', 'It names no control. A useful justification says <b>which</b> control, <b>where</b> it is enforced and ideally <b>how it is tested</b>, so a reviewer can verify it: “Server-side check in <code>authz.py</code>; covered by test <code>test_roles</code>.”')}</li>
</ol>
</section>

<section id="glossary"><h2>Glossary</h2>
${table(
  ['Term', 'Meaning'],
  [
    ['Asset', 'Something worth protecting: customer data, money, availability, reputation, a signing key.'],
    ['Threat', 'Something bad that could happen to an asset. “A stranger could read other users’ invoices.”'],
    ['Vulnerability', 'A weakness that lets a threat happen. “The invoice endpoint does not check ownership.”'],
    ['Threat actor', 'Whoever or whatever causes a threat: an outsider, a customer, an insider, a compromised partner.'],
    ['Attack surface', 'Everything an attacker can reach or influence: endpoints, inputs, files, integrations, people.'],
    ['Entry point', 'A specific place where data or control enters the system: a URL, a queue, an upload, a phone number.'],
    ['Data flow diagram (DFD)', 'The picture of processes, external interactors, data stores, data flows and trust boundaries.'],
    ['Trust boundary', 'A line across which the level of trust changes, for example internet to internal network.'],
    ['External interactor', 'A person or system outside your control that exchanges data with yours.'],
    ['Authentication', 'Proving who you are.'],
    ['Authorization', 'Deciding what an authenticated identity may do. Most serious web flaws are missing authorization.'],
    ['Least privilege', 'Giving each person and component only the access it needs.'],
    ['Defence in depth', 'Several independent controls, so one failure is not the end.'],
    ['Mitigation', 'A control that reduces a threat.'],
    ['Residual risk', 'The risk that remains after mitigation, accepted knowingly by someone with authority.'],
    ['Abuse case', 'A use case written from the attacker’s side: “As an attacker I want to reuse an old reset link.”'],
    ['Assumption', 'Something you rely on but have not verified. Write them down; check the important ones.'],
    ['STRIDE', 'Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege.'],
    ['Template', 'The element types and threat rules a tool applies. This tool defaults to STRIDE Core.'],
  ],
)}
</section>

<section id="reading"><h2>Where to go next</h2>
<p>This site teaches the method and the tool. For depth, these are widely used and worth your time (find the current editions and pages with a search):</p>
${ul([
  '<b>Adam Shostack, <i>Threat Modeling: Designing for Security</i></b> (Wiley). The standard book on STRIDE and data flow diagrams, with exercises.',
  '<b>Izar Tarandach and Matthew Coles, <i>Threat Modeling: A Practical Guide for Development Teams</i></b> (O’Reilly). Aimed at teams who build and ship continuously.',
  '<b>The Threat Modeling Manifesto</b> (<a href="https://www.threatmodelingmanifesto.org" rel="noopener">threatmodelingmanifesto.org</a>). A short statement of values and principles, written by practitioners.',
  '<b>OWASP</b> (<a href="https://owasp.org" rel="noopener">owasp.org</a>): the Threat Modeling Cheat Sheet and Threat Modeling Process pages, and the Top 10 lists for common weaknesses to look for.',
  '<b>Microsoft’s threat modeling documentation</b> and the Microsoft Threat Modeling Tool, whose templates this tool can import.',
  '<b>MITRE ATT&amp;CK</b> and <b>CAPEC</b>: catalogues of real attacker techniques and attack patterns, useful for “what could go wrong” brainstorming.',
  '<b>LINDDUN</b> (<a href="https://linddun.org" rel="noopener">linddun.org</a>): a sister method for <i>privacy</i> threats, for when personal data is the main concern.',
  '<b>Kohnfelder and Garg, “The threats to our products”</b> (Microsoft, 1999): the original STRIDE write-up, if you like origins.',
])}
<p>Next: <a href="../practice/index.html">practice scenarios</a> and <a href="../think/index.html">thinking like an attacker</a>.</p>
</section>`;
    return page({ slug: 'learn', title: 'Learn threat modeling from scratch', lead: 'A step-by-step path from “what is this?” to modeling a real system: reading order, a guided tutorial you build in the app, a ten-question self-check, a glossary and a reading list.', toc, body });
  };

  // ================================================================== /practice
  const scenarioPractice = ({ id, title, name, brief, tasks, boundaries, elements, flows, threats, missed, tip }) => `<section id="${id}"><h2>${esc(title)}</h2>
<p>${brief}</p>
<h3>Your tasks</h3>
${ol(tasks)}
${answer('Model answer (try it first!)', `
<h4>Elements, flows and boundaries</h4>
<p><b>Trust boundaries:</b> ${boundaries}</p>
${table(['Element', 'Type', 'Why'], elements.map(([a, b, c]) => [esc(a), esc(b), esc(c)]))}
${table(['Flow', 'Carries'], flows.map(([a, b]) => [esc(a), esc(b)]))}
<h4>Threats to find</h4>
${table(['STRIDE', 'Where', 'What could go wrong', 'Fix'], threats.map(([a, b, c, d]) => [`<b>${a}</b>`, esc(b), esc(c), esc(d)]))}
<h4>What learners usually miss</h4>
${ul(missed)}
${tip ? `<p><b>Discussion:</b> ${tip}</p>` : ''}
<p>Build the reference model: <code>stride sync ${name}.model.json practice/specs/${name}.json</code>, or download the spec and use <i>File → Open…</i> in the app.</p>
${specBlock('practice', name)}`)}
</section>`;

  const practice = () => {
    const toc = [
      ['how', 'How to practice'],
      ['reset', '1. Password reset'],
      ['webhook', '2. Payment webhook receiver'],
      ['mobile', '3. Fitness mobile app'],
      ['share', '4. File sharing by link'],
      ['after', 'After the answer'],
    ];
    const how = `<section id="how"><h2>How to practice</h2>
<p>Each scenario is a small feature that real systems get wrong. Spend <b>20 to 30 minutes</b> on each, <i>before</i> opening the model answer:</p>
${ol([
  'Draw the diagram in the app (<i>File → New model</i>): elements, one arrow per direction, boundaries.',
  'Read the generated threats, then write down at least <b>six threats of your own</b> covering as many STRIDE letters as you can. Add the ones the tool missed with <i>Add threat</i>.',
  'Pick the two that worry you most and say how you would fix them, specifically.',
  'Only now open the model answer. Score yourself: how many did you find? Which did you miss, and why? Add the missing ones to your model.',
])}
${note('tip', 'The answers are written as one reasonable model, not the only one. If you found a good threat that is not listed, that is a win. Order is not important; reasons are.')}
</section>`;
    const reset = scenarioPractice({
      id: 'reset', title: '1. Password reset', name: 'password-reset',
      brief: 'A user who forgot their password asks for a reset. The service creates a one-time token, stores a hash of it, and emails a link through an email provider. The user clicks the link and sets a new password.',
      tasks: ['Draw the diagram. Which elements are outside your control?', 'Where is the weakest link in the chain: which step relies on something you do not own?', 'Write threats for at least four STRIDE letters.', 'What should be logged, and what must <i>never</i> be logged?'],
      boundaries: '<i>Our systems</i> around the reset page, account service and accounts database. The user and the email provider are outside. Email is an <b>untrusted channel</b> that you do not control.',
      elements: [['User', 'Human User (external)', 'Anyone can request a reset for any address'], ['Reset page', 'Web Application', 'Public entry point'], ['Account service', 'Web Service', 'Creates and checks tokens'], ['Accounts DB', 'SQL Database', 'Holds password hashes and token hashes'], ['Email provider', 'External Web Service', 'Delivers the link; outside your control']],
      flows: [['User → Reset page', 'Reset request with email address; later the link click and new password'], ['Reset page → Account service', 'Create reset token; token and new password'], ['Account service → Accounts DB', 'Store token hash; update password hash'], ['Account service → Email provider', 'Reset email with link']],
      threats: [['S', 'Link and token', 'Attacker guesses or reuses a reset token and takes over the account', 'Long random single-use token, short expiry, stored only as a hash'], ['S', 'Email channel', 'Attacker with access to the victim’s mailbox resets the password silently', 'Notify other channels, require extra verification for sensitive accounts, cool-down'], ['T', 'Reset email with link', 'Link is built from the request’s Host header, so the email points to the attacker’s site', 'Build links from fixed configuration, never from request headers'], ['I', 'Reset request', 'Different responses reveal which emails have accounts (enumeration)', 'Same message and timing whether or not the account exists'], ['I', 'Link click', 'Token in the URL leaks through logs, browser history and Referer headers', 'Exchange the token at once, no-referrer policy, never log query strings'], ['R', 'Whole flow', 'No record of who requested or used a reset, so abuse cannot be investigated', 'Audit events with time, address and result; alert on bursts'], ['D', 'Reset request', 'Attacker floods one address with reset emails, or exhausts the email quota', 'Rate limits per account and per source, captcha after a few tries'], ['E', 'Update password', 'Old sessions stay valid after reset, or reset bypasses multi-factor sign-in', 'Revoke sessions on reset; keep MFA requirements']],
      missed: ['That <b>email is not secure</b>. Anyone who can read the mailbox can use the link.', 'Tokens stored in <b>plaintext</b> in the database: a read-only leak becomes account takeover.', 'The <b>timing</b> side of enumeration, not only the message text.'],
      tip: 'Is “anyone with the user’s mailbox” inside or outside your threat model? Write down the decision either way.',
    });
    const webhook = scenarioPractice({
      id: 'webhook', title: '2. Payment webhook receiver', name: 'webhook-receiver',
      brief: 'A payment provider calls a public webhook endpoint when a payment succeeds or fails. The endpoint puts verified events on a queue; a worker reads them and updates order status in the orders database.',
      tasks: ['Draw it. Which element is exposed to the internet, and who can call it?', 'What would an attacker send to this endpoint, and what would they hope to achieve?', 'Find at least one threat for each of S, T, D and E.', 'What can go wrong <i>inside</i> the system, after the endpoint?'],
      boundaries: '<i>Our systems</i> around the endpoint, queue, worker and database. The provider is outside. The endpoint is the part of your system that faces the internet.',
      elements: [['Payment provider', 'External Web Service', 'Sends events; you trust it only as far as the signature proves'], ['Webhook endpoint', 'Web Service', 'Public, unauthenticated by session, authenticated by signature'], ['Event queue', 'Cache (data store)', 'Holds events until processed'], ['Order worker', 'Win32 Service', 'Applies events to orders'], ['Orders DB', 'SQL Database', 'Order status']],
      flows: [['Payment provider → Webhook endpoint', 'Signed payment events'], ['Webhook endpoint → Payment provider', 'Acknowledgement'], ['Webhook endpoint → Event queue', 'Verified events'], ['Event queue → Order worker', 'Events to process'], ['Order worker → Orders DB', 'Order status updates']],
      threats: [['S', 'Signed payment events', 'Anyone posts a fake “payment succeeded” and gets goods for free', 'Verify the signature over the raw body with the shared secret; reject anything unsigned'], ['T', 'Signed payment events', 'A genuine old event is replayed (for example a refund or a success for another order)', 'Reject stale timestamps and de-duplicate by event id'], ['T', 'Events to process', 'Fields are trusted without checking amount and order against your own records', 'Validate against the order, or re-fetch the event from the provider’s API'], ['I', 'Acknowledgement', 'Verbose errors or logged full payloads expose personal data', 'Minimal responses, redact logs'], ['D', 'Webhook endpoint', 'Flooding the endpoint, or one malformed “poison” event that crashes the worker on every retry', 'Rate limit, acknowledge fast and process later, dead-letter queue and retry limits'], ['E', 'Order status updates', 'The worker’s database account can change everything, so a bug in event handling is a full compromise', 'Least-privilege account that can only update order status'], ['R', 'Order status updates', 'You cannot tell which event caused which status change', 'Store the event id with every change; keep an append-only log'], ['T', 'Event queue', 'Anything inside the network can inject events directly, skipping signature checks', 'Authenticate queue producers; restrict who can publish']],
      missed: ['The <b>queue is a data store</b> with its own attackers: verification at the edge does not protect it.', '<b>Acknowledge only after the event is safely stored</b>, or you lose events.', '<b>Secret rotation</b>: what happens when the signing secret has to change?'],
      tip: 'Should an unsigned request even reach your application code? Where is the earliest place to reject it?',
    });
    const mobile = scenarioPractice({
      id: 'mobile', title: '3. Fitness mobile app', name: 'mobile-api',
      brief: 'A phone app records workouts, keeps a local cache and syncs with a cloud API through a gateway. The API stores activity data and asks a push service to send reminders to the phone.',
      tasks: ['Draw it. Which side of the main boundary do you control?', 'Assume the phone is lost, rooted, or running a modified copy of your app. What breaks?', 'Find the three most serious Information disclosure and Elevation of privilege threats.', 'Where is the push service a risk to you?'],
      boundaries: '<i>User device</i> (you do not control it: treat everything on it as attacker-readable and attacker-modifiable) and <i>Backend</i>. The push service is outside.',
      elements: [['Phone user', 'Human User (external)', 'The legitimate user, or whoever holds the phone'], ['Mobile app', 'Generic Process', 'Runs on the device: not trustworthy to enforce rules'], ['Local cache', 'Device (data store)', 'Cached activity and tokens on the phone'], ['API gateway', 'Web Server', 'Backend entry point'], ['Fitness API', 'Web Service', 'Business logic and authorization'], ['Activity DB', 'Non Relational Database', 'Health-related data'], ['Push service', 'External Web Service', 'Delivers notifications through the phone vendor']],
      flows: [['Phone user ↔ Mobile app', 'Taps and sensor data'], ['Mobile app ↔ Local cache', 'Cached activity and tokens'], ['Mobile app ↔ API gateway', 'API calls with token; responses'], ['API gateway → Fitness API', 'Forwarded calls'], ['Fitness API → Activity DB', 'Reads and writes'], ['Fitness API → Push service → Mobile app', 'Reminder requests and notifications']],
      threats: [['S', 'API calls with token', 'A stolen or copied access token is used from another device', 'Short-lived tokens, rotating refresh tokens, revoke on logout or loss'], ['T', 'API calls with token', 'A proxy changes the user id or activity id in a request', 'Server-side checks on every request; never trust values that came from the app'], ['E', 'Forwarded calls', 'Changing an object id returns or edits another user’s data (broken object-level authorization)', 'Ownership check in the API on every object access, with tests'], ['I', 'Local cache', 'Tokens and health data are readable on a lost, rooted or backed-up phone', 'OS secure storage, encrypt the local database, store the minimum, exclude from backups'], ['I', 'API responses', 'The API returns more fields than the screen shows', 'Explicit response shapes, no entire-record returns'], ['I', 'Push notifications', 'Sensitive details appear on the lock screen or pass through the push vendor', 'Send “you have an update”, fetch details after sign-in'], ['D', 'API calls with token', 'Bulk sync or reminder abuse overloads the API or spams a user', 'Per-user and per-device rate limits, page-size caps'], ['R', 'API calls with token', 'You cannot tell the user from a thief using a stolen phone', 'Device-bound sessions, audit trail with device id, user-visible session list with revoke']],
      missed: ['<b>Secrets inside the app</b> (API keys, signing keys): they can be extracted from the package.', '<b>Old app versions</b> that are still allowed to call your API.', 'The <b>transport on hostile networks</b>: TLS everywhere, and a plan if you pin certificates.'],
      tip: 'The golden rule of this scenario: anything checked only in the app is not checked.',
    });
    const share = scenarioPractice({
      id: 'share', title: '4. File sharing by link', name: 'file-share-links',
      brief: 'A file owner creates a share link with an expiry and permissions. Anyone with the link can open it; the web app asks the link service whether it is valid, then fetches the file from storage.',
      tasks: ['Draw it. Who is the “recipient”, and what do you actually know about them?', 'List three ways a link could reach someone it was not meant for.', 'Can a recipient reach the file <i>without</i> going through the link service? How would you stop that?', 'What should the owner be able to see afterwards?'],
      boundaries: '<i>Our systems</i> around the web app, link service, links database and file storage. Owner and recipient are outside; the recipient is <b>anonymous</b>.',
      elements: [['File owner', 'Human User (external)', 'Authenticated, creates links'], ['Link recipient', 'Human User (external)', 'Anonymous: whoever holds the link'], ['Web app', 'Web Application', 'Entry point for both roles'], ['Link service', 'Web Service', 'Creates and validates links'], ['Share links DB', 'SQL Database', 'Link, expiry, permissions, target file'], ['File storage', 'Cloud Storage', 'The files; must not be reachable directly']],
      flows: [['File owner → Web app → Link service', 'Create link'], ['Link service ↔ Share links DB', 'Store and look up link, expiry, permissions'], ['Link recipient → Web app → Link service', 'Open and validate link'], ['Web app → File storage', 'Fetch file'], ['Web app → Link recipient', 'File download']],
      threats: [['I', 'Open link', 'Short or predictable links are guessed or enumerated', 'At least 128 bits of randomness, rate limit validation, identical responses for missing and expired links'], ['I', 'Link and download', 'A forwarded link, chat preview or Referer log exposes the file to more people', 'Expiry, optional sign-in or passcode, revocation, no-referrer policy, per-link access log'], ['I', 'Fetch file', 'Storage objects are public or signed URLs live for days, bypassing the link service', 'Private storage, short-lived signed URLs minted only after validation'], ['T', 'Create link', 'Permissions or expiry are taken from request parameters the client can edit', 'Server derives permissions from its own stored record only'], ['S', 'Open link', 'Anyone with the link is “the recipient”; you cannot tell who it really was', 'Decide knowingly: accept, or require sign-in for sensitive files'], ['E', 'Validate link', 'A link meant for one file grants access to a folder or sibling files (path tricks)', 'Scope the link to one object id, normalise and check paths'], ['D', 'Fetch file', 'Repeated downloads of huge files exhaust bandwidth and cost', 'Rate limits, quotas, download caps per link'], ['R', 'Fetch file', 'The owner cannot see who opened or downloaded a file', 'Access log with time and source per link, visible to the owner']],
      missed: ['<b>Deleting the file must invalidate its links</b>, and expired links must really stop working.', 'Serving user files from the <b>main site’s domain</b> can let a malicious file attack other users; use a separate download domain.', 'The <b>decision</b> that bearer links are weak authentication: write it down as an accepted risk or add a control.'],
      tip: 'Is a share link a convenience feature or a security feature? Your answer sets how strong it needs to be.',
    });
    const after = `<section id="after"><h2>After the answer</h2>
${ul(['Add every threat you missed to <i>your</i> model with <i>Add threat</i>, so the practice leaves something behind.', 'Pick one scenario and explain it out loud to someone else in five minutes. Gaps show up immediately.', 'Change one thing in the scenario (add a login, add a vendor, add an admin) and see which threats appear or change.', 'Then try a system you work on. Start with its single most exposed entry point.'])}
<p>Next: <a href="../think/index.html">thinking like an attacker, and deciding what to do about each threat</a>.</p>
</section>`;
    return page({ slug: 'practice', title: 'Practice scenarios', lead: 'Four small, realistic features that systems often get wrong. Draw each one, find the threats, then compare with a model answer and a runnable spec.', toc, body: how + reset + webhook + mobile + share + after });
  };

  // ================================================================== /think
  const think = () => {
    const toc = [
      ['mindset', 'The attacker’s mindset'],
      ['prompts', 'Question prompts by STRIDE letter'],
      ['abuse', 'Abuse cases and chains'],
      ['assume', 'Assume something is compromised'],
      ['rating', 'Rating a threat'],
      ['decide', 'Deciding what to do'],
      ['write', 'Writing good mitigations and justifications'],
      ['others', 'Other methods and when to use them'],
      ['pitfalls', 'Pitfalls'],
    ];
    const body = `
<section id="mindset"><h2>The attacker’s mindset</h2>
<p>The tool generates a large first list from your diagram. What it cannot do is <b>think about your business</b>. That part is a human skill, and it can be learned. Start from these questions, in this order:</p>
${ol([
  '<b>What would an attacker want?</b> Money, data, free service, disruption, a foothold for later, revenge, publicity. Name the <i>assets</i> first: customer records, payments, credentials, availability, reputation.',
  '<b>Who could they be?</b> A stranger on the internet, a customer, a partner, an employee, a contractor, a compromised vendor, a competitor. Each has different access. Insiders already stand <i>past</i> most of your boundaries.',
  '<b>Where do they get in?</b> List every entry point: URLs, APIs, file uploads, message queues, admin tools, phone lines, emails, build pipelines, and people (support staff who can be tricked).',
  '<b>What is the cheapest path?</b> Attackers choose the easiest route, not the cleverest. Skip the exotic and ask what a bored person with a browser and a free afternoon can do.',
  '<b>What is the worst outcome?</b> Work backwards from the thing that would hurt most and ask what would have to be true for it to happen.',
])}
</section>

<section id="prompts"><h2>Question prompts by STRIDE letter</h2>
<p>At each arrow and each element, run through these. They turn “think of threats” into a checklist you can actually use.</p>
${table(
  ['', 'Ask yourself'],
  [
    ['<b>S</b> Spoofing', 'How does the receiver know who sent this? What if the sender lies, replays an old message, or uses a stolen credential? Can the receiver itself be faked (look-alike endpoint, DNS, a rogue device)?'],
    ['<b>T</b> Tampering', 'Who can change this data in transit, at rest, or before it reaches the server? Which values do we take from the client that we should compute ourselves? Can the order, timing or repetition of requests be changed?'],
    ['<b>R</b> Repudiation', 'Could someone do this and later deny it? What record would prove who did what, when and from where? Can that record itself be edited or deleted by the same person?'],
    ['<b>I</b> Information disclosure', 'What is the most sensitive thing here? Who can read it: in transit, in storage, in logs, in backups, in error messages, in caches, in analytics? What does the response reveal beyond what was asked?'],
    ['<b>D</b> Denial of service', 'What is the most expensive thing a caller can ask for? What if they ask a million times, or send one enormous item? What happens when this dependency is down or slow?'],
    ['<b>E</b> Elevation of privilege', 'What can a normal user do that only an admin should? Is every action checked on the <i>server</i>, for <i>this user</i>, on <i>this object</i>? What does this component run as, and what could it reach if taken over?'],
  ],
)}
</section>

<section id="abuse"><h2>Abuse cases and chains</h2>
<p><b>Abuse cases</b> turn a feature around. For a normal user story, write the attacker’s version:</p>
${ul(['User story: <i>“As a customer I can reset my password by email.”</i>', 'Abuse case: <i>“As an attacker I request resets for other people’s accounts, guess or steal the token, and take over the account.”</i>'])}
<p>Writing three abuse cases for each important feature gives you better threats than any list, because they are specific to your product.</p>
<p><b>Chains.</b> Real incidents rarely use one flaw. A low-risk information leak (a verbose error naming an internal host) plus a missing check on that host plus an over-privileged service account becomes a serious breach. When rating threats, ask “what does this give an attacker as a stepping stone?”, not only “how bad is it alone?”.</p>
</section>

<section id="assume"><h2>Assume something is compromised</h2>
<p>For each important component, ask: <b>“If this were taken over, what could the attacker reach next?”</b> Trace its outgoing arrows. That shows where you depend on a single component being perfect, and where least privilege, network segmentation and independent checks matter most. Do the same for credentials: if this key leaked today, how would you find out, and how fast could you replace it?</p>
</section>

<section id="rating"><h2>Rating a threat</h2>
<p>You cannot fix everything first, so rank. A simple, honest approach is <b>likelihood × impact</b> on a three-level scale, agreed by the team.</p>
${table(
  ['Likelihood goes up when…', 'Impact goes up when…'],
  [
    ['it is reachable from the internet without signing in', 'it exposes sensitive or regulated personal data'],
    ['it needs little skill or special tooling', 'it affects many users, not one'],
    ['there is a clear gain (money, data) for the attacker', 'it can move money or change records people rely on'],
    ['no control exists today, or the control is untested', 'it harms safety, availability of a critical service, or trust'],
    ['it has happened to similar systems', 'it is hard to detect or reverse'],
  ],
)}
${table(
  ['', 'Low impact', 'Medium impact', 'High impact'],
  [
    ['<b>High likelihood</b>', 'Medium', 'High', 'High'],
    ['<b>Medium likelihood</b>', 'Low', 'Medium', 'High'],
    ['<b>Low likelihood</b>', 'Low', 'Low', 'Medium'],
  ],
)}
<p>Use the result as the threat’s <b>priority</b> in the tool, and write down the reason in one sentence. <i>Example:</i> “High: any signed-in user can read any invoice by changing the id (easy, internet-facing) and invoices hold billing addresses (sensitive).”</p>
${note('warn', 'Numeric scoring schemes look precise but are subjective; many teams moved away from point scoring (such as DREAD) because two people rate the same threat very differently. A short, agreed three-level scale plus a written reason is more useful and easier to defend.')}
</section>

<section id="decide"><h2>Deciding what to do</h2>
<p>Every threat ends in one of four decisions. “We have not looked at it” is not a decision.</p>
${table(
  ['Decision', 'Meaning', 'Example', 'In the tool'],
  [
    ['<b>Mitigate</b>', 'Add or improve a control so the threat is less likely or less harmful.', 'Check ownership of every invoice on the server', 'Needs Investigation → Mitigation Implemented, with the control named'],
    ['<b>Avoid</b> (eliminate)', 'Remove the feature, data or flow that causes the threat.', 'Stop storing card numbers; use the provider’s hosted form', 'Remove it from the diagram, or Not Applicable with the reason'],
    ['<b>Transfer</b>', 'Move the risk to someone better placed, by contract or product choice. It never moves <i>your</i> responsibility to protect your users’ data.', 'Use a managed identity service; buy cyber insurance for the residual', 'Mitigation Implemented, naming the vendor and what you verified'],
    ['<b>Accept</b>', 'Knowingly live with it, because it is unlikely, cheap, or costlier to fix than to bear. By someone with authority, in writing, with a review date.', 'An internal-only report page shows a name list to all staff', 'Not Applicable or kept open with a justification, owner and date'],
  ],
)}
<p><b>Who decides?</b> The people who own the risk: usually the product or service owner, informed by engineering and security. Accepting a high-priority risk should need a more senior person than accepting a low one. The <a href="../how-to/index.html#reports">executive summary</a> exists to put these decisions in front of them in plain language.</p>
</section>

<section id="write"><h2>Writing good mitigations and justifications</h2>
<p>A good mitigation is <b>specific, testable and owned</b>.</p>
${table(
  ['Weak', 'Strong'],
  [
    ['“Improve security of the login.”', '“Limit sign-in to 5 attempts per account per 15 minutes; locked accounts get an email. Owner: Auth team. Test: <code>test_login_lockout</code>.”'],
    ['“Handled.”', '“Authorization is checked in <code>InvoiceService.get()</code>; any invoice not owned by the caller returns 404. Covered by the role-matrix tests.”'],
    ['“Encrypt data.”', '“Database volumes use AES-256 with keys held in the cloud key vault; backups use a separate key. Verified in the 2026-Q1 review.”'],
    ['“Not applicable.”', '“Not applicable: this flow only exists in the test environment (see deployment diagram, no route in production).”'],
  ],
)}
<p>Ask of every mitigation: <i>Where is it enforced? How would we know if it stopped working? Who owns it?</i></p>
</section>

<section id="others"><h2>Other methods and when to use them</h2>
<p>STRIDE-per-flow, as used here, is a strong default because it is simple, structured and teaches well. Know its neighbours:</p>
${table(
  ['Method', 'Use it when', 'How it differs'],
  [
    ['<b>Attack trees</b>', 'You have one critical goal (“steal customer data”) and want every path to it', 'Starts from the attacker’s goal and branches into ways to achieve it, rather than from the architecture'],
    ['<b>LINDDUN</b>', 'Personal data and privacy are the main concern', 'Same diagram-based approach but with privacy threat categories (linking, identifying, non-repudiation, detecting, data disclosure, unawareness, non-compliance)'],
    ['<b>PASTA</b>', 'You need a risk-centric, business-driven process with stronger attacker simulation', 'A longer, staged process that ties threats to business impact'],
    ['<b>ATT&amp;CK / CAPEC</b>', 'You want realistic attacker techniques to brainstorm with, or to test detection', 'Catalogues of known techniques and patterns, not a method for drawing your system'],
  ],
)}
<p>They combine well: use STRIDE to find threats broadly, attack trees to go deep on the few that matter, and a catalogue to make the brainstorm realistic.</p>
</section>

<section id="pitfalls"><h2>Pitfalls</h2>
${ul([
  '<b>Boiling the ocean.</b> Model one feature or one flow at a time. A finished small model beats an abandoned big one.',
  '<b>Only imagining outsiders.</b> Customers, staff and vendors have legitimate access that can be misused or stolen.',
  '<b>Trusting “internal”.</b> The inside of your network is not a boundary of trust unless you have verified it.',
  '<b>Rating everything High.</b> If everything is urgent nothing is. Use the matrix and defend each rating.',
  '<b>Treating the tool’s list as complete.</b> It is a strong start. Your abuse cases and your knowledge of the business add the rest.',
  '<b>No follow-through.</b> A threat without an owner and a date does not get fixed. Put the work into the normal backlog.',
  '<b>One and done.</b> Revisit when the architecture, data or vendors change.',
])}
<p>Put it into practice: <a href="../practice/index.html">practice scenarios</a>, or back to the <a href="../learn/index.html">learning path</a>.</p>
</section>`;
    return page({ slug: 'think', title: 'Thinking like an attacker, and deciding what to do', lead: 'The human skills the tool cannot automate: finding threats beyond the generated list, rating them honestly, choosing between fix, avoid, transfer and accept, and writing mitigations people can verify.', toc, body });
  };

  return { 'learn/index.html': learn, 'practice/index.html': practice, 'think/index.html': think };
}
