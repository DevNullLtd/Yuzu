// Login page HTML — compiled in its own translation unit (MSVC raw-string limit).

// NOLINTBEGIN(cert-err58-cpp)
extern const char* const kLoginHtml =
    R"HTM(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Login</title>
  <link rel="stylesheet" href="/static/yuzu.css">
  <style>
    body {
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; padding: 16px;
    }
    /* A centred bordered panel on the slate canvas: no gradient, glow or shadow. */
    .login-card {
      width: 380px; max-width: 100%; padding: 28px;
      background: var(--surface); border: 1px solid var(--line);
      border-radius: var(--rad-panel);
    }
    .login-card h1 {
      display: flex; align-items: center; gap: 9px;
      font-size: 24px; font-weight: 600; letter-spacing: -.015em; line-height: 1.2; color: var(--ink);
    }
    /* The brand mark: the yellow diamond. */
    .login-card h1::after {
      content: ""; width: 9px; height: 9px; margin-top: 4px;
      background: var(--hl); border-radius: 2px; transform: rotate(45deg);
    }
    .login-card .subtitle { margin: 4px 0 20px; color: var(--mut); }
    .field { display: flex; flex-direction: column; gap: 5px; margin-bottom: 16px; }
    .field label { font-size: 13px; font-weight: 500; color: var(--ink2); }
    .field input {
      width: 100%; height: var(--ctl); padding: 0 10px; font: inherit;
      background: var(--bg); color: var(--ink);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
    }
    .field input:focus-visible, .btn-login:focus-visible, .btn-sso:focus-visible {
      outline: 2px solid var(--focus); outline-offset: 2px;
    }
    .btn-login {
      width: 100%; height: var(--ctl); margin-top: 4px; cursor: pointer;
      background: var(--primary); color: var(--on-primary);
      border: 1px solid var(--primary); border-radius: var(--rad-ctl);
      font: inherit; font-weight: 600; transition: background .12s, border-color .12s;
    }
    .btn-login:hover { background: var(--primary-h); border-color: var(--primary-h); }
    .btn-login:disabled { opacity: .4; cursor: not-allowed; }
    .error-msg { min-height: 1.2em; margin-top: 12px; font-size: 13px; color: var(--bad); }
    .sso-section { margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--line); }
    .btn-sso {
      width: 100%; height: var(--ctl); cursor: not-allowed; opacity: .5;
      background: var(--raise); color: var(--ink);
      border: 1px solid var(--line2); border-radius: var(--rad-ctl);
      font: inherit; font-weight: 500; transition: background .12s, border-color .12s;
    }
    .btn-sso.enabled { cursor: pointer; opacity: 1; }
    .btn-sso.enabled:hover { background: var(--surface2); border-color: var(--mut); }
    .sso-label { margin-top: 6px; font-size: 12.5px; color: var(--faint); }
    .enroll-secret {
      margin-bottom: 16px; padding: 12px 14px; font-size: 13px;
      background: var(--surface2); border: 1px solid var(--line2); border-radius: var(--rad-panel);
    }
    .enroll-secret-label { margin-bottom: 2px; font-size: 12.5px; color: var(--mut); }
    .enroll-secret code { font-family: var(--mds-font-family-mono); font-size: 12.5px; color: var(--ink); }
    /* The QR image carries its own white ground and quiet zone, so it is only clipped to the control radius. */
    .enroll-qr-box { overflow: hidden; border-radius: var(--rad-ctl); line-height: 0; }
    .enroll-qr-hint { margin-bottom: 8px; text-align: center; font-size: 12.5px; color: var(--mut); }
    .recovery-list {
      margin: 0 0 16px; padding: 12px 12px 12px 28px;
      background: var(--bg); border: 1px solid var(--line2); border-radius: var(--rad-ctl);
      font-family: var(--mds-font-family-mono); font-size: 12.5px; color: var(--ink);
    }
  </style>
</head>
)HTM"
    // Split here to stay under MSVC's C2026 16380-byte raw-string limit; adjacent
    // literals concatenate, so the served HTML is unchanged.
    R"HTM(<body>
  <div class="login-card">
    <h1>Yuzu</h1>
    <div class="subtitle">Sign in to the dashboard</div>

    <form id="login-form" onsubmit="doLogin(event)">
      <div class="field">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" autocomplete="username"
               autocapitalize="none" autocorrect="off" spellcheck="false"
               aria-label="Username" autofocus required>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password"
               aria-label="Password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn-login" id="btn-login" aria-label="Sign in">Sign In</button>
      <div class="error-msg" id="error-msg" role="alert" aria-live="polite"></div>
    </form>

    <form id="mfa-form" onsubmit="doMfa(event)" style="display:none">
      <div class="subtitle">Enter the 6-digit code from your authenticator app, or one of your recovery codes.</div>
      <input type="hidden" id="mfa-pending-token">
      <div class="field">
        <label for="mfa-code">Verification code</label>
        <input type="text" id="mfa-code" name="code" autocomplete="one-time-code"
               autocapitalize="none" autocorrect="off" spellcheck="false"
               inputmode="numeric" autofocus required>
      </div>
      <button type="submit" class="btn-login" id="btn-mfa" aria-label="Verify">Verify</button>
      <div class="error-msg" id="mfa-error-msg" role="alert" aria-live="polite"></div>
    </form>

    <form id="enroll-form" onsubmit="doEnroll(event)" style="display:none">
      <div class="subtitle">Multi-factor authentication is required. Scan this with your
        authenticator app, then enter the 6-digit code it shows to finish signing in.</div>
      <input type="hidden" id="enroll-pending-token">
      <div id="enroll-qr" style="display:none;justify-content:center;margin:0 0 8px 0">
        <div class="enroll-qr-box"></div>
      </div>
      <div id="enroll-qr-hint" class="enroll-qr-hint" style="display:none">
        Can't scan? Enter the secret below manually.</div>
      <div class="enroll-secret">
        <div class="enroll-secret-label">Base32 secret (manual entry)</div>
        <code id="enroll-secret"></code>
        <div class="enroll-secret-label" style="margin-top:0.5rem">otpauth URI</div>
        <code id="enroll-otpauth" style="display:block;word-break:break-all"></code>
      </div>
      <div class="field">
        <label for="enroll-code">Verification code</label>
        <input type="text" id="enroll-code" name="code" autocomplete="one-time-code"
               autocapitalize="none" autocorrect="off" spellcheck="false"
               inputmode="numeric" required>
      </div>
      <button type="submit" class="btn-login" id="btn-enroll" aria-label="Enable and sign in">Enable &amp; Sign In</button>
      <div class="error-msg" id="enroll-error-msg" role="alert" aria-live="polite"></div>
    </form>

    <div id="recovery-panel" style="display:none">
      <div class="subtitle">Save these recovery codes now — each can be
        used once if you lose your authenticator.</div>
      <ul id="recovery-list" class="recovery-list"></ul>
      <button type="button" class="btn-login" onclick="window.location.href='/'"
              aria-label="Continue to dashboard">I've saved them — Continue</button>
    </div>

    <div class="sso-section" id="sso-section">
      <button class="btn-sso" id="btn-sso" disabled>Sign in with SSO (OIDC)</button>
      <div class="sso-label" id="sso-label">Coming soon</div>
    </div>
  </div>

  <script>
    /*OIDC_CONFIG*/

    function doLogin(e) {
      e.preventDefault();
      var btn = document.getElementById('btn-login');
      var errEl = document.getElementById('error-msg');
      btn.disabled = true;
      errEl.textContent = '';

      var username = document.getElementById('username').value;
      var password = document.getElementById('password').value;

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/login');
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.onload = function() {
        if (xhr.status === 200) {
          window.location.href = '/';
          return;
        }
        if (xhr.status === 202) {
          try {
            var resp = JSON.parse(xhr.responseText);
            var loginForm = document.getElementById('login-form');
            var ssoSection = document.getElementById('sso-section');
            // Already-enrolled user — swap to the TOTP challenge form.
            if (resp && resp.status === 'mfa_required' && resp.mfa_pending_token) {
              document.getElementById('mfa-pending-token').value = resp.mfa_pending_token;
              loginForm.style.display = 'none';
              if (ssoSection) ssoSection.style.display = 'none';
              document.getElementById('mfa-form').style.display = '';
              document.getElementById('mfa-code').focus();
              return;
            }
            // Enforcement requires enrollment — swap to the enroll form.
            if (resp && resp.status === 'mfa_enrollment_required' && resp.mfa_pending_token) {
              document.getElementById('enroll-pending-token').value = resp.mfa_pending_token;
              document.getElementById('enroll-otpauth').textContent = resp.otpauth_uri || '';
              document.getElementById('enroll-secret').textContent = resp.secret_base32 || '';
              // qr_svg is server-rendered (qrcodegen over our own otpauth URI),
              // not user input — safe to inject as markup. Empty → keep hidden,
              // the manual secret above is the fallback.
              var qrWrap = document.getElementById('enroll-qr');
              var qrHint = document.getElementById('enroll-qr-hint');
              if (resp.qr_svg) {
                qrWrap.firstElementChild.innerHTML = resp.qr_svg;
                qrWrap.style.display = 'flex';
                qrHint.style.display = '';
              } else {
                qrWrap.style.display = 'none';
                qrHint.style.display = 'none';
              }
              loginForm.style.display = 'none';
              if (ssoSection) ssoSection.style.display = 'none';
              document.getElementById('enroll-form').style.display = '';
              document.getElementById('enroll-code').focus();
              return;
            }
          } catch(ex) { /* fall through to error display */ }
          errEl.textContent = 'Login failed (' + xhr.status + ')';
          btn.disabled = false;
          return;
        }
        // Server returns the structured envelope:
        //   {"error":{"code":N,"message":"..."},"meta":{...}}
        // Pre-envelope responses used a flat string "error".
        var msg = '';
        try {
          var resp = JSON.parse(xhr.responseText);
          if (resp && resp.error) {
            if (typeof resp.error === 'string') {
              msg = resp.error;
            } else if (typeof resp.error === 'object' && resp.error.message) {
              msg = resp.error.message;
            }
          }
        } catch(ex) { /* fall through to default */ }
        if (!msg) {
          msg = (xhr.status === 401) ? 'Invalid username or password'
                                     : 'Login failed (' + xhr.status + ')';
        }
        errEl.textContent = msg;
        btn.disabled = false;
      };
      xhr.onerror = function() {
        errEl.textContent = 'Network error';
        btn.disabled = false;
      };
      xhr.send('username=' + encodeURIComponent(username) +
               '&password=' + encodeURIComponent(password));
    }

    function doMfa(e) {
      e.preventDefault();
      var btn = document.getElementById('btn-mfa');
      var errEl = document.getElementById('mfa-error-msg');
      btn.disabled = true;
      errEl.textContent = '';

      var pending = document.getElementById('mfa-pending-token').value;
      var code = document.getElementById('mfa-code').value;

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/login/mfa');
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.onload = function() {
        if (xhr.status === 200) {
          window.location.href = '/';
          return;
        }
        var msg = '';
        try {
          var resp = JSON.parse(xhr.responseText);
          if (resp && resp.error && resp.error.message) {
            msg = resp.error.message;
          }
        } catch(ex) { /* default below */ }
        if (!msg) {
          msg = 'Invalid verification code';
        }
        errEl.textContent = msg;
        btn.disabled = false;
        document.getElementById('mfa-code').focus();
        document.getElementById('mfa-code').select();
      };
      xhr.onerror = function() {
        errEl.textContent = 'Network error';
        btn.disabled = false;
      };
      xhr.send('mfa_pending_token=' + encodeURIComponent(pending) +
               '&code=' + encodeURIComponent(code));
    }

    function doEnroll(e) {
      e.preventDefault();
      var btn = document.getElementById('btn-enroll');
      var errEl = document.getElementById('enroll-error-msg');
      btn.disabled = true;
      errEl.textContent = '';

      var pending = document.getElementById('enroll-pending-token').value;
      var code = document.getElementById('enroll-code').value;

      var xhr = new XMLHttpRequest();
      xhr.open('POST', '/login/mfa/enroll');
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.onload = function() {
        if (xhr.status === 200) {
          // Enrollment complete — session is set. Reveal recovery codes
          // before letting the operator continue to the dashboard.
          var codes = [];
          try {
            var resp = JSON.parse(xhr.responseText);
            if (resp && Array.isArray(resp.recovery_codes)) codes = resp.recovery_codes;
          } catch(ex) { /* no codes to show */ }
          if (codes.length) {
            var list = document.getElementById('recovery-list');
            list.innerHTML = '';
            codes.forEach(function(c) {
              var li = document.createElement('li');
              li.textContent = c;
              list.appendChild(li);
            });
            document.getElementById('enroll-form').style.display = 'none';
            document.getElementById('recovery-panel').style.display = '';
          } else {
            window.location.href = '/';
          }
          return;
        }
        var msg = '';
        try {
          var resp = JSON.parse(xhr.responseText);
          if (resp && resp.error && resp.error.message) msg = resp.error.message;
        } catch(ex) { /* default below */ }
        if (!msg) msg = 'Invalid verification code';
        errEl.textContent = msg;
        btn.disabled = false;
        document.getElementById('enroll-code').focus();
        document.getElementById('enroll-code').select();
      };
      xhr.onerror = function() {
        errEl.textContent = 'Network error';
        btn.disabled = false;
      };
      xhr.send('mfa_pending_token=' + encodeURIComponent(pending) +
               '&code=' + encodeURIComponent(code));
    }

    function startOidc() {
      window.location.href = '/auth/oidc/start';
    }

    // Enable SSO button if OIDC is configured (server injects window.OIDC_ENABLED)
    if (window.OIDC_ENABLED) {
      var ssoBtn = document.getElementById('btn-sso');
      ssoBtn.disabled = false;
      ssoBtn.classList.add('enabled');
      ssoBtn.textContent = 'Sign in with Microsoft Entra ID';
      ssoBtn.onclick = startOidc;
      document.getElementById('sso-label').textContent = '';
    }

    // Show OIDC error if redirected back with error param
    (function() {
      var params = new URLSearchParams(window.location.search);
      var err = params.get('error');
      if (err) {
        var errEl = document.getElementById('error-msg');
        var msgs = {
          'sso_denied': 'SSO sign-in was denied by the identity provider',
          'sso_failed': 'SSO authentication failed',
          'sso_invalid': 'Invalid SSO response'
        };
        errEl.textContent = msgs[err] || 'SSO error';
      }
    })();
  </script>
</body>
</html>
)HTM";
// NOLINTEND(cert-err58-cpp)
