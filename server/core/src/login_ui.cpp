// The sign-in form pieces the landing page (home_ui.cpp) composes — its own
// translation unit so each raw string stays far under MSVC's C2026 cap.
//
// These are the forms and the script the former `/login` page carried, with one
// behaviour change: a completed sign-in (password, TOTP, or enrolment) reloads
// `/home` (with the validated `next` key the panel carries) instead of going to
// `/`, so the user stays on Home and sees the signed-in panel. The posts, the
// 202 handling and the error display are unchanged.

#include "home_ui.hpp"

namespace yuzu::server::login_ui {

// Username, password, the primary button. The error line, the notice, the SSO
// link and the two-factor note are rendered around these by home_ui.cpp.
constexpr std::string_view kFields = R"HTM(<div class="fld">
  <label for="username">Username</label>
  <input class="in" type="text" id="username" name="username" autocomplete="username"
         autocapitalize="none" autocorrect="off" spellcheck="false" autofocus required>
</div>
<div class="fld">
  <label for="password">Password</label>
  <input class="in" type="password" id="password" name="password" autocomplete="current-password" required>
</div>
<button type="submit" class="btn primary" id="btn-login">Sign in</button>
)HTM";

// The TOTP challenge, the enforced-enrolment step and the one-time recovery
// codes. Hidden until `doLogin` gets a 202; `display:none` inline because the
// shared `.form` rule would override a `hidden` attribute.
constexpr std::string_view kSteps = R"HTM(<form id="mfa-form" class="form" onsubmit="doMfa(event)" style="display:none">
  <p class="small">Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
  <input type="hidden" id="mfa-pending-token">
  <div class="fld">
    <label for="mfa-code">Verification code</label>
    <input class="in" type="text" id="mfa-code" name="code" autocomplete="one-time-code"
           autocapitalize="none" autocorrect="off" spellcheck="false" inputmode="numeric" required>
  </div>
  <button type="submit" class="btn primary" id="btn-mfa">Verify</button>
  <div class="error-msg" id="mfa-error-msg" role="alert" aria-live="polite"></div>
</form>

<form id="enroll-form" class="form" onsubmit="doEnroll(event)" style="display:none">
  <p class="small">Multi-factor authentication is required. Scan this with your
    authenticator app, then enter the 6-digit code it shows to finish signing in.</p>
  <input type="hidden" id="enroll-pending-token">
  <div id="enroll-qr" style="display:none;justify-content:center">
    <div class="enroll-qr-box"></div>
  </div>
  <p id="enroll-qr-hint" class="small" style="display:none;text-align:center">
    Can't scan? Enter the secret below manually.</p>
  <div class="note">
    <div class="small">Base32 secret (manual entry)</div>
    <code id="enroll-secret" class="mono"></code>
    <div class="small" style="margin-top:8px">otpauth URI</div>
    <code id="enroll-otpauth" class="mono" style="display:block;word-break:break-all"></code>
  </div>
  <div class="fld">
    <label for="enroll-code">Verification code</label>
    <input class="in" type="text" id="enroll-code" name="code" autocomplete="one-time-code"
           autocapitalize="none" autocorrect="off" spellcheck="false" inputmode="numeric" required>
  </div>
  <button type="submit" class="btn primary" id="btn-enroll">Enable and sign in</button>
  <div class="error-msg" id="enroll-error-msg" role="alert" aria-live="polite"></div>
</form>

<div id="recovery-panel" class="form" style="display:none">
  <p class="small">Save these recovery codes now. Each can be used once if you lose your authenticator.</p>
  <ul id="recovery-list" class="recovery-list"></ul>
  <a id="recovery-continue" class="btn primary" href="/home">I have saved them. Continue</a>
</div>
)HTM";

// Plain XHR against the real auth routes. `home()` is where every completed
// sign-in goes: `/home`, plus the validated key the server put on the panel.
constexpr std::string_view kScript = R"JS(<script>
    function home() {
      var p = document.getElementById('signin');
      var n = p ? p.getAttribute('data-next') : '';
      return '/home' + (n ? '?next=' + encodeURIComponent(n) : '');
    }
    function errorMessage(xhr, fallback) {
      // Server returns the structured envelope {"error":{"code":N,"message":"..."}};
      // pre-envelope responses used a flat string "error".
      var msg = '';
      try {
        var resp = JSON.parse(xhr.responseText);
        if (resp && resp.error) {
          if (typeof resp.error === 'string') msg = resp.error;
          else if (typeof resp.error === 'object' && resp.error.message) msg = resp.error.message;
        }
      } catch (ex) { /* fall through to the default */ }
      return msg || fallback;
    }
    function show(id, on) { document.getElementById(id).style.display = on ? '' : 'none'; }

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
        if (xhr.status === 200) { window.location.href = home(); return; }
        if (xhr.status === 202) {
          try {
            var resp = JSON.parse(xhr.responseText);
            // Already-enrolled user: swap to the TOTP challenge form.
            if (resp && resp.status === 'mfa_required' && resp.mfa_pending_token) {
              document.getElementById('mfa-pending-token').value = resp.mfa_pending_token;
              show('login-form', false);
              show('mfa-form', true);
              document.getElementById('mfa-code').focus();
              return;
            }
            // Enforcement requires enrolment: swap to the enrol form.
            if (resp && resp.status === 'mfa_enrollment_required' && resp.mfa_pending_token) {
              document.getElementById('enroll-pending-token').value = resp.mfa_pending_token;
              document.getElementById('enroll-otpauth').textContent = resp.otpauth_uri || '';
              document.getElementById('enroll-secret').textContent = resp.secret_base32 || '';
              // qr_svg is server-rendered (qrcodegen over our own otpauth URI), not
              // user input. Empty: keep hidden, the manual secret is the fallback.
              var qrWrap = document.getElementById('enroll-qr');
              if (resp.qr_svg) {
                qrWrap.firstElementChild.innerHTML = resp.qr_svg;
                qrWrap.style.display = 'flex';
                show('enroll-qr-hint', true);
              } else {
                qrWrap.style.display = 'none';
                show('enroll-qr-hint', false);
              }
              show('login-form', false);
              show('enroll-form', true);
              document.getElementById('enroll-code').focus();
              return;
            }
          } catch (ex) { /* fall through to the error display */ }
          errEl.textContent = 'Login failed (' + xhr.status + ')';
          btn.disabled = false;
          return;
        }
        errEl.textContent = errorMessage(xhr, xhr.status === 401 ? 'Invalid username or password'
                                                                 : 'Login failed (' + xhr.status + ')');
        btn.disabled = false;
      };
      xhr.onerror = function() { errEl.textContent = 'Network error'; btn.disabled = false; };
      xhr.send('username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password));
    }

    function doCode(e, path, btnId, errId, pendingId, codeId, onOk) {
      e.preventDefault();
      var btn = document.getElementById(btnId);
      var errEl = document.getElementById(errId);
      btn.disabled = true;
      errEl.textContent = '';
      var xhr = new XMLHttpRequest();
      xhr.open('POST', path);
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.onload = function() {
        if (xhr.status === 200) { onOk(xhr); return; }
        errEl.textContent = errorMessage(xhr, 'Invalid verification code');
        btn.disabled = false;
        document.getElementById(codeId).focus();
        document.getElementById(codeId).select();
      };
      xhr.onerror = function() { errEl.textContent = 'Network error'; btn.disabled = false; };
      xhr.send('mfa_pending_token=' + encodeURIComponent(document.getElementById(pendingId).value) +
               '&code=' + encodeURIComponent(document.getElementById(codeId).value));
    }

    function doMfa(e) {
      doCode(e, '/login/mfa', 'btn-mfa', 'mfa-error-msg', 'mfa-pending-token', 'mfa-code',
             function() { window.location.href = home(); });
    }

    function doEnroll(e) {
      doCode(e, '/login/mfa/enroll', 'btn-enroll', 'enroll-error-msg', 'enroll-pending-token', 'enroll-code',
             function(xhr) {
               // Enrolment complete and the session is set. Reveal the recovery
               // codes before letting the operator continue.
               var codes = [];
               try {
                 var resp = JSON.parse(xhr.responseText);
                 if (resp && Array.isArray(resp.recovery_codes)) codes = resp.recovery_codes;
               } catch (ex) { /* no codes to show */ }
               if (!codes.length) { window.location.href = home(); return; }
               var list = document.getElementById('recovery-list');
               list.innerHTML = '';
               codes.forEach(function(c) {
                 var li = document.createElement('li');
                 li.textContent = c;
                 list.appendChild(li);
               });
               document.getElementById('recovery-continue').href = home();
               show('enroll-form', false);
               show('recovery-panel', true);
             });
    }
  </script>
)JS";

static_assert(kFields.size() < 15000 && kSteps.size() < 15000 && kScript.size() < 15000,
              "MSVC C2026: keep every raw string literal under the 16,380-byte cap");

std::string_view sign_in_fields() { return kFields; }
std::string_view sign_in_steps() { return kSteps; }
std::string_view sign_in_script() { return kScript; }

} // namespace yuzu::server::login_ui
