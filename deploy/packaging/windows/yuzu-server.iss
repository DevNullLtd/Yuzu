; Yuzu Server - Windows Installer (InnoSetup 6)
; Build: ISCC.exe yuzu-server.iss
; Silent: YuzuServerSetup.exe /VERYSILENT /SUPPRESSMSGBOXES /ADMIN_USER=admin /ADMIN_PASS=Password123!
;
; Silent parameters:
;   /ADMIN_USER=name       Admin username (required on a fresh install)
;   /ADMIN_PASS=pass       Admin password, FRESH INSTALL ONLY: at least 12
;                          characters and at most 1024 bytes as UTF-8 (a
;                          character outside ASCII takes 2 to 4 bytes). It is
;                          written to yuzu-server.cfg, which only SEEDS the first
;                          administrator into an EMPTY auth database (#5274); on
;                          an existing database the stored password wins and a
;                          rewritten file would be ignored.
;                          ON AN UPGRADE (yuzu-server.cfg already exists) leave
;                          out /ADMIN_USER, /ADMIN_PASS and the operator pair:
;                          the existing accounts are kept, and a non-empty
;                          /ADMIN_PASS= or /OPERATOR_PASS= is REFUSED with exit
;                          code 11 before anything changes. Change or reset a
;                          password in the dashboard (Settings > User Management
;                          > Change password / Reset password), or follow
;                          docs/ops-runbooks/auth-db-recovery.md.
;   /OPERATOR_USER=name    Operator username (optional; only with /ADMIN_PASS).
;                          On a PostgreSQL auth store (every supported
;                          deployment) this account is not provisioned and
;                          cannot sign in today (#5343); create further
;                          accounts in Settings > User Management instead.
;   /OPERATOR_PASS=pass    Operator password (required with /OPERATOR_USER; same
;                          length rules; fresh install only)
;   /POSTGRES_DSN_FILE=f   File holding the PostgreSQL connection string. One of
;                          this or /POSTGRES_DSN is required on a fresh install and
;                          on an upgrade from any earlier version (none stored one),
;                          unless a YUZU_POSTGRES_DSN environment variable is set;
;                          later upgrades keep the stored one. Preferred: unlike
;                          /POSTGRES_DSN it keeps the password out of the /LOG= file.
;   /POSTGRES_DSN=dsn      The PostgreSQL connection string itself
;   /GATEWAY               Enable gateway mode
;   /GATEWAY_ADDR=h:p      Gateway command address (default: localhost:50063)
;   /OIDC_ISSUER=url       OIDC issuer URL
;   /OIDC_CLIENT_ID=id     OIDC client ID
;   /OIDC_CLIENT_SECRET=s  OIDC client secret
;   /OIDC_CLIENT_SECRET_FILE=f  File holding the OIDC client secret (preferred)
;   /OIDC_ADMIN_GROUP=g    OIDC admin group name
;   /HTTPS_CERT=path       PEM certificate for HTTPS dashboard
;   /HTTPS_KEY=path        PEM private key for HTTPS dashboard
;   /GRPC_CERT=path        PEM certificate for agent gRPC
;   /GRPC_KEY=path         PEM private key for agent gRPC
;   /CA_CERT=path          PEM CA cert for mTLS agent verification
;   /NOHTTPS               Disable HTTPS (dev only)
;   /NOTLS                 Disable gRPC TLS (dev only)
;   /NOSTART               Do not start service after install
;
; Exit codes: 0 success; 7 the installation was stopped before any file was
; installed (Inno's PrepareToInstall failure) -- for this installer that means
; an input was invalid or missing, or the data directory, certificates,
; secrets or configuration could not be secured (#5196, #5210, #5272). The
; reason is in the setup log (/LOG=<file>), on a line starting
; "PrepareToInstall:". A service already stopped by then stays stopped, unless
; the abort came before the old directory was moved (it is then restarted). 10
; the files were installed but the service could not be registered or its
; command line could not be written and confirmed; Setup disables the service
; if it can, and says whether it did. 11 an upgrade (yuzu-server.cfg already
; exists) was given a non-empty /ADMIN_PASS= or /OPERATOR_PASS=, which can no
; longer change a stored password (#5274); nothing was stopped or changed, and
; the reason is in the setup log on a line starting "InitializeSetup:".
; (Inno Setup's own exit codes are 0-8.)
;
; THE SETUP LOG RECORDS THE FULL COMMAND LINE, including any /ADMIN_PASS=,
; /OPERATOR_PASS=, /POSTGRES_DSN= or /OIDC_CLIENT_SECRET= value. Prefer the
; *_FILE parameters, and protect or delete the log.
;
; Secrets are kept in "%ProgramData%\Yuzu Server", locked to Administrators
; and SYSTEM; the service's command line (readable by local users) carries
; only their paths. See the [Code] section for the directory states.

#ifndef AppVersion
  #define AppVersion "0.7.1"
#endif

#ifndef BuildDir
  #define BuildDir "..\..\..\build-windows"
#endif

[Setup]
AppId={{A1E3B7F2-4C9D-6F4A-2E8B-3D1C7A5F0E9B}
AppName=Yuzu Server
AppVersion={#AppVersion}
AppVerName=Yuzu Server {#AppVersion}
AppPublisher=Yuzu Project
AppPublisherURL=https://github.com/YuzuProject/yuzu
DefaultDirName={autopf}\Yuzu Server
DefaultGroupName=Yuzu Server
OutputBaseFilename=YuzuServerSetup-{#AppVersion}
OutputDir=output
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
UninstallDisplayIcon={app}\bin\yuzu-server.exe
SetupIconFile=yuzu.ico
WizardStyle=modern
DisableProgramGroupPage=yes
LicenseFile=..\..\..\LICENSE
CloseApplications=force
RestartApplications=no
CloseApplicationsFilter=yuzu-server.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; --- Server binary ---
Source: "{#BuildDir}\server\core\yuzu-server.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#BuildDir}\server\core\*.dll"; DestDir: "{app}\bin"; Flags: ignoreversion skipifsourcedoesntexist

; InstructionDefinitions are embedded into yuzu-server.exe at build time
; (server/core/scripts/embed_content.py); the runtime never reads them
; from disk. No content\definitions\ directory shipped.

; --- Config generator: extracted and run by PrepareToInstall, never installed ---
Source: "generate-config.ps1"; Flags: dontcopy

[Dirs]
; "%ProgramData%\Yuzu Server" is NOT listed: PrepareToInstall in [Code] creates,
; locks and verifies it before anything is installed (#5196, #5210). A
; Permissions: entry here would only ADD entries to it, after it was verified.
Name: "{app}\logs"; Permissions: admins-full system-full

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop YuzuServer"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{sys}\cmd.exe"; Parameters: "/c timeout /t 3 /nobreak >nul"; Flags: runhidden waituntilterminated; RunOnceId: "WaitStop"
Filename: "{app}\bin\yuzu-server.exe"; Parameters: "--remove-service"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\logs"

[Code]
// ── Variables ────────────────────────────────────────────────────────────
var
  // Wizard pages
  AdminPage: TInputQueryWizardPage;
  OperatorPage: TInputQueryWizardPage;
  NetworkPage: TWizardPage;
  DatabasePage: TInputQueryWizardPage;
  IdentityPage: TWizardPage;
  TLSPage: TWizardPage;

  // Network page controls
  GatewayCheckbox: TNewCheckBox;
  GatewayAddrLabel: TNewStaticText;
  GatewayAddrEdit: TEdit;
  PortInfoLabel: TNewStaticText;

  // Identity page controls
  OIDCCheckbox: TNewCheckBox;
  OIDCIssuerLabel: TNewStaticText;
  OIDCIssuerEdit: TEdit;
  OIDCClientIdLabel: TNewStaticText;
  OIDCClientIdEdit: TEdit;
  OIDCSecretLabel: TNewStaticText;
  OIDCSecretEdit: TEdit;
  OIDCAdminGroupLabel: TNewStaticText;
  OIDCAdminGroupEdit: TEdit;

  // TLS page controls
  HTTPSGroupLabel: TNewStaticText;
  NoHTTPSCheckbox: TNewCheckBox;
  HTTPSCertLabel: TNewStaticText;
  HTTPSCertEdit: TEdit;
  HTTPSCertBtn: TNewButton;
  HTTPSKeyLabel: TNewStaticText;
  HTTPSKeyEdit: TEdit;
  HTTPSKeyBtn: TNewButton;
  GRPCGroupLabel: TNewStaticText;
  NoTLSCheckbox: TNewCheckBox;
  GRPCCertLabel: TNewStaticText;
  GRPCCertEdit: TEdit;
  GRPCCertBtn: TNewButton;
  GRPCKeyLabel: TNewStaticText;
  GRPCKeyEdit: TEdit;
  GRPCKeyBtn: TNewButton;
  CACertLabel: TNewStaticText;
  CACertEdit: TEdit;
  CACertBtn: TNewButton;

  // Set when PrepareToInstall stopped a running YuzuServer service, so an
  // abort can say so truthfully. Sticky: cleared only if this run starts the
  // service again itself.
  StoppedRunningService: Boolean;
  // Set when this run disabled the service (a failed restore of the old data
  // directory), so the abort message does not promise it restarts at reboot.
  ServiceDisabled: Boolean;
  // Set when the service could not be registered or its command line could
  // not be written; Setup then exits with code 10 (GetCustomSetupExitCode).
  ServiceSetupFailed: Boolean;

// ── Command-line helpers ─────────────────────────────────────────────────
function GetCmdParam(const ParamName: string): string;
var
  I: Integer;
  Prefix: string;
begin
  Result := '';
  Prefix := '/' + ParamName + '=';
  for I := 1 to ParamCount do
    if CompareText(Copy(ParamStr(I), 1, Length(Prefix)), Prefix) = 0 then
    begin
      Result := Copy(ParamStr(I), Length(Prefix) + 1, MaxInt);
      Exit;
    end;
end;

function HasCmdFlag(const FlagName: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/' + FlagName) = 0 then
    begin
      Result := True;
      Exit;
    end;
end;

// True when Name is set where the service will see it: machine-wide, or in
// the YuzuServer service's own Environment value (REG_MULTI_SZ, NAME=value
// lines). Either is honoured by the server, and either is readable by local
// users; the server refuses to start with both a variable and its -file flag.
function EnvVarSet(const Name: string): Boolean;
var
  V: string;
begin
  Result := RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
                                Name, V) and (V <> '');
  if not Result then
    if RegQueryMultiStringValue(HKLM, 'SYSTEM\CurrentControlSet\Services\YuzuServer',
                                'Environment', V) then
      Result := (Pos(Uppercase(Name) + '=', Uppercase(V)) = 1) or
                (Pos(#0 + Uppercase(Name) + '=', Uppercase(V)) > 0);
end;

// ── Password rules and the upgrade refusal (#5274, #5342) ────────────────

// The UTF-8 encoded length of S in bytes: the unit the server's password policy
// measures (at most 1024 bytes, server/core/src/password_policy.hpp), and what
// generate-config.ps1 hashes. Length() counts UTF-16 code units, so each half
// of a surrogate pair (one character, 4 bytes in UTF-8) counts 2 here.
function Utf8ByteLength(const S: string): Integer;
var
  I, C: Integer;
begin
  Result := 0;
  for I := 1 to Length(S) do
  begin
    C := Ord(S[I]);
    if C < $80 then
      Result := Result + 1
    else if C < $800 then
      Result := Result + 2
    else if (C >= $D800) and (C <= $DFFF) then
      Result := Result + 2
    else
      Result := Result + 3;
  end;
end;

const
  MaxPasswordBytes = 1024;
  // Inno Setup's own exit codes are 0-8; 7 and 10 carry this installer's
  // meanings (see the header).
  UpgradePasswordExitCode = 11;

// True when this is an upgrade that keeps the existing accounts: a
// yuzu-server.cfg is already in the data directory. The same test the wizard
// and PrepareToInstall use for "there is an existing configuration to keep".
function ExistingConfig: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonappdata}\Yuzu Server\yuzu-server.cfg'));
end;

procedure ExitProcess(uExitCode: Cardinal);
  external 'ExitProcess@kernel32.dll stdcall';

// Since #5274 yuzu-server.cfg only SEEDS the first administrator into an
// empty auth database; on an existing one the stored password wins and a
// rewritten file is ignored. A new /ADMIN_PASS= or /OPERATOR_PASS= on an
// upgrade would therefore be dropped without a word -- and a password rotated
// because it leaked would stay valid. Refused here, before the wizard, before
// the service is stopped and before anything is written, with its own exit
// code (11) so an unattended deployment can tell it apart from code 7.
// Inno Setup has no way to return a custom code from a refusal (its
// GetCustomSetupExitCode runs only after a successful install), hence
// ExitProcess: the setup log keeps the "InitializeSetup:" line, but Setup's
// own temporary folder is left behind in %TEMP%.
function InitializeSetup(): Boolean;
var
  Refusal: string;
begin
  Result := True;
  if ExistingConfig and ((GetCmdParam('ADMIN_PASS') <> '') or (GetCmdParam('OPERATOR_PASS') <> '')) then
  begin
    Refusal := 'This is an upgrade (yuzu-server.cfg already exists), and /ADMIN_PASS= or ' +
               '/OPERATOR_PASS= was given. The installer can no longer change a stored ' +
               'password: the configuration file only seeds the first administrator into an ' +
               'empty database, so the new password would be ignored and the old one would ' +
               'stay valid. Run the installer again without /ADMIN_USER=, /ADMIN_PASS=, ' +
               '/OPERATOR_USER= and /OPERATOR_PASS= (the existing accounts are kept), then ' +
               'change or reset the password in the dashboard (Settings > User Management > ' +
               'Change password / Reset password), or follow ' +
               'docs/ops-runbooks/auth-db-recovery.md if no administrator can sign in.' + #13#10#13#10 +
               'Nothing has been changed.';
    Log('InitializeSetup: ' + Refusal);
    SuppressibleMsgBox(Refusal, mbCriticalError, MB_OK, IDOK);
    ExitProcess(UpgradePasswordExitCode);
    Result := False;
  end;
end;

// ── File browse helper ───────────────────────────────────────────────────
function BrowsePEM(const Title: string): string;
var
  FileName: string;
begin
  Result := '';
  FileName := '';
  if GetOpenFileName(Title, FileName, '', 'PEM files (*.pem;*.crt;*.key)|*.pem;*.crt;*.key|All files (*.*)|*.*', '') then
    Result := FileName;
end;

// ── Browse button click handlers ─────────────────────────────────────────
procedure HTTPSCertBtnClick(Sender: TObject);
var F: string;
begin
  F := BrowsePEM('Select HTTPS certificate (PEM)');
  if F <> '' then HTTPSCertEdit.Text := F;
end;

procedure HTTPSKeyBtnClick(Sender: TObject);
var F: string;
begin
  F := BrowsePEM('Select HTTPS private key (PEM)');
  if F <> '' then HTTPSKeyEdit.Text := F;
end;

procedure GRPCCertBtnClick(Sender: TObject);
var F: string;
begin
  F := BrowsePEM('Select gRPC server certificate (PEM)');
  if F <> '' then GRPCCertEdit.Text := F;
end;

procedure GRPCKeyBtnClick(Sender: TObject);
var F: string;
begin
  F := BrowsePEM('Select gRPC server private key (PEM)');
  if F <> '' then GRPCKeyEdit.Text := F;
end;

procedure CACertBtnClick(Sender: TObject);
var F: string;
begin
  F := BrowsePEM('Select CA certificate for mTLS (PEM)');
  if F <> '' then CACertEdit.Text := F;
end;

// ── OIDC checkbox toggle ─────────────────────────────────────────────────
procedure OIDCCheckboxClick(Sender: TObject);
var Enabled: Boolean;
begin
  Enabled := OIDCCheckbox.Checked;
  OIDCIssuerEdit.Enabled := Enabled;
  OIDCClientIdEdit.Enabled := Enabled;
  OIDCSecretEdit.Enabled := Enabled;
  OIDCAdminGroupEdit.Enabled := Enabled;
end;

// ── Gateway checkbox toggle ──────────────────────────────────────────────
procedure GatewayCheckboxClick(Sender: TObject);
begin
  GatewayAddrEdit.Enabled := GatewayCheckbox.Checked;
  if GatewayCheckbox.Checked then
    PortInfoLabel.Caption :=
      'Port assignments with gateway:'#13#10 +
      '  Server web dashboard:  8080'#13#10 +
      '  Server agent gRPC:     50051 (direct agents)'#13#10 +
      '  Server management:     50052'#13#10 +
      '  Gateway upstream:      50055 (gateway registers here)'#13#10 +
      '  Gateway commands:      ' + GatewayAddrEdit.Text + #13#10 +
      '  Gateway agent-facing:  50051 (on gateway node)'
  else
    PortInfoLabel.Caption :=
      'Port assignments (no gateway):'#13#10 +
      '  Web dashboard:   8080'#13#10 +
      '  Agent gRPC:      50051'#13#10 +
      '  Management gRPC: 50052';
end;

// ── NoHTTPS / NoTLS checkbox toggles ─────────────────────────────────────
procedure NoHTTPSCheckboxClick(Sender: TObject);
var Enabled: Boolean;
begin
  Enabled := not NoHTTPSCheckbox.Checked;
  HTTPSCertEdit.Enabled := Enabled;
  HTTPSCertBtn.Enabled := Enabled;
  HTTPSKeyEdit.Enabled := Enabled;
  HTTPSKeyBtn.Enabled := Enabled;
end;

procedure NoTLSCheckboxClick(Sender: TObject);
var Enabled: Boolean;
begin
  Enabled := not NoTLSCheckbox.Checked;
  GRPCCertEdit.Enabled := Enabled;
  GRPCCertBtn.Enabled := Enabled;
  GRPCKeyEdit.Enabled := Enabled;
  GRPCKeyBtn.Enabled := Enabled;
  CACertEdit.Enabled := Enabled;
  CACertBtn.Enabled := Enabled;
end;

// ── Create helper: label ─────────────────────────────────────────────────
function MakeLabel(Page: TWizardPage; ATop: Integer; const ACaption: string): TNewStaticText;
begin
  Result := TNewStaticText.Create(Page);
  Result.Parent := Page.Surface;
  Result.Top := ATop;
  Result.Left := 0;
  Result.Caption := ACaption;
end;

// ── Create helper: edit box ──────────────────────────────────────────────
function MakeEdit(Page: TWizardPage; ATop, AWidth: Integer; const AText: string): TEdit;
begin
  Result := TEdit.Create(Page);
  Result.Parent := Page.Surface;
  Result.Top := ATop;
  Result.Left := 0;
  Result.Width := AWidth;
  Result.Text := AText;
end;

// ── Create helper: browse button ─────────────────────────────────────────
function MakeBrowseBtn(Page: TWizardPage; ATop, ALeft: Integer; AOnClick: TNotifyEvent): TNewButton;
begin
  Result := TNewButton.Create(Page);
  Result.Parent := Page.Surface;
  Result.Top := ATop - 2;
  Result.Left := ALeft;
  Result.Width := 80;
  Result.Height := 23;
  Result.Caption := 'Browse...';
  Result.OnClick := AOnClick;
end;

// ── Wizard initialisation ────────────────────────────────────────────────
procedure InitializeWizard;
var
  Y: Integer;
  EditW: Integer;
begin
  EditW := 330;

  // ── Page: Admin credentials ──
  AdminPage := CreateInputQueryPage(wpSelectDir,
    'Administrator Account',
    'Create the admin account for the Yuzu dashboard.',
    'The admin has full access to all server features including user management, ' +
    'policy deployment, and agent commands. This page appears on a fresh install only: ' +
    'an upgrade keeps the existing accounts, and passwords are changed in the dashboard ' +
    '(Settings > User Management).');
  AdminPage.Add('Username:', False);
  AdminPage.Add('Password (at least 12 characters, at most 1024 bytes):', True);
  AdminPage.Add('Confirm password:', True);
  AdminPage.Values[0] := GetCmdParam('ADMIN_USER');
  if AdminPage.Values[0] = '' then AdminPage.Values[0] := 'admin';
  AdminPage.Values[1] := GetCmdParam('ADMIN_PASS');
  AdminPage.Values[2] := GetCmdParam('ADMIN_PASS');

  // ── Page: Operator credentials ──
  OperatorPage := CreateInputQueryPage(AdminPage.ID,
    'Operator Account (Optional)',
    'Create a read-only operator account.',
    'Operators can view fleet status, query responses, and monitor compliance ' +
    'but cannot execute instructions or change settings. Leave the username blank to skip.');
  OperatorPage.Add('Username:', False);
  OperatorPage.Add('Password (at least 12 characters, at most 1024 bytes):', True);
  OperatorPage.Add('Confirm password:', True);
  OperatorPage.Values[0] := GetCmdParam('OPERATOR_USER');
  OperatorPage.Values[1] := GetCmdParam('OPERATOR_PASS');
  OperatorPage.Values[2] := GetCmdParam('OPERATOR_PASS');

  // ── Page: Network / Gateway ──
  NetworkPage := CreateCustomPage(OperatorPage.ID,
    'Network Configuration',
    'Configure gateway mode if you have a Yuzu Gateway on this machine.');

  GatewayCheckbox := TNewCheckBox.Create(NetworkPage);
  GatewayCheckbox.Parent := NetworkPage.Surface;
  GatewayCheckbox.Top := 0;
  GatewayCheckbox.Left := 0;
  GatewayCheckbox.Width := 400;
  GatewayCheckbox.Caption := 'A Yuzu Gateway is installed on this machine';
  GatewayCheckbox.Checked := HasCmdFlag('GATEWAY');
  GatewayCheckbox.OnClick := @GatewayCheckboxClick;

  GatewayAddrLabel := MakeLabel(NetworkPage, 30, 'Gateway command address:');
  GatewayAddrEdit := MakeEdit(NetworkPage, 48, EditW, '');
  GatewayAddrEdit.Text := GetCmdParam('GATEWAY_ADDR');
  if GatewayAddrEdit.Text = '' then GatewayAddrEdit.Text := 'localhost:50063';
  GatewayAddrEdit.Enabled := GatewayCheckbox.Checked;

  PortInfoLabel := TNewStaticText.Create(NetworkPage);
  PortInfoLabel.Parent := NetworkPage.Surface;
  PortInfoLabel.Top := 80;
  PortInfoLabel.Left := 0;
  PortInfoLabel.Width := 420;
  PortInfoLabel.Height := 120;
  PortInfoLabel.AutoSize := False;
  PortInfoLabel.WordWrap := True;
  GatewayCheckboxClick(nil);  // Set initial port info text

  // ── Page: Database ──
  DatabasePage := CreateInputQueryPage(NetworkPage.ID,
    'Database',
    'The PostgreSQL database the server stores its data in.',
    'The server does not start without a PostgreSQL database. Enter a libpq connection ' +
    'string, for example host=db.example.com dbname=yuzu user=yuzu password=... or ' +
    'postgresql://yuzu:...@db.example.com/yuzu. It is stored in the secured data ' +
    'directory, never on the service''s command line. When upgrading, leave it blank to ' +
    'keep the stored one.');
  DatabasePage.Add('Connection string:', True);
  DatabasePage.Values[0] := GetCmdParam('POSTGRES_DSN');

  // ── Page: Identity / OIDC ──
  IdentityPage := CreateCustomPage(DatabasePage.ID,
    'Identity Provider (Optional)',
    'Connect to Active Directory or Entra ID for single sign-on.');

  OIDCCheckbox := TNewCheckBox.Create(IdentityPage);
  OIDCCheckbox.Parent := IdentityPage.Surface;
  OIDCCheckbox.Top := 0;
  OIDCCheckbox.Left := 0;
  OIDCCheckbox.Width := 420;
  OIDCCheckbox.Caption := 'Enable OIDC single sign-on (Active Directory / Entra ID)';
  OIDCCheckbox.Checked := GetCmdParam('OIDC_ISSUER') <> '';
  OIDCCheckbox.OnClick := @OIDCCheckboxClick;

  Y := 28;
  OIDCIssuerLabel := MakeLabel(IdentityPage, Y, 'Issuer URL (e.g. https://login.microsoftonline.com/{tenant}/v2.0):');
  Y := Y + 18;
  OIDCIssuerEdit := MakeEdit(IdentityPage, Y, EditW, GetCmdParam('OIDC_ISSUER'));
  Y := Y + 28;
  OIDCClientIdLabel := MakeLabel(IdentityPage, Y, 'Client ID (app registration):');
  Y := Y + 18;
  OIDCClientIdEdit := MakeEdit(IdentityPage, Y, EditW, GetCmdParam('OIDC_CLIENT_ID'));
  Y := Y + 28;
  OIDCSecretLabel := MakeLabel(IdentityPage, Y, 'Client secret (blank on an upgrade keeps the stored one):');
  Y := Y + 18;
  OIDCSecretEdit := MakeEdit(IdentityPage, Y, EditW, GetCmdParam('OIDC_CLIENT_SECRET'));
  OIDCSecretEdit.PasswordChar := '*';
  Y := Y + 28;
  OIDCAdminGroupLabel := MakeLabel(IdentityPage, Y, 'Admin group name (users in this group get admin role):');
  Y := Y + 18;
  OIDCAdminGroupEdit := MakeEdit(IdentityPage, Y, EditW, GetCmdParam('OIDC_ADMIN_GROUP'));

  OIDCCheckboxClick(nil);  // Set initial enabled state

  // ── Page: TLS Certificates ──
  TLSPage := CreateCustomPage(IdentityPage.ID,
    'TLS Certificates',
    'Configure HTTPS for the web dashboard and mTLS for agent connections.');

  Y := 0;
  HTTPSGroupLabel := MakeLabel(TLSPage, Y, 'HTTPS (web dashboard):');
  HTTPSGroupLabel.Font.Style := [fsBold];
  Y := Y + 20;
  NoHTTPSCheckbox := TNewCheckBox.Create(TLSPage);
  NoHTTPSCheckbox.Parent := TLSPage.Surface;
  NoHTTPSCheckbox.Top := Y;
  NoHTTPSCheckbox.Left := 0;
  NoHTTPSCheckbox.Width := 350;
  NoHTTPSCheckbox.Caption := 'Skip HTTPS (development only, not recommended)';
  NoHTTPSCheckbox.Checked := HasCmdFlag('NOHTTPS');
  NoHTTPSCheckbox.OnClick := @NoHTTPSCheckboxClick;

  Y := Y + 22;
  HTTPSCertLabel := MakeLabel(TLSPage, Y, 'Certificate:');
  Y := Y + 16;
  HTTPSCertEdit := MakeEdit(TLSPage, Y, EditW, GetCmdParam('HTTPS_CERT'));
  HTTPSCertBtn := MakeBrowseBtn(TLSPage, Y, EditW + 8, @HTTPSCertBtnClick);
  Y := Y + 24;
  HTTPSKeyLabel := MakeLabel(TLSPage, Y, 'Private key:');
  Y := Y + 16;
  HTTPSKeyEdit := MakeEdit(TLSPage, Y, EditW, GetCmdParam('HTTPS_KEY'));
  HTTPSKeyBtn := MakeBrowseBtn(TLSPage, Y, EditW + 8, @HTTPSKeyBtnClick);

  Y := Y + 36;
  GRPCGroupLabel := MakeLabel(TLSPage, Y, 'Agent gRPC / mTLS:');
  GRPCGroupLabel.Font.Style := [fsBold];
  Y := Y + 20;
  NoTLSCheckbox := TNewCheckBox.Create(TLSPage);
  NoTLSCheckbox.Parent := TLSPage.Surface;
  NoTLSCheckbox.Top := Y;
  NoTLSCheckbox.Left := 0;
  NoTLSCheckbox.Width := 350;
  NoTLSCheckbox.Caption := 'Skip gRPC TLS (development only, not recommended)';
  NoTLSCheckbox.Checked := HasCmdFlag('NOTLS');
  NoTLSCheckbox.OnClick := @NoTLSCheckboxClick;

  Y := Y + 22;
  GRPCCertLabel := MakeLabel(TLSPage, Y, 'Server certificate:');
  Y := Y + 16;
  GRPCCertEdit := MakeEdit(TLSPage, Y, EditW, GetCmdParam('GRPC_CERT'));
  GRPCCertBtn := MakeBrowseBtn(TLSPage, Y, EditW + 8, @GRPCCertBtnClick);
  Y := Y + 24;
  GRPCKeyLabel := MakeLabel(TLSPage, Y, 'Server private key:');
  Y := Y + 16;
  GRPCKeyEdit := MakeEdit(TLSPage, Y, EditW, GetCmdParam('GRPC_KEY'));
  GRPCKeyBtn := MakeBrowseBtn(TLSPage, Y, EditW + 8, @GRPCKeyBtnClick);
  Y := Y + 24;
  CACertLabel := MakeLabel(TLSPage, Y, 'CA certificate (for verifying agent client certs):');
  Y := Y + 16;
  CACertEdit := MakeEdit(TLSPage, Y, EditW, GetCmdParam('CA_CERT'));
  CACertBtn := MakeBrowseBtn(TLSPage, Y, EditW + 8, @CACertBtnClick);

  NoHTTPSCheckboxClick(nil);
  NoTLSCheckboxClick(nil);
end;

// ── Validation ───────────────────────────────────────────────────────────
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;

  // Validate admin credentials
  if CurPageID = AdminPage.ID then
  begin
    if AdminPage.Values[0] = '' then
    begin
      MsgBox('Admin username is required.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    // (On an upgrade this page is skipped: see ShouldSkipPage.)
    if Length(AdminPage.Values[1]) < 12 then
    begin
      MsgBox('Admin password must be at least 12 characters.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if Utf8ByteLength(AdminPage.Values[1]) > MaxPasswordBytes then
    begin
      MsgBox('Admin password must be at most 1024 bytes as UTF-8 (a character outside ' +
             'ASCII takes 2 to 4 bytes).', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if AdminPage.Values[1] <> AdminPage.Values[2] then
    begin
      MsgBox('Admin passwords do not match.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;

  // Validate operator credentials (only if username provided)
  if CurPageID = OperatorPage.ID then
  begin
    if OperatorPage.Values[0] <> '' then
    begin
      if AdminPage.Values[1] = '' then
      begin
        MsgBox('An operator account can only be set together with a new admin password.',
               mbError, MB_OK);
        Result := False;
        Exit;
      end;
      if Length(OperatorPage.Values[1]) < 12 then
      begin
        MsgBox('Operator password must be at least 12 characters.', mbError, MB_OK);
        Result := False;
        Exit;
      end;
      if Utf8ByteLength(OperatorPage.Values[1]) > MaxPasswordBytes then
      begin
        MsgBox('Operator password must be at most 1024 bytes as UTF-8 (a character outside ' +
               'ASCII takes 2 to 4 bytes).', mbError, MB_OK);
        Result := False;
        Exit;
      end;
      if OperatorPage.Values[1] <> OperatorPage.Values[2] then
      begin
        MsgBox('Operator passwords do not match.', mbError, MB_OK);
        Result := False;
        Exit;
      end;
    end;
  end;

  // A connection string is required unless one is stored already
  if CurPageID = DatabasePage.ID then
  begin
    if (DatabasePage.Values[0] = '') and
       not FileExists(ExpandConstant('{commonappdata}\Yuzu Server\postgres.dsn')) and
       (GetCmdParam('POSTGRES_DSN_FILE') = '') and not EnvVarSet('YUZU_POSTGRES_DSN') then
    begin
      MsgBox('A PostgreSQL connection string is required: the server does not start without ' +
             'a database.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;

  // Validate OIDC fields if enabled
  if CurPageID = IdentityPage.ID then
  begin
    if OIDCCheckbox.Checked then
    begin
      if OIDCIssuerEdit.Text = '' then
      begin
        MsgBox('OIDC issuer URL is required when SSO is enabled.', mbError, MB_OK);
        Result := False;
        Exit;
      end;
      if OIDCClientIdEdit.Text = '' then
      begin
        MsgBox('OIDC client ID is required when SSO is enabled.', mbError, MB_OK);
        Result := False;
        Exit;
      end;
    end;
  end;

  // Validate TLS certificates (warn if HTTPS enabled but no certs)
  if CurPageID = TLSPage.ID then
  begin
    if (not NoHTTPSCheckbox.Checked) and ((HTTPSCertEdit.Text = '') or (HTTPSKeyEdit.Text = '')) then
    begin
      if MsgBox('HTTPS is enabled but no certificate/key was provided. ' +
                'The server will fail to start without them.'#13#10#13#10 +
                'Continue anyway?', mbConfirmation, MB_YESNO) = IDNO then
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
end;

// ── Skip pages in silent mode ────────────────────────────────────────────
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  // An upgrade keeps the existing accounts: the installer cannot change a
  // stored password (#5274), so the credential pages are not offered.
  if ((PageID = AdminPage.ID) or (PageID = OperatorPage.ID)) and ExistingConfig then
    Result := True;
  if WizardSilent then
  begin
    if (PageID = AdminPage.ID) or (PageID = OperatorPage.ID) or
       (PageID = NetworkPage.ID) or (PageID = DatabasePage.ID) or (PageID = IdentityPage.ID) or
       (PageID = TLSPage.ID) then
      Result := True;
  end;
end;

// ── Paths ────────────────────────────────────────────────────────────────
//
// Everything secret lives under "%ProgramData%\Yuzu Server", which the
// installer locks to Administrators and SYSTEM (#5196, #5210):
//   yuzu-server.cfg       dashboard password hashes
//   postgres.dsn          the Postgres connection string (#5272)
//   oidc-client-secret    the OIDC client secret (#5272)
//   certs\                operator TLS certificates and keys
//   data\                 the server's data directory
// The server's OWN CA, default certificates and key-encryption keys stay where
// the server keeps them by default (C:\ProgramData\Yuzu\certs, --ca-dir not
// passed). The server applies its own protected Administrators+SYSTEM DACL to
// that folder and the key files when it writes them (key_provider.cpp,
// WinOwnerOnlyDacl). Moving them needs server changes first -- the CA root's
// key_ref in Postgres is an absolute path into that folder, and the Settings
// page writes uploaded certificates there regardless of --ca-dir (#5273).
// The service's command line (its ImagePath) and its registry Environment value
// are readable by local users, so they carry only PATHS to these files, never a
// secret (--postgres-dsn-file, --oidc-client-secret-file).

function DataDirPath: string;
begin
  Result := ExpandConstant('{commonappdata}\Yuzu Server');
end;

function CertDirPath(const Root: string): string;
begin
  Result := Root + '\certs';
end;

function StagePath: string;
begin
  Result := ExpandConstant('{tmp}\yuzu-server.stage');
end;

// ── Inputs ───────────────────────────────────────────────────────────────

type
  TInstallInputs = record
    AdminUser, AdminPass, OpUser, OpPass: string;
    Dsn, DsnFile: string;
    UseOIDC: Boolean;
    OidcIssuer, OidcClientId, OidcSecret, OidcSecretFile, OidcAdminGroup: string;
    HttpsCert, HttpsKey, GrpcCert, GrpcKey, CaCert: string;
  end;

procedure GetInputs(var R: TInstallInputs);
begin
  if WizardSilent then
  begin
    R.AdminUser := GetCmdParam('ADMIN_USER');
    R.AdminPass := GetCmdParam('ADMIN_PASS');
    R.OpUser := GetCmdParam('OPERATOR_USER');
    R.OpPass := GetCmdParam('OPERATOR_PASS');
    R.Dsn := GetCmdParam('POSTGRES_DSN');
    R.UseOIDC := GetCmdParam('OIDC_ISSUER') <> '';
    R.OidcIssuer := GetCmdParam('OIDC_ISSUER');
    R.OidcClientId := GetCmdParam('OIDC_CLIENT_ID');
    R.OidcSecret := GetCmdParam('OIDC_CLIENT_SECRET');
    R.OidcAdminGroup := GetCmdParam('OIDC_ADMIN_GROUP');
    R.HttpsCert := GetCmdParam('HTTPS_CERT');
    R.HttpsKey := GetCmdParam('HTTPS_KEY');
    R.GrpcCert := GetCmdParam('GRPC_CERT');
    R.GrpcKey := GetCmdParam('GRPC_KEY');
    R.CaCert := GetCmdParam('CA_CERT');
  end
  else
  begin
    R.AdminUser := AdminPage.Values[0];
    R.AdminPass := AdminPage.Values[1];
    R.OpUser := OperatorPage.Values[0];
    R.OpPass := OperatorPage.Values[1];
    R.Dsn := DatabasePage.Values[0];
    R.UseOIDC := OIDCCheckbox.Checked;
    R.OidcIssuer := OIDCIssuerEdit.Text;
    R.OidcClientId := OIDCClientIdEdit.Text;
    R.OidcSecret := OIDCSecretEdit.Text;
    R.OidcAdminGroup := OIDCAdminGroupEdit.Text;
    R.HttpsCert := HTTPSCertEdit.Text;
    R.HttpsKey := HTTPSKeyEdit.Text;
    R.GrpcCert := GRPCCertEdit.Text;
    R.GrpcKey := GRPCKeyEdit.Text;
    R.CaCert := CACertEdit.Text;
    if NoHTTPSCheckbox.Checked then
    begin
      R.HttpsCert := '';
      R.HttpsKey := '';
    end;
    if NoTLSCheckbox.Checked then
    begin
      R.GrpcCert := '';
      R.GrpcKey := '';
      R.CaCert := '';
    end;
  end;
  // The file forms are command-line only: they keep a secret out of the
  // command line, and so out of a /LOG= file, which records it.
  R.DsnFile := GetCmdParam('POSTGRES_DSN_FILE');
  R.OidcSecretFile := GetCmdParam('OIDC_CLIENT_SECRET_FILE');
  if not R.UseOIDC then
  begin
    R.OidcSecret := '';
    R.OidcSecretFile := '';
  end;
end;

function ShouldStartService: Boolean;
begin
  if WizardSilent then
    Result := not HasCmdFlag('NOSTART')
  else
    Result := True;
end;


// ── Helpers ──────────────────────────────────────────────────────────────

function SetEnvironmentVariable(lpName: string; lpValue: string): BOOL;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';

// Embed S as a PowerShell single-quoted literal. Inside single quotes
// PowerShell expands nothing, so the only characters needing care are the ones
// that END the literal: the ASCII quote and the typographic single quotes
// U+2018..U+201B, which PowerShell treats as the same delimiter. Each is
// escaped by doubling it. (Same as the agent installer's PsLit.)
function PsLit(const S: string): string;
var
  I: Integer;
begin
  Result := '';
  for I := 1 to Length(S) do
    if (S[I] = '''') or (S[I] = #$2018) or (S[I] = #$2019) or (S[I] = #$201A) or (S[I] = #$201B) then
      Result := Result + S[I] + S[I]
    else
      Result := Result + S[I];
  Result := '''' + Result + '''';
end;

const
  FileAttrDirectory = $10;
  FileAttrReparsePoint = $400;

// True when Path itself (not what it may point to) is a junction or symbolic
// link. FindFirst on a path with no wildcard returns the entry's own
// attributes from its parent directory, so it never follows the link. Found is
// False when the entry could not be read at all.
function IsReparsePoint(const Path: string; var Found: Boolean): Boolean;
var
  R: TFindRec;
begin
  Result := False;
  Found := FindFirst(Path, R);
  if Found then
  begin
    Result := (R.Attributes and FileAttrReparsePoint) <> 0;
    FindClose(R);
  end;
end;

// Appended to every abort message while the existing service is stopped by
// this run. StoppedRunningService is cleared only when an early insecure-path
// abort starts the service again, so the suffix is shown only while it is
// still stopped (and a retried PrepareToInstall reports the current state).
function AbortSuffix: string;
begin
  Result := '';
  if ServiceDisabled then
    Result := #13#10#13#10 + 'The Yuzu Server service has been stopped and DISABLED (see above).'
  else if StoppedRunningService then
    Result := #13#10#13#10 + 'The existing Yuzu Server service was stopped and has not been ' +
              'restarted. It will start again at the next reboot, or run: sc start YuzuServer';
end;

// The operator-facing refusal for a directory that is not, or could not be
// made, secure.
function NotSecuredMessage(const Dir, Reason: string): string;
begin
  Result := 'The Yuzu Server data directory is not secured:' + #13#10 + Dir + #13#10#13#10 +
            Reason + #13#10#13#10 +
            'Only Administrators and SYSTEM may have access to it: it holds the dashboard ' +
            'password hashes, the database connection string, and the server''s private keys.';
end;

// ── The permission check ─────────────────────────────────────────────────
//
// Runs a PowerShell check and returns '' on PASS, otherwise the reason.
// Modes:
//   root    Path is a directory (not a link) whose DACL is exactly
//           (A;OICI;FA;;;BA)(A;OICI;FA;;;SY), protected, owner BA or SY.
//   tree    root, plus every descendant: not a link, not a hard link, owner
//           BA or SY, NOT protected, and exactly the inherited pair --
//           (A;OICIID;FA;;;..) on a directory, (A;ID;FA;;;..) on a file.
//   owners  root's attributes only (not its DACL), plus every descendant: not
//           a link, not a hard link, owner BA or SY. Used before an
//           already-secured tree's entries are reset to inherit.
//   carry   ListFile names files, one per line, and the directories holding
//           them, as "D|<path>". Each file must be a plain file -- not a
//           directory, link or hard link -- owned by BA or SY, and grant no
//           other account more than read access. Each directory must not be
//           a link, must be owned by BA or SY, and grant no other account
//           delete, delete-child, change-permissions or take-ownership
//           (inherit-only entries do not apply to it and are skipped).
//           Ownership alone is not integrity: a folder a standard user
//           created before the original install keeps that user as owner,
//           so they can re-permission it and delete or rename what an
//           administrator later wrote into it -- swapping a checked file for
//           their own before it is copied -- and any entry granting them
//           write on a file lets them rewrite it in place. The stock
//           ProgramData grants (Users may create files in subfolders, and
//           read) pass.
//
// The same rules as the agent installer's RunAclCheck apply (yuzu-agent.iss;
// the reasons are recorded there): compare the EXACT owner and ACE set on the
// SDDL string, which names accounts by SID alias, never by localised name; no
// .NET method or static call, because Constrained Language Mode (WDAC, or
// AppLocker for a non-SYSTEM install) refuses them -- only property reads,
// -match, -band and cmdlets; attributes are read before any Get-Acl, because
// Get-Acl through a link reads its target; the verdict goes to a file and only
// exit 0 with PASS counts, so every way of not getting an answer fails closed;
// -Command, not -File, because AllSigned governs script files; PSModulePath is
// reset to Windows PowerShell's own modules first (#5176).
//
// The tree walk is done by hand, one directory at a time, and refuses any
// junction or symbolic link where it finds it: Windows PowerShell 5.1's
// Get-ChildItem -Recurse follows them. It checks the entries directly in
// data\ but does not descend into data\'s subdirectories: the server keeps
// large trees there (upload blobs, agent updates) that the installer never
// writes or resets. It is capped (16 levels, 10000 entries) so it refuses
// rather than hangs.
function RunAclCheck(const Path, Mode, ListFile: string): string;
var
  ResultCode: Integer;
  ReasonFile, Script, Reason: string;
  ReasonText: AnsiString;
begin
  Result := '';
  ReasonFile := ExpandConstant('{tmp}\yuzu-server-acl.txt');
  DeleteFile(ReasonFile);
  Script :=
    '$env:PSModulePath=$PSHOME+''\Modules'';' +
    '$ErrorActionPreference=''Stop'';' +
    '$d=' + PsLit(Path) + ';' +
    '$out=' + PsLit(ReasonFile) + ';' +
    '$m=' + PsLit(Mode) + ';' +
    '$lf=' + PsLit(ListFile) + ';' +
    'function Fail($x){Set-Content -LiteralPath $out -Value $x -Encoding ASCII;exit 3};' +
    'function Sd($p){try{return [string](Get-Acl -LiteralPath $p).Sddl}catch{Fail (''the permissions could not be read on '' + $p)}};' +
    'function Own($p,$s){if($s -notmatch ''^O:(BA|SY)G:''){Fail (''it is owned by an account other than Administrators or SYSTEM: '' + $p + '' '' + $s)}};' +
    'if($m -eq ''carry''){' +
      // Rights of an SDDL ACE as a mask. An unknown token counts as full
      // control, so anything unrecognised is refused, never passed.
      '$map=@{''GA''=0x1F01FF;''GW''=0x120116;''GR''=0x120089;''GX''=0x1200A0;''FA''=0x1F01FF;''FW''=0x120116;''FR''=0x120089;''FX''=0x1200A0;''SD''=0x10000;''RC''=0x20000;''WD''=0x40000;''WO''=0x80000;''CC''=1;''DC''=2;''LC''=4;''SW''=8;''RP''=0x10;''WP''=0x20;''DT''=0x40;''LO''=0x80;''CR''=0x100};' +
      'function Mask($t){if($t -match ''^0x[0-9A-Fa-f]+$''){$h=[int64]$t;if(($h -band 0xF0000000) -ne 0){return 0x1F01FF};return $h};$v=0;foreach($k in @($t -split ''(..)'' | Where-Object {$_})){$x=$map[$k];if($null -eq $x){return 0x1F01FF};$v=$v -bor $x};return $v};' +
      // Refuse an Allow entry for any account other than BA/SY whose rights
      // include a bit in $bad. $io: skip inherit-only entries.
      'function Aces($p,$s,$bad,$io,$what){' +
        'if($s -notmatch ''D:[A-Z]*(\(.*?\))(S:.*)?$''){Fail (''its permission list could not be read: '' + $p)};' +
        '$all=($Matches[1] -replace ''^\(|\)$'','''');' +
        'foreach($a in @($all -split ''\)\('')){' +
          '$f=@($a -split '';'');if($f.Count -lt 6){Fail (''its permission list could not be read: '' + $p)};' +
          'if(($f[5] -eq ''BA'') -or ($f[5] -eq ''SY'')){continue};' +
          'if($io -and ($f[1] -match ''IO'')){continue};' +
          // Deny entries take access away; any allow-type other than plain A
          // (conditional XA/ZA, object OA, ...) is one this check does not
          // evaluate, so it is refused rather than skipped.
          'if(($f[0] -eq ''D'') -or ($f[0] -eq ''OD'') -or ($f[0] -eq ''XD'')){continue};' +
          'if($f[0] -ne ''A''){Fail (''its permission list has an entry of a kind this check does not evaluate ('' + $f[0] + '' for '' + $f[5] + ''): '' + $p + '' '' + $s)};' +
          'if(((Mask $f[2]) -band $bad) -ne 0){Fail (''another account ('' + $f[5] + '') can '' + $what + '': '' + $p + '' '' + $s)}' +
        '}' +
      '};' +
      'try{$l=@(Get-Content -LiteralPath $lf -Encoding UTF8)}catch{Fail ''the list of files to carry over could not be read''};' +
      'foreach($e in $l){' +
        'if(-not $e){continue};' +
        'if($e -match ''^D\|(.*)$''){' +
          '$p=$Matches[1];' +
          'try{$i=Get-Item -LiteralPath $p -Force}catch{Fail (''it could not be opened: '' + $p)};' +
          'if(($i.Attributes -band 1024) -ne 0){Fail (''it is a junction or symbolic link, not a directory: '' + $p)};' +
          'if(($i.Attributes -band 16) -eq 0){Fail (''it is a file, not a directory: '' + $p)};' +
          '$s=Sd $p;' +
          'if($s -notmatch ''^O:(BA|SY)G:''){Fail (''the folder holding files to carry over is not owned by Administrators or SYSTEM, so whoever owns it could have changed or swapped them: '' + $p + '' '' + $s)};' +
          'Aces $p $s 0xD0040 $true ''delete, rename or re-permission what is in this folder'';' +
          'continue' +
        '};' +
        '$p=$e;' +
        'try{$i=Get-Item -LiteralPath $p -Force}catch{Fail (''it could not be opened: '' + $p)};' +
        'if(($i.Attributes -band 1024) -ne 0){Fail (''it is a junction or symbolic link, not a file: '' + $p)};' +
        'if(($i.Attributes -band 16) -ne 0){Fail (''it is a directory, not a file: '' + $p)};' +
        'if($i.LinkType -eq ''HardLink''){Fail (''it is a hard link: '' + $p)};' +
        '$s=Sd $p;' +
        'if($s -notmatch ''^O:(BA|SY)G:''){Fail (''it is not owned by Administrators or SYSTEM, so it cannot be confirmed that an administrator or the server placed it: '' + $p + '' '' + $s)};' +
        'Aces $p $s 0xD0156 $false ''change this file''' +
      '};' +
      'Set-Content -LiteralPath $out -Value ''PASS'' -Encoding ASCII;exit 0' +
    '};' +
    'try{$r=Get-Item -LiteralPath $d -Force}catch{Fail ''it could not be opened''};' +
    'if(($r.Attributes -band 1024) -ne 0){Fail ''it is a junction or symbolic link, not a directory''};' +
    'if(($r.Attributes -band 16) -eq 0){Fail ''it is a file, not a directory''};' +
    'if($m -ne ''owners''){' +
      '$s=Sd $d;Own $d $s;' +
      'if($s -notmatch ''D:([A-Z]*)(\(.*)?$''){Fail (''its permission list could not be read: '' + $s)};' +
      '$f=$Matches[1];$l=[string]$Matches[2];' +
      'if($f -notmatch ''P''){Fail ''it still inherits permissions from ProgramData''};' +
      'if(($l -notmatch ''^\(A;OICI;FA;;;(SY|BA)\)\(A;OICI;FA;;;(SY|BA)\)$'') -or ($Matches[1] -eq $Matches[2])){Fail (''its permission list is not exactly Administrators and SYSTEM, each with full control: '' + $s)}' +
    '};' +
    'if($m -eq ''root''){Set-Content -LiteralPath $out -Value ''PASS'' -Encoding ASCII;exit 0};' +
    '$q=@($d);$dp=@(0);$k=0;$n=0;$nd=$d+''\data'';' +
    'while($k -lt $q.Count){' +
      '$cur=$q[$k];$lv=$dp[$k];$k++;' +
      'try{$c=@(Get-ChildItem -LiteralPath $cur -Force)}catch{Fail (''its contents could not be listed: '' + $cur)};' +
      'foreach($i in $c){' +
        '$n++;if($n -gt 10000){Fail ''it holds more than 10000 entries, too many to verify''};' +
        '$p=$i.FullName;' +
        'if(($i.Attributes -band 1024) -ne 0){Fail (''it contains a junction or symbolic link: '' + $p)};' +
        '$dir=(($i.Attributes -band 16) -ne 0);' +
        'if((-not $dir) -and ($i.LinkType -eq ''HardLink'')){Fail (''it contains a hard link: '' + $p)};' +
        '$s=Sd $p;Own $p $s;' +
        'if($m -eq ''tree''){' +
          'if($s -notmatch ''D:([A-Z]*)(\(.*)?$''){Fail (''its permission list could not be read: '' + $p + '' '' + $s)};' +
          '$f=$Matches[1];$l=[string]$Matches[2];' +
          'if($f -match ''P''){Fail (''an entry does not inherit its permissions: '' + $p + '' '' + $s)};' +
          'if($dir){$e=''^\(A;OICIID;FA;;;(SY|BA)\)\(A;OICIID;FA;;;(SY|BA)\)$''}else{$e=''^\(A;ID;FA;;;(SY|BA)\)\(A;ID;FA;;;(SY|BA)\)$''};' +
          'if(($l -notmatch $e) -or ($Matches[1] -eq $Matches[2])){Fail (''an entry''''s permission list is not exactly the inherited Administrators and SYSTEM pair: '' + $p + '' '' + $s)}' +
        '};' +
        'if($dir -and ($cur -ne $nd)){if($lv -ge 16){Fail (''it is nested more than 16 levels deep: '' + $p)};$q+=$p;$dp+=($lv+1)}' +
      '}' +
    '};' +
    'Set-Content -LiteralPath $out -Value ''PASS'' -Encoding ASCII;' +
    'exit 0';

  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
              '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Script + '"',
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := 'the permission check could not be run, so it could not be verified';
    Exit;
  end;
  if LoadStringFromFile(ReasonFile, ReasonText) then
    Reason := Trim(String(ReasonText))
  else
    Reason := '';
  DeleteFile(ReasonFile);
  // Both are required: a non-zero exit means the check rejected it; a zero
  // exit without PASS means it never reached a verdict, which proves nothing.
  if (ResultCode <> 0) or (Reason <> 'PASS') then
  begin
    if Reason = '' then
      Reason := 'the check did not produce a result (exit code ' + IntToStr(ResultCode) + ')';
    Result := Reason;
  end;
end;

// Write Files, and the directories holding them (Dirs), to a list file and
// run the carry check on them.
function CheckCarry(const Files, Dirs: TArrayOfString): string;
var
  ListFile: string;
  All: TArrayOfString;
  I, N: Integer;
begin
  Result := '';
  if GetArrayLength(Files) = 0 then Exit;
  SetArrayLength(All, GetArrayLength(Files) + GetArrayLength(Dirs));
  N := 0;
  for I := 0 to GetArrayLength(Dirs) - 1 do
  begin
    All[N] := 'D|' + Dirs[I];
    N := N + 1;
  end;
  for I := 0 to GetArrayLength(Files) - 1 do
  begin
    All[N] := Files[I];
    N := N + 1;
  end;
  ListFile := ExpandConstant('{tmp}\yuzu-server-carry.txt');
  DeleteFile(ListFile);
  if not SaveStringsToUTF8FileWithoutBOM(ListFile, All, False) then
  begin
    Result := 'the list of files to carry over could not be written';
    Exit;
  end;
  Result := RunAclCheck('', 'carry', ListFile);
  DeleteFile(ListFile);
end;

procedure AddPath(var Files: TArrayOfString; const P: string);
var
  N: Integer;
begin
  N := GetArrayLength(Files);
  SetArrayLength(Files, N + 1);
  Files[N] := P;
end;

// Collect the plain files directly in Dir (subdirectories stay behind). A
// file link is refused; a directory link is skipped, never followed. A Dir
// that does not exist yields nothing. Returns '' or the refusal.
function ListDirectFiles(const Dir: string; var Files: TArrayOfString): string;
var
  R: TFindRec;
  More, Found: Boolean;
begin
  Result := '';
  if IsReparsePoint(Dir, Found) then
  begin
    Result := 'it is a junction or symbolic link, not a directory: ' + Dir;
    Exit;
  end;
  if not Found then Exit;
  if not DirExists(Dir) then
  begin
    Result := 'it is a file, not a directory: ' + Dir;
    Exit;
  end;
  if not FindFirst(Dir + '\*', R) then
  begin
    Result := 'its contents could not be listed: ' + Dir;
    Exit;
  end;
  try
    More := True;
    while More and (Result = '') do
    begin
      if (R.Name <> '.') and (R.Name <> '..') then
      begin
        if (R.Attributes and FileAttrDirectory) = 0 then
        begin
          if (R.Attributes and FileAttrReparsePoint) <> 0 then
            Result := 'it contains a file link, which must be removed with cmd /c del: ' +
                      Dir + '\' + R.Name
          else
            AddPath(Files, Dir + '\' + R.Name);
        end;
      end;
      if Result = '' then
        More := FindNext(R);
    end;
  finally
    FindClose(R);
  end;
end;

// ── Writing into a locked directory ──────────────────────────────────────
//
// Every file is written under a new name in the locked directory, so it is
// created there and inherits Administrators and SYSTEM, then swapped in. Anyone
// holding a handle to an old file keeps the old file.

// Files replaced in the live data directory during this run, for an abort
// message (the in-place path cannot be rolled back as a whole).
var
  Replaced: string;

function SetFileAttributes(lpFileName: string; dwFileAttributes: DWORD): BOOL;
  external 'SetFileAttributesW@kernel32.dll stdcall';

const
  FileAttrNormal = $80;

// The old file is renamed aside first (under a name of its own, so an
// operator's "<file>.old" backup is never touched) and put back if the new one
// cannot be moved in, so a failure never leaves the file missing.
function SwapIn(const Tmp, Dest: string): string;
var
  Old: string;
  HadOld: Boolean;
begin
  Result := '';
  // A source file's read-only attribute is copied with it; it would block
  // replacing this file next time.
  SetFileAttributes(Tmp, FileAttrNormal);
  Old := Dest + '.replaced-' + GetDateTimeString('yyyymmdd-hhnnss', '-', '-');
  HadOld := FileExists(Dest);
  if HadOld then
  begin
    if FileExists(Old) or not RenameFile(Dest, Old) then
    begin
      DeleteFile(Tmp);
      Result := 'Could not replace ' + Dest + ' (it may be in use).';
      Exit;
    end;
  end;
  if not RenameFile(Tmp, Dest) then
  begin
    DeleteFile(Tmp);
    if HadOld and not RenameFile(Old, Dest) then
      Result := 'Could not move the new file into place, nor put the old one back: the old ' +
                'file is now ' + Old
    else
      Result := 'Could not move the new file into place: ' + Dest;
    Exit;
  end;
  if HadOld then
  begin
    SetFileAttributes(Old, FileAttrNormal);
    if not DeleteFile(Old) then
      Log('SwapIn: could not delete the replaced file ' + Old + ' (inside the locked directory).');
  end;
  Replaced := Replaced + #13#10 + '  ' + Dest;
end;

function CopyInto(const Src, Dest: string): string;
var
  Tmp: string;
begin
  Result := '';
  Tmp := ExtractFilePath(Dest) + '.' + ExtractFileName(Dest) + '.new';
  DeleteFile(Tmp);
  if not FileCopy(Src, Tmp, True) then
  begin
    Result := 'Could not copy ' + Src + #13#10 + 'to ' + Dest;
    Exit;
  end;
  Result := SwapIn(Tmp, Dest);
end;

// Write a secret given on the command line or in the wizard (Value), or copy
// it from the operator's file (SrcFile).
function WriteSecret(const Value, SrcFile, Dest: string): string;
var
  Tmp: string;
  Lines: TArrayOfString;
begin
  if SrcFile <> '' then
  begin
    Result := CopyInto(SrcFile, Dest);
    Exit;
  end;
  Result := '';
  Tmp := ExtractFilePath(Dest) + '.' + ExtractFileName(Dest) + '.new';
  DeleteFile(Tmp);
  SetArrayLength(Lines, 1);
  Lines[0] := Value;
  if not SaveStringsToUTF8FileWithoutBOM(Tmp, Lines, False) then
  begin
    DeleteFile(Tmp);
    Result := 'Could not write ' + Dest;
    Exit;
  end;
  Result := SwapIn(Tmp, Dest);
end;

function CopyAll(const Files: TArrayOfString; const DestDir: string): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to GetArrayLength(Files) - 1 do
  begin
    Result := CopyInto(Files[I], DestDir + '\' + ExtractFileName(Files[I]));
    if Result <> '' then Exit;
  end;
end;

function InstallCertificates(const Inp: TInstallInputs; const Root: string): string;
var
  C: string;
begin
  C := CertDirPath(Root);
  Result := '';
  if Inp.HttpsCert <> '' then Result := CopyInto(Inp.HttpsCert, C + '\https-cert.pem');
  if (Result = '') and (Inp.HttpsKey <> '') then Result := CopyInto(Inp.HttpsKey, C + '\https-key.pem');
  if (Result = '') and (Inp.GrpcCert <> '') then Result := CopyInto(Inp.GrpcCert, C + '\grpc-cert.pem');
  if (Result = '') and (Inp.GrpcKey <> '') then Result := CopyInto(Inp.GrpcKey, C + '\grpc-key.pem');
  if (Result = '') and (Inp.CaCert <> '') then Result := CopyInto(Inp.CaCert, C + '\ca-cert.pem');
end;

// ── Configuration (password hashes) ──────────────────────────────────────

// Hashing needs .NET, which Constrained Language Mode refuses. Checked before
// anything changes, with a property read and a cmdlet (both allowed there), so
// the operator gets a reason rather than "no result".
function CheckFullLanguage(): string;
var
  ResultCode: Integer;
begin
  Result := '';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
              '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
              'if($ExecutionContext.SessionState.LanguageMode -ne ''FullLanguage''){exit 4};exit 0"',
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := 'PowerShell could not be started, so the dashboard passwords cannot be hashed.'
  else if ResultCode = 4 then
    Result := 'PowerShell is restricted to Constrained Language Mode on this machine (WDAC ' +
              'script enforcement, or AppLocker script rules for an install run by an ' +
              'administrator), so the installer cannot hash the dashboard passwords. Either ' +
              'upgrade an existing installation without /ADMIN_PASS (its accounts are kept, and ' +
              'nothing needs hashing), or run the installer as SYSTEM, which AppLocker exempts.'
  else if ResultCode <> 0 then
    Result := 'The PowerShell language-mode check failed (exit code ' + IntToStr(ResultCode) + ').';
end;

// Run generate-config.ps1 with the credentials in its environment (never on
// its command line: a '"' in a password broke the quoting, and a command line
// is visible to process listings). The script is loaded as text and run as a
// script block, because a GPO AllSigned policy governs script files.
function WriteServerConfig(const Inp: TInstallInputs; const Root: string): string;
var
  ResultCode: Integer;
  ScriptFile, ReasonFile, Cmd, Reason, CfgPath: string;
  ReasonText: AnsiString;
  Ran: Boolean;
begin
  Result := '';
  CfgPath := Root + '\yuzu-server.cfg';
  ExtractTemporaryFile('generate-config.ps1');
  ScriptFile := ExpandConstant('{tmp}\generate-config.ps1');
  ReasonFile := ExpandConstant('{tmp}\yuzu-server-config.txt');
  DeleteFile(ReasonFile);

  Cmd := 'if($ExecutionContext.SessionState.LanguageMode -ne ''FullLanguage''){' +
           'Set-Content -LiteralPath ' + PsLit(ReasonFile) + ' -Value ''PowerShell is in Constrained Language Mode'' -Encoding ASCII;exit 4};' +
         '$s=[System.IO.File]::ReadAllText(' + PsLit(ScriptFile) + ');' +
         '& ([scriptblock]::Create($s)) -ConfigPath ' + PsLit(CfgPath) +
         ' -ReasonPath ' + PsLit(ReasonFile) + ';' +
         'exit $LASTEXITCODE';

  SetEnvironmentVariable('YUZU_SETUP_ADMIN_USER', Inp.AdminUser);
  SetEnvironmentVariable('YUZU_SETUP_ADMIN_PASS', Inp.AdminPass);
  SetEnvironmentVariable('YUZU_SETUP_OPERATOR_USER', Inp.OpUser);
  SetEnvironmentVariable('YUZU_SETUP_OPERATOR_PASS', Inp.OpPass);
  try
    Ran := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
                '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Cmd + '"',
                '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  finally
    SetEnvironmentVariable('YUZU_SETUP_ADMIN_USER', '');
    SetEnvironmentVariable('YUZU_SETUP_ADMIN_PASS', '');
    SetEnvironmentVariable('YUZU_SETUP_OPERATOR_USER', '');
    SetEnvironmentVariable('YUZU_SETUP_OPERATOR_PASS', '');
  end;

  if LoadStringFromFile(ReasonFile, ReasonText) then
    Reason := Trim(String(ReasonText))
  else
    Reason := '';
  DeleteFile(ReasonFile);

  if not Ran then
    Result := 'The server configuration could not be written: PowerShell could not be started.'
  else if ResultCode <> 0 then
  begin
    if Reason = '' then
      Reason := 'the configuration step failed (exit code ' + IntToStr(ResultCode) + ')';
    Result := 'The server configuration could not be written securely:' + #13#10 + Reason;
  end
  else
    // File.Replace keeps the REPLACED file's permissions; make it inherit
    // again. /L acts on the path itself. The tree check decides.
    Exec(ExpandConstant('{sys}\icacls.exe'), '"' + CfgPath + '" /reset /L /C /Q',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// ── Input validation (before anything changes) ───────────────────────────

function BadUsername(const Name: string): Boolean;
var
  I: Integer;
begin
  Result := Name = '';
  for I := 1 to Length(Name) do
    if (Name[I] = ':') or (Ord(Name[I]) < 32) or (Ord(Name[I]) = 127) then
      Result := True;
end;

// A value placed on the service's command line inside double quotes. No
// double quote, control character or '%' (the ImagePath is expanded, so %NAME%
// would be replaced), and no trailing backslash (the C runtime reads \" as a
// literal quote and merges the next argument into this one).
function BadArg(const S: string): Boolean;
var
  I: Integer;
begin
  Result := (S <> '') and (S[Length(S)] = '\');
  for I := 1 to Length(S) do
    if (S[I] = '"') or (S[I] = '%') or (Ord(S[I]) < 32) then
      Result := True;
end;

function CheckFileParam(const Path, Param: string): string;
var
  Found: Boolean;
begin
  Result := '';
  if Path = '' then Exit;
  if IsReparsePoint(Path, Found) or not Found or not FileExists(Path) then
    Result := 'The file given with /' + Param + '= was not found, or is not a plain file: ' + Path;
end;

// The wizard pages validate an interactive install; a silent one was not
// validated at all. Checked before the service is stopped or anything changes.
function CheckInputs(const Inp: TInstallInputs): string;
begin
  Result := '';
  if Inp.AdminPass <> '' then
  begin
    if BadUsername(Inp.AdminUser) then
      Result := 'An admin username is required (/ADMIN_USER=), without '':'' or control characters.'
    else if Length(Inp.AdminPass) < 12 then
      Result := 'The admin password (/ADMIN_PASS=) must be at least 12 characters.'
    else if Utf8ByteLength(Inp.AdminPass) > MaxPasswordBytes then
      Result := 'The admin password (/ADMIN_PASS=) must be at most 1024 bytes as UTF-8.'
    else if Inp.OpUser <> '' then
    begin
      if BadUsername(Inp.OpUser) then
        Result := 'The operator username (/OPERATOR_USER=) may not contain '':'' or control characters.'
      else if CompareText(Inp.OpUser, Inp.AdminUser) = 0 then
        Result := 'The operator username must differ from the admin username.'
      else if Length(Inp.OpPass) < 12 then
        Result := 'The operator password (/OPERATOR_PASS=) must be at least 12 characters.'
      else if Utf8ByteLength(Inp.OpPass) > MaxPasswordBytes then
        Result := 'The operator password (/OPERATOR_PASS=) must be at most 1024 bytes as UTF-8.';
    end;
  end
  else if WizardSilent and (Inp.AdminUser <> '') then
    Result := '/ADMIN_USER= was given without /ADMIN_PASS=.'
  else if Inp.OpUser <> '' then
    Result := 'An operator account can only be set together with the admin password; leave both ' +
              'out to keep the existing accounts.';
  if Result = '' then
  begin
    if (Inp.Dsn <> '') and (Inp.DsnFile <> '') then
      Result := 'Give either /POSTGRES_DSN= or /POSTGRES_DSN_FILE=, not both.'
    else if (Inp.OidcSecret <> '') and (Inp.OidcSecretFile <> '') then
      Result := 'Give either /OIDC_CLIENT_SECRET= or /OIDC_CLIENT_SECRET_FILE=, not both.'
    else if Inp.UseOIDC and (BadArg(Inp.OidcIssuer) or BadArg(Inp.OidcClientId) or
                            BadArg(Inp.OidcAdminGroup) or (Inp.OidcClientId = '')) then
      Result := 'The OIDC issuer, client ID and admin group may not contain double quotes, ''%'', ' +
                'control characters or a trailing backslash, and a client ID is required with an ' +
                'issuer.';
  end;
  if Result = '' then
  begin
    if (Inp.HttpsCert <> '') <> (Inp.HttpsKey <> '') then
      Result := 'Give the HTTPS certificate and its private key together (/HTTPS_CERT= and /HTTPS_KEY=).'
    else if (Inp.GrpcCert <> '') <> (Inp.GrpcKey <> '') then
      Result := 'Give the gRPC certificate and its private key together (/GRPC_CERT= and /GRPC_KEY=).'
    else if WizardSilent and HasCmdFlag('GATEWAY') and BadArg(GetCmdParam('GATEWAY_ADDR')) then
      Result := 'The gateway address (/GATEWAY_ADDR=) may not contain double quotes, ''%'', ' +
                'control characters or a trailing backslash.'
    else if not WizardSilent and GatewayCheckbox.Checked and BadArg(GatewayAddrEdit.Text) then
      Result := 'The gateway address may not contain double quotes, ''%'', control characters ' +
                'or a trailing backslash.';
  end;
  if Result = '' then Result := CheckFileParam(Inp.DsnFile, 'POSTGRES_DSN_FILE');
  if Result = '' then Result := CheckFileParam(Inp.OidcSecretFile, 'OIDC_CLIENT_SECRET_FILE');
  // Every certificate source is checked before anything is swapped (F5).
  if Result = '' then Result := CheckFileParam(Inp.HttpsCert, 'HTTPS_CERT');
  if Result = '' then Result := CheckFileParam(Inp.HttpsKey, 'HTTPS_KEY');
  if Result = '' then Result := CheckFileParam(Inp.GrpcCert, 'GRPC_CERT');
  if Result = '' then Result := CheckFileParam(Inp.GrpcKey, 'GRPC_KEY');
  if Result = '' then Result := CheckFileParam(Inp.CaCert, 'CA_CERT');
  if Result <> '' then
    Result := Result + #13#10#13#10 + 'Nothing has been changed.';
end;

// ── Service ──────────────────────────────────────────────────────────────

// Evidence that an administrator installed this server before: the
// installer's uninstall key, or a registered YuzuServer service (a server set
// up by hand has only the second). Both take administrator rights to create.
function RegisteredInstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := RegKeyExists(HKLM,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\{A1E3B7F2-4C9D-6F4A-2E8B-3D1C7A5F0E9B}_is1');
  if not Result then
    if Exec(ExpandConstant('{sys}\sc.exe'), 'query YuzuServer', '', SW_HIDE,
            ewWaitUntilTerminated, ResultCode) then
      Result := ResultCode <> 1060;  // 1060 = no such service
end;

// Stop an existing service so its files are not held open, waiting for it
// (bounded) rather than a blind delay. sc.exe's exit code is the Win32 error:
// 1060 = no such service, 1062 = not running.
procedure StopService();
var
  StopResultCode, ResultCode, I: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop YuzuServer', '', SW_HIDE, ewWaitUntilTerminated,
       StopResultCode);
  if StopResultCode = 0 then
  begin
    StoppedRunningService := True;
    ResultCode := 1;
    for I := 1 to 15 do
    begin
      Exec(ExpandConstant('{sys}\cmd.exe'), '/c ""' + ExpandConstant('{sys}\sc.exe') +
           '" query YuzuServer | "' + ExpandConstant('{sys}\find.exe') + '" "STOPPED" >nul"',
           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      if ResultCode = 0 then
        Break;
      Sleep(1000);
    end;
    if ResultCode <> 0 then
      Log('PrepareToInstall: the YuzuServer service did not reach STOPPED within 15s.');
  end;
end;

// The service's command line. It is readable by every local user, so it holds
// paths, never secrets.
function GetServiceArgs: string;
var
  Inp: TInstallInputs;
  DataDir, CertDir: string;
  UseGateway, SkipHTTPS, SkipTLS: Boolean;
begin
  GetInputs(Inp);
  DataDir := DataDirPath;
  CertDir := CertDirPath(DataDir);
  if WizardSilent then
  begin
    UseGateway := HasCmdFlag('GATEWAY');
    SkipHTTPS := HasCmdFlag('NOHTTPS');
    SkipTLS := HasCmdFlag('NOTLS');
  end
  else
  begin
    UseGateway := GatewayCheckbox.Checked;
    SkipHTTPS := NoHTTPSCheckbox.Checked;
    SkipTLS := NoTLSCheckbox.Checked;
  end;

  Result := '--config "' + DataDir + '\yuzu-server.cfg"' +
            ' --data-dir "' + DataDir + '\data"' +
            ' --log-file "' + ExpandConstant('{app}') + '\logs\yuzu-server.log"';
  if FileExists(DataDir + '\postgres.dsn') then
    Result := Result + ' --postgres-dsn-file "' + DataDir + '\postgres.dsn"';

  if UseGateway then
  begin
    Result := Result + ' --gateway-mode --gateway-upstream 0.0.0.0:50055';
    if WizardSilent then
    begin
      if (GetCmdParam('GATEWAY_ADDR') <> '') and not BadArg(GetCmdParam('GATEWAY_ADDR')) then
        Result := Result + ' --gateway-command-addr "' + GetCmdParam('GATEWAY_ADDR') + '"'
      else
        Result := Result + ' --gateway-command-addr localhost:50063';
    end
    else if not BadArg(GatewayAddrEdit.Text) then
      Result := Result + ' --gateway-command-addr "' + GatewayAddrEdit.Text + '"';
  end;

  // TLS files are used when they are in the locked directory -- supplied now,
  // or carried from the previous installation.
  if SkipHTTPS then
    Result := Result + ' --no-https'
  else if FileExists(CertDir + '\https-cert.pem') and FileExists(CertDir + '\https-key.pem') then
    Result := Result + ' --https-cert "' + CertDir + '\https-cert.pem"' +
                       ' --https-key "' + CertDir + '\https-key.pem"';

  if SkipTLS then
    Result := Result + ' --no-tls'
  else
  begin
    if FileExists(CertDir + '\grpc-cert.pem') and FileExists(CertDir + '\grpc-key.pem') then
      Result := Result + ' --cert "' + CertDir + '\grpc-cert.pem"' +
                         ' --key "' + CertDir + '\grpc-key.pem"';
    if FileExists(CertDir + '\ca-cert.pem') then
      Result := Result + ' --ca-cert "' + CertDir + '\ca-cert.pem"';
  end;

  if Inp.UseOIDC then
  begin
    Result := Result + ' --oidc-issuer "' + Inp.OidcIssuer + '"' +
                       ' --oidc-client-id "' + Inp.OidcClientId + '"';
    if FileExists(DataDir + '\oidc-client-secret') then
      Result := Result + ' --oidc-client-secret-file "' + DataDir + '\oidc-client-secret"';
    if Inp.OidcAdminGroup <> '' then
      Result := Result + ' --oidc-admin-group "' + Inp.OidcAdminGroup + '"';
  end;
end;

// 10 when the service could not be registered or configured (see
// CurStepChanged). The installed files are in place, but SCCM/Intune must not
// record this as a working deployment.
function GetCustomSetupExitCode: Integer;
begin
  if ServiceSetupFailed then
    Result := 10
  else
    Result := 0;
end;

// ── Post-install: register the service ───────────────────────────────────
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  BinPath, Want, Got, Key: string;
  Ok: Boolean;
  StartType: Cardinal;
begin
  if CurStep = ssPostInstall then
  begin
    // The data directory, configuration, secrets and certificates were all
    // written and verified by PrepareToInstall, before any file was installed.
    BinPath := ExpandConstant('{app}') + '\bin\yuzu-server.exe';
    Key := 'SYSTEM\CurrentControlSet\Services\YuzuServer';
    Exec(BinPath, '--install-service', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    // Write the command line to the service's ImagePath directly. sc.exe's
    // binPath= quoting mangled a quoted executable path followed by quoted
    // arguments, and an unquoted path with spaces is an unquoted-service-path
    // hole. Then read it back: if security software blocked the write, the
    // OLD command line -- which may carry a secret (0.14.0 passed the OIDC
    // client secret there) -- would otherwise stay in force while Setup
    // reported success.
    Want := '"' + BinPath + '" ' + GetServiceArgs;
    Ok := Exec(ExpandConstant('{sys}\sc.exe'), 'query YuzuServer', '', SW_HIDE,
               ewWaitUntilTerminated, ResultCode) and (ResultCode <> 1060);
    Ok := Ok and RegWriteExpandStringValue(HKLM, Key, 'ImagePath', Want);
    Ok := Ok and RegQueryStringValue(HKLM, Key, 'ImagePath', Got) and (Got = Want);
    if not Ok then
    begin
      ServiceSetupFailed := True;
      Exec(ExpandConstant('{sys}\sc.exe'), 'config YuzuServer start= disabled', '', SW_HIDE,
           ewWaitUntilTerminated, ResultCode);
      // Confirm it rather than claim it: whatever blocked the command line may
      // block this too, and an unregistered service has nothing to disable.
      if RegQueryDWordValue(HKLM, Key, 'Start', StartType) and (StartType = 4) then
        Got := 'The service has been disabled rather than left to run with an old command line.'
      else
        Got := 'The service could NOT be disabled (or is not registered): if it exists, disable ' +
               'it yourself (sc config YuzuServer start= disabled) until this is fixed.';
      Log('CurStepChanged: the YuzuServer service could not be registered, or its command line ' +
          'could not be written and confirmed (security software may have blocked the change). ' +
          Got + ' Setup exits with code 10.');
      SuppressibleMsgBox('The Yuzu Server files were installed, but the YuzuServer service could ' +
        'not be registered, or its command line could not be written and confirmed -- security ' +
        'software may have blocked the change. ' + Got + ' Allow the change and run the ' +
        'installer again.', mbError, MB_OK, IDOK);
    end
    else if ShouldStartService then
      Exec(ExpandConstant('{sys}\sc.exe'), 'start YuzuServer', '', SW_HIDE,
           ewWaitUntilTerminated, ResultCode);
  end;
end;

// ── Before anything is installed: secure, write secrets ──────────────────
//
// "%ProgramData%\Yuzu Server" is in one of three states, decided before the
// service is stopped or anything is changed:
//
//   NEW       it does not exist. A locked directory is built in the
//             installer's private temporary folder, filled, verified, and
//             moved into place, so it never exists unlocked.
//   SECURED   it exists and its top folder is exactly locked. Everything in it
//             must be owned by Administrators or SYSTEM and contain no link;
//             new files are written in place, then the top-level entries,
//             certs\* and data\* are reset to inherit and made
//             Administrators-owned, and the whole tree is verified.
//   INSECURE  it exists but is not locked -- every version before this one
//             left it so. Only if an administrator installed a server here
//             before (RegisteredInstall) is it upgraded: a fresh locked
//             directory is built, only plain, non-hard-linked files owned by
//             Administrators or SYSTEM are copied into it (the configuration,
//             postgres.dsn, oidc-client-secret, and the files directly in
//             certs\ and data\; subdirectories stay behind), the old directory
//             is renamed aside -- never changed or deleted -- and the new one
//             moved into place. Any file that fails the check refuses the
//             whole upgrade, naming it: a file owned by someone else is
//             exactly what a planted file looks like. With no registered
//             installation it is refused outright.
//
// A link (junction or symbolic link) at the path is refused in every state.
// Nothing recurses through a link; nothing takes ownership of anything.
//
// A non-empty result stops the installation with that message (logged, and
// shown unless silent) and Setup exits with code 7. Nothing in {app} has been
// touched at that point.

const
  StateNew = 0;
  StateSecured = 1;
  StateInsecure = 2;

function ClassifyDataDir(var State: Integer): string;
var
  Found: Boolean;
  Reason: string;
begin
  Result := '';
  State := StateNew;
  if IsReparsePoint(DataDirPath, Found) then
  begin
    Result := NotSecuredMessage(DataDirPath, 'It is a junction or symbolic link, not a directory. ' +
      'Remove the link (cmd /c rmdir; never Remove-Item -Recurse, which deletes the target''s ' +
      'contents) and run the installer again.');
    Exit;
  end;
  if not Found then
  begin
    if DirExists(DataDirPath) or FileExists(DataDirPath) then
      Result := NotSecuredMessage(DataDirPath, 'It could not be inspected.');
    Exit;
  end;
  if not DirExists(DataDirPath) then
  begin
    Result := NotSecuredMessage(DataDirPath, 'It is a file, not a directory.');
    Exit;
  end;
  Reason := RunAclCheck(DataDirPath, 'root', '');
  if Reason = '' then
    State := StateSecured
  else if RegisteredInstall() then
  begin
    State := StateInsecure;
    Log('PrepareToInstall: the existing data directory is not secured (' + Reason +
        '); upgrading it into a new, locked directory.');
  end
  else
    Result := NotSecuredMessage(DataDirPath, 'It already exists, it is not secured (' + Reason +
      '), and no Yuzu Server installation is registered on this machine, so it cannot be ' +
      'confirmed that an administrator created it. Check what it contains, move anything of ' +
      'yours to a safe place, delete it (remove any junction or link in it first with ' +
      'cmd /c rmdir or cmd /c del; never Remove-Item -Recurse), and run the installer again.');
end;

// Build an empty locked directory at Stage, with data\ and certs\ in it.
function BuildStage(const Stage: string): string;
var
  ResultCode: Integer;
begin
  Result := '';
  if DirExists(Stage) then
    DelTree(Stage, True, True, True);
  if not ForceDirectories(Stage) then
  begin
    Result := 'Could not create the temporary directory ' + Stage;
    Exit;
  end;
  // No /T, and /L on each, so each acts on this path only. Exit codes are not
  // trusted; the check after them is. /grant:r alone would leave a third
  // SID's explicit entry, hence /reset first (see yuzu-agent.iss).
  Exec(ExpandConstant('{sys}\icacls.exe'), '"' + Stage + '" /setowner *S-1-5-32-544 /L /C /Q',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\icacls.exe'), '"' + Stage + '" /reset /L /C /Q',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\icacls.exe'), '"' + Stage + '" /inheritance:r /grant:r ' +
       '"*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" /L /C /Q',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // Created after the lock, so they inherit it.
  if not (ForceDirectories(Stage + '\data') and ForceDirectories(Stage + '\certs')) then
  begin
    Result := 'Could not create the temporary directory ' + Stage;
    Exit;
  end;
  Result := RunAclCheck(Stage, 'tree', '');
  if Result <> '' then
    Result := 'The new data directory could not be locked: ' + Result + '. Security software ' +
              'may have blocked it.';
end;

function PrepareToInstall(var NeedsRestart: Boolean): string;
var
  Inp: TInstallInputs;
  State, ResultCode: Integer;
  DataDir, Stage, Aside, Reason, OldCfgDir, OldImagePath: string;
  RegenConfig, CarryDsn, CarryOidc: Boolean;
  CarryFiles, DataFiles, Dirs: TArrayOfString;
begin
  GetInputs(Inp);
  DataDir := DataDirPath;
  Stage := StagePath;
  SetArrayLength(CarryFiles, 0);
  SetArrayLength(DataFiles, 0);
  SetArrayLength(Dirs, 0);
  Replaced := '';
  ServiceDisabled := False;

  // ── 1. Every check, before the service is stopped ──
  Result := CheckInputs(Inp);
  if Result = '' then Result := ClassifyDataDir(State);
  if Result = '' then
  begin
    RegenConfig := Inp.AdminPass <> '';
    CarryDsn := (Inp.Dsn = '') and (Inp.DsnFile = '') and (State <> StateNew) and
                FileExists(DataDir + '\postgres.dsn');
    CarryOidc := Inp.UseOIDC and (Inp.OidcSecret = '') and (Inp.OidcSecretFile = '') and
                 (State <> StateNew) and FileExists(DataDir + '\oidc-client-secret');
    if not RegenConfig and ((State = StateNew) or not FileExists(DataDir + '\yuzu-server.cfg')) then
      Result := 'The admin username and password (/ADMIN_USER=, /ADMIN_PASS=) are required: ' +
                'there is no existing configuration to keep.' + #13#10#13#10 +
                'Nothing has been changed.'
    else if (EnvVarSet('YUZU_POSTGRES_DSN')) and ((Inp.Dsn <> '') or (Inp.DsnFile <> '') or CarryDsn) then
      // The server refuses to start with both (--postgres-dsn-file cannot be
      // combined with YUZU_POSTGRES_DSN), so this would install a server
      // that does not boot.
      Result := 'A YUZU_POSTGRES_DSN environment variable is set (machine-wide or for the ' +
                'YuzuServer service), and a connection ' +
                'string is also being stored for the server; the server refuses to start with ' +
                'both. Remove the environment variable (every local user can read it), for ' +
                'example: [Environment]::SetEnvironmentVariable(''YUZU_POSTGRES_DSN'', $null, ' +
                '''Machine''), then run the installer again.' + #13#10#13#10 +
                'Nothing has been changed.'
    else if (Inp.Dsn = '') and (Inp.DsnFile = '') and not CarryDsn then
    begin
      if EnvVarSet('YUZU_POSTGRES_DSN') then
        Log('PrepareToInstall: no connection string was given or stored; the server will use ' +
            'the YUZU_POSTGRES_DSN environment variable (machine-wide or the service''s), which ' +
            'local users can read. Pass /POSTGRES_DSN_FILE= to store it in the locked data directory instead.')
      else
        Result := 'A PostgreSQL connection string is required: the server does not start ' +
                  'without one (ADR-0006). Give /POSTGRES_DSN_FILE=<file> (recommended: it keeps ' +
                  'the password out of the setup log) or /POSTGRES_DSN=<connection string>.' + #13#10#13#10 +
                  'Nothing has been changed.';
    end;
  end;
  if (Result = '') and Inp.UseOIDC and (Inp.OidcSecret = '') and (Inp.OidcSecretFile = '') and
     not CarryOidc then
  begin
    // Earlier installers stored the OIDC client secret nowhere but the
    // service's command line -- and their sc.exe binPath= quoting dropped
    // every argument, so in practice it is there only if an operator added it
    // by hand. If it is, upgrading without giving it again would silently drop
    // it (sign-in for a confidential client such as an Entra web app then fails
    // at the token exchange).
    if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Services\YuzuServer', 'ImagePath',
                               OldImagePath) then
      OldImagePath := '';
    if (Pos('--oidc-client-secret ', OldImagePath) > 0) or
       (Pos('--oidc-client-secret=', OldImagePath) > 0) then
      Result := 'The service''s current command line carries an OIDC client secret (readable by ' +
                'local users), and it is not stored anywhere else. ' +
                'Give it again with /OIDC_CLIENT_SECRET_FILE=<file> (or in the wizard), so it is ' +
                'kept in the secured data directory; then rotate it in your identity provider.' + #13#10#13#10 + 'Nothing has been changed.';
  end;
  if (Result = '') and EnvVarSet('YUZU_OIDC_CLIENT_SECRET') and
     ((Inp.OidcSecret <> '') or (Inp.OidcSecretFile <> '') or CarryOidc) then
    Result := 'A YUZU_OIDC_CLIENT_SECRET environment variable is set (machine-wide or for the ' +
              'YuzuServer service), and an OIDC client secret is also being stored for the server; ' +
              'the server refuses to start with both. Remove the environment variable (local users ' +
              'can read it), then run the installer again.' + #13#10#13#10 + 'Nothing has been changed.';
  if (Result = '') and RegenConfig then
  begin
    Result := CheckFullLanguage();
    if Result <> '' then
      Result := Result + #13#10#13#10 + 'Nothing has been changed.';
  end;
  if (Result = '') and (State = StateSecured) then
  begin
    Reason := RunAclCheck(DataDir, 'owners', '');
    if Reason <> '' then
      Result := NotSecuredMessage(DataDir, Reason + '. Nothing has been changed.');
  end;
  if (Result = '') and (State = StateInsecure) then
  begin
    // What will be carried from the old directory. Only its direct carry
    // sources are inspected; it is never walked.
    if not RegenConfig then AddPath(CarryFiles, DataDir + '\yuzu-server.cfg');
    if CarryDsn then AddPath(CarryFiles, DataDir + '\postgres.dsn');
    if CarryOidc then AddPath(CarryFiles, DataDir + '\oidc-client-secret');
    Reason := ListDirectFiles(CertDirPath(DataDir), CarryFiles);
    if Reason = '' then Reason := ListDirectFiles(DataDir + '\data', DataFiles);
    // The folders the carried files sit in must not be controlled by
    // anyone else either: see RunAclCheck's carry mode.
    AddPath(Dirs, DataDir);
    if DirExists(CertDirPath(DataDir)) then AddPath(Dirs, CertDirPath(DataDir));
    if DirExists(DataDir + '\data') then AddPath(Dirs, DataDir + '\data');
    if Reason = '' then Reason := CheckCarry(CarryFiles, Dirs);
    if Reason = '' then Reason := CheckCarry(DataFiles, Dirs);
    if Reason <> '' then
      Result := NotSecuredMessage(DataDir, 'It is not secured, and it cannot be upgraded: ' +
        Reason + '. Inspect it; if that file is yours, make Administrators its owner ' +
        '(icacls <file> /setowner *S-1-5-32-544 /L) or remove it, then run the installer again. ' +
        'Nothing has been changed.');
  end;
  if Result <> '' then
  begin
    Log('PrepareToInstall: ' + Result);
    Exit;
  end;

  // ── 2. A new or upgraded directory is filled while it is still private ──
  if State <> StateSecured then
  begin
    // The finished directory is moved into place with a rename, which cannot
    // cross volumes. Known now, so refuse now, before anything changes.
    if CompareText(ExtractFileDrive(Stage), ExtractFileDrive(DataDir)) <> 0 then
    begin
      Result := 'The installer''s temporary folder (' + ExtractFileDrive(Stage) + ') is on a ' +
                'different drive from ' + DataDir + ', so the new data directory cannot be moved ' +
                'into place. Set TEMP and TMP to a folder on ' + ExtractFileDrive(DataDir) +
                ', or run the installer as SYSTEM, then run it again.' + #13#10#13#10 +
                'Nothing has been changed.';
      Log('PrepareToInstall: ' + Result);
      Exit;
    end;
    Result := BuildStage(Stage);
    if (Result = '') and (State = StateInsecure) then
    begin
      for ResultCode := 0 to GetArrayLength(CarryFiles) - 1 do
        if Result = '' then
        begin
          if ExtractFilePath(CarryFiles[ResultCode]) = CertDirPath(DataDir) + '\' then
            OldCfgDir := Stage + '\certs'
          else
            OldCfgDir := Stage;
          Result := CopyInto(CarryFiles[ResultCode],
                             OldCfgDir + '\' + ExtractFileName(CarryFiles[ResultCode]));
        end;
    end;
    if Result = '' then Result := InstallCertificates(Inp, Stage);
    if (Result = '') and ((Inp.Dsn <> '') or (Inp.DsnFile <> '')) then
      Result := WriteSecret(Inp.Dsn, Inp.DsnFile, Stage + '\postgres.dsn');
    if (Result = '') and ((Inp.OidcSecret <> '') or (Inp.OidcSecretFile <> '')) then
      Result := WriteSecret(Inp.OidcSecret, Inp.OidcSecretFile, Stage + '\oidc-client-secret');
    if (Result = '') and RegenConfig then Result := WriteServerConfig(Inp, Stage);
    if Result = '' then
    begin
      // Files this installer wrote are owned by whoever ran it, which on a
      // client SKU (or with "Object creator" as the default owner) is the
      // administrator's own account, not Administrators. The stage is private
      // to this installer, so making everything in it Administrators-owned
      // adopts nothing anyone else placed. /L: never through a link.
      Exec(ExpandConstant('{sys}\icacls.exe'), '"' + Stage + '" /setowner *S-1-5-32-544 /T /L /C /Q',
           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Reason := RunAclCheck(Stage, 'tree', '');
      if Reason <> '' then
        Result := NotSecuredMessage(DataDir, 'The new directory did not verify: ' + Reason);
    end;
    if Result <> '' then
    begin
      DelTree(Stage, True, True, True);
      Result := Result + #13#10#13#10 + 'Nothing has been changed.';
      Log('PrepareToInstall: ' + Result);
      Exit;
    end;
  end;

  // ── 3. Stop the service, then put the new state in place ──
  StopService();

  if State = StateSecured then
  begin
    // Created inside the locked directory, so they inherit it.
    if not (ForceDirectories(CertDirPath(DataDir)) and ForceDirectories(DataDir + '\data')) then
      Result := 'Could not create certs\ or data\ in ' + DataDir;
    if Result = '' then Result := InstallCertificates(Inp, DataDir);
    if (Result = '') and ((Inp.Dsn <> '') or (Inp.DsnFile <> '')) then
      Result := WriteSecret(Inp.Dsn, Inp.DsnFile, DataDir + '\postgres.dsn');
    if (Result = '') and ((Inp.OidcSecret <> '') or (Inp.OidcSecretFile <> '')) then
      Result := WriteSecret(Inp.OidcSecret, Inp.OidcSecretFile, DataDir + '\oidc-client-secret');
    if (Result = '') and RegenConfig then Result := WriteServerConfig(Inp, DataDir);
    if Result = '' then
    begin
      // The closed set that may carry explicit permissions: the top-level
      // entries (including certs\ and data\ themselves) and their direct
      // files. No /T. Everything was checked to be owned by Administrators or
      // SYSTEM above, so this only ever repairs their own files.
      Exec(ExpandConstant('{sys}\icacls.exe'), '"' + DataDir + '\*" /reset /L /C /Q',
           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Exec(ExpandConstant('{sys}\icacls.exe'), '"' + CertDirPath(DataDir) + '\*" /reset /L /C /Q',
           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Exec(ExpandConstant('{sys}\icacls.exe'), '"' + DataDir + '\data\*" /reset /L /C /Q',
           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      // And owned by Administrators (files this run wrote are owned by the
      // account that ran it; see the stage note). Same closed set, already
      // checked to be owned by Administrators or SYSTEM.
      Exec(ExpandConstant('{sys}\icacls.exe'), '"' + DataDir + '\*" /setowner *S-1-5-32-544 /L /C /Q',
           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Exec(ExpandConstant('{sys}\icacls.exe'), '"' + CertDirPath(DataDir) + '\*" /setowner *S-1-5-32-544 /L /C /Q',
           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Exec(ExpandConstant('{sys}\icacls.exe'), '"' + DataDir + '\data\*" /setowner *S-1-5-32-544 /L /C /Q',
           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;
  end
  else
  begin
    if State = StateInsecure then
    begin
      // data\ is copied only now, with the service stopped, so its files are
      // consistent.
      Result := CopyAll(DataFiles, Stage + '\data');
      if Result = '' then
      begin
        Exec(ExpandConstant('{sys}\icacls.exe'), '"' + Stage + '" /setowner *S-1-5-32-544 /T /L /C /Q',
             '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        Reason := RunAclCheck(Stage, 'tree', '');
        if Reason <> '' then
          Result := NotSecuredMessage(DataDir, 'The new directory did not verify: ' + Reason);
      end;
      if Result = '' then
      begin
        Aside := DataDir + '.insecure-' + GetDateTimeString('yyyymmdd-hhnnss', '-', '-');
        if not RenameFile(DataDir, Aside) then
        begin
          Result := 'The old data directory could not be renamed aside: something has a file in ' +
                    'it open (close it, or find it with Resource Monitor''s "Associated Handles"):' + #13#10 + DataDir + #13#10#13#10 + 'Nothing has been changed.';
          // Nothing changed, so put the service back the way it was.
          if StoppedRunningService and
             Exec(ExpandConstant('{sys}\sc.exe'), 'start YuzuServer', '', SW_HIDE,
                  ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
            StoppedRunningService := False;
        end;
      end;
      if Result <> '' then
      begin
        DelTree(Stage, True, True, True);
        // Nothing has been changed yet (the old directory is still in place),
        // so put the service back the way it was.
        if StoppedRunningService and
           Exec(ExpandConstant('{sys}\sc.exe'), 'start YuzuServer', '', SW_HIDE,
                ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
          StoppedRunningService := False;
      end;
    end;
    if Result = '' then
    begin
      if not RenameFile(Stage, DataDir) then
      begin
        Result := NotSecuredMessage(DataDir, 'The new directory could not be moved into place ' +
          '(something else already holds the name, or the temporary folder is on another ' +
          'drive). If TEMP is on another drive, set TEMP and TMP to a folder on the system ' +
          'drive, or run the installer as SYSTEM, then run it again.');
        DelTree(Stage, True, True, True);
        if State = StateInsecure then
        begin
          if RenameFile(Aside, DataDir) then
            Result := Result + ' The old directory has been put back.'
          else
          begin
            // Something took the name in the moment it was free. The service
            // must not start over a directory this installer did not make.
            Exec(ExpandConstant('{sys}\sc.exe'), 'config YuzuServer start= disabled', '', SW_HIDE,
                 ewWaitUntilTerminated, ResultCode);
            ServiceDisabled := True;
            Result := Result + ' The old directory could not be put back either: it is now ' +
                      Aside + '. Something else created ' + DataDir + ' in the meantime -- ' +
                      'inspect it. The YuzuServer service has been DISABLED so that it cannot ' +
                      'start over that directory; re-enable it (sc config YuzuServer start= auto) ' +
                      'only after moving the old directory back or running the installer again.';
          end;
        end;
      end
      else if State = StateInsecure then
        Log('PrepareToInstall: the previous, unsecured data directory was kept as ' + Aside +
            '. Its data\ subdirectories (agent-updates, upload-blobs: packages and uploads the ' +
            'database refers to) were NOT carried: check them, then move them into the new data\ ' +
            'before deleting it (see the upgrade note in the server administration guide). Then ' +
            'delete it: it still holds the old password hashes and keys, which local users could ' +
            'read -- rotate them.');
    end;
  end;

  // ── 4. Prove the result ──
  if Result = '' then
  begin
    Reason := RunAclCheck(DataDir, 'tree', '');
    if Reason <> '' then
      Result := NotSecuredMessage(DataDir, Reason + '. Securing it did not take effect -- ' +
        'security software may have blocked it. The installation has been stopped.');
  end;
  if Result <> '' then
  begin
    if (State = StateSecured) and (Replaced <> '') then
      Result := Result + #13#10#13#10 + 'These files had already been replaced in the data ' +
                'directory:' + Replaced;
    Log('PrepareToInstall: ' + Result);
    Result := Result + AbortSuffix;
  end;
end;

// ── Uninstall: offer to remove data directory ────────────────────────────
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    { Ask about the data directory only when someone can answer. A plain MsgBox
      is NOT suppressed by /SUPPRESSMSGBOXES (only SuppressibleMsgBox is), so a
      silent uninstall (SCCM/Intune/GPO, /VERYSILENT) used to wait forever on an
      invisible dialog (#5147). Silent uninstalls keep the data directory, the
      same answer as the prompt's default button. }
    if not UninstallSilent then
      if MsgBox('Remove server data directory?' + #13#10 +
                ExpandConstant('{commonappdata}\Yuzu Server') + #13#10#13#10 +
                'This deletes the configuration (dashboard accounts), the stored database ' +
                'connection string and OIDC secret, your TLS certificates and the server''s data ' +
                'directory. The PostgreSQL database itself is not touched.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        DelTree(ExpandConstant('{commonappdata}\Yuzu Server'), True, True, True);
      end;
  end;
end;
