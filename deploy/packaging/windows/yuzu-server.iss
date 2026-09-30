; Yuzu Server - Windows Installer (InnoSetup 6)
; Build: ISCC.exe yuzu-server.iss
; Silent: YuzuServerSetup.exe /VERYSILENT /SUPPRESSMSGBOXES /ADMIN_USER=admin /ADMIN_PASS=Password123!
;
; Silent parameters:
;   /ADMIN_USER=name       Admin username (required)
;   /ADMIN_PASS=pass       Admin password (required, min 12 chars)
;   /OPERATOR_USER=name    Operator username (optional)
;   /OPERATOR_PASS=pass    Operator password (optional)
;   /GATEWAY               Enable gateway mode
;   /GATEWAY_ADDR=h:p      Gateway command address (default: localhost:50063)
;   /OIDC_ISSUER=url       OIDC issuer URL
;   /OIDC_CLIENT_ID=id     OIDC client ID
;   /OIDC_CLIENT_SECRET=s  OIDC client secret
;   /OIDC_ADMIN_GROUP=g    OIDC admin group name
;   /HTTPS_CERT=path       PEM certificate for HTTPS dashboard
;   /HTTPS_KEY=path        PEM private key for HTTPS dashboard
;   /GRPC_CERT=path        PEM certificate for agent gRPC
;   /GRPC_KEY=path         PEM private key for agent gRPC
;   /CA_CERT=path          PEM CA cert for mTLS agent verification
;   /NOHTTPS               Disable HTTPS (dev only)
;   /NOTLS                 Disable gRPC TLS (dev only)
;   /NOSTART               Do not start service after install

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

; --- Config generator (temporary, removed after install) ---
Source: "generate-config.ps1"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Dirs]
Name: "{app}\logs"; Permissions: admins-full system-full
Name: "{commonappdata}\Yuzu Server"; Permissions: admins-full system-full
Name: "{commonappdata}\Yuzu Server\data"; Permissions: admins-full system-full
Name: "{commonappdata}\Yuzu Server\certs"; Permissions: admins-full system-full

[UninstallRun]
Filename: "sc.exe"; Parameters: "stop YuzuServer"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "cmd.exe"; Parameters: "/c timeout /t 3 /nobreak >nul"; Flags: runhidden waituntilterminated; RunOnceId: "WaitStop"
Filename: "{app}\bin\yuzu-server.exe"; Parameters: "--remove-service"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\logs"

[Code]
// Setup's exit code when the configuration could not be written securely
// (the files are installed but the service is not registered). Above Inno's
// own 0-8 so it cannot be confused with them.
const
  ConfigGenExitCode = 10;

// ── Variables ────────────────────────────────────────────────────────────
var
  // Wizard pages
  AdminPage: TInputQueryWizardPage;
  // Set when yuzu-server.cfg could not be written with its strict ACL; the
  // service is then not registered and setup exits with ConfigGenExitCode.
  ConfigGenFailed: Boolean;
  OperatorPage: TInputQueryWizardPage;
  NetworkPage: TWizardPage;
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
    'policy deployment, and agent commands.');
  AdminPage.Add('Username:', False);
  AdminPage.Add('Password (minimum 12 characters):', True);
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
  OperatorPage.Add('Password (minimum 12 characters):', True);
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

  // ── Page: Identity / OIDC ──
  IdentityPage := CreateCustomPage(NetworkPage.ID,
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
  OIDCSecretLabel := MakeLabel(IdentityPage, Y, 'Client secret:');
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
    if Length(AdminPage.Values[1]) < 12 then
    begin
      MsgBox('Admin password must be at least 12 characters.', mbError, MB_OK);
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
      if Length(OperatorPage.Values[1]) < 12 then
      begin
        MsgBox('Operator password must be at least 12 characters.', mbError, MB_OK);
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
  if WizardSilent then
  begin
    if (PageID = AdminPage.ID) or (PageID = OperatorPage.ID) or
       (PageID = NetworkPage.ID) or (PageID = IdentityPage.ID) or
       (PageID = TLSPage.ID) then
      Result := True;
  end;
end;

// ── Build service arguments ──────────────────────────────────────────────
function GetServiceArgs: string;
var
  DataDir, CertDir: string;
  AdminUser, AdminPass, OpUser, OpPass: string;
  UseGateway, UseOIDC, SkipHTTPS, SkipTLS: Boolean;
begin
  DataDir := ExpandConstant('{commonappdata}\Yuzu Server');
  CertDir := DataDir + '\certs';

  // Read values from pages or command line
  if WizardSilent then
  begin
    AdminUser := GetCmdParam('ADMIN_USER');
    AdminPass := GetCmdParam('ADMIN_PASS');
    OpUser := GetCmdParam('OPERATOR_USER');
    OpPass := GetCmdParam('OPERATOR_PASS');
    UseGateway := HasCmdFlag('GATEWAY');
    UseOIDC := GetCmdParam('OIDC_ISSUER') <> '';
    SkipHTTPS := HasCmdFlag('NOHTTPS');
    SkipTLS := HasCmdFlag('NOTLS');
  end
  else
  begin
    AdminUser := AdminPage.Values[0];
    AdminPass := AdminPage.Values[1];
    OpUser := OperatorPage.Values[0];
    OpPass := OperatorPage.Values[1];
    UseGateway := GatewayCheckbox.Checked;
    UseOIDC := OIDCCheckbox.Checked;
    SkipHTTPS := NoHTTPSCheckbox.Checked;
    SkipTLS := NoTLSCheckbox.Checked;
  end;

  // Base arguments
  Result := '--config "' + DataDir + '\yuzu-server.cfg"' +
            ' --data-dir "' + DataDir + '\data"' +
            ' --log-file "' + ExpandConstant('{app}') + '\logs\yuzu-server.log"';

  // Gateway mode
  if UseGateway then
  begin
    Result := Result + ' --gateway-mode --gateway-upstream 0.0.0.0:50055';
    if WizardSilent then
    begin
      if GetCmdParam('GATEWAY_ADDR') <> '' then
        Result := Result + ' --gateway-command-addr ' + GetCmdParam('GATEWAY_ADDR')
      else
        Result := Result + ' --gateway-command-addr localhost:50063';
    end
    else
      Result := Result + ' --gateway-command-addr ' + GatewayAddrEdit.Text;
  end;

  // HTTPS
  if SkipHTTPS then
    Result := Result + ' --no-https'
  else
  begin
    if WizardSilent then
    begin
      if GetCmdParam('HTTPS_CERT') <> '' then
        Result := Result + ' --https-cert "' + CertDir + '\https-cert.pem"';
      if GetCmdParam('HTTPS_KEY') <> '' then
        Result := Result + ' --https-key "' + CertDir + '\https-key.pem"';
    end
    else
    begin
      if HTTPSCertEdit.Text <> '' then
        Result := Result + ' --https-cert "' + CertDir + '\https-cert.pem"';
      if HTTPSKeyEdit.Text <> '' then
        Result := Result + ' --https-key "' + CertDir + '\https-key.pem"';
    end;
  end;

  // gRPC TLS
  if SkipTLS then
    Result := Result + ' --no-tls'
  else
  begin
    if WizardSilent then
    begin
      if GetCmdParam('GRPC_CERT') <> '' then
        Result := Result + ' --cert "' + CertDir + '\grpc-cert.pem"';
      if GetCmdParam('GRPC_KEY') <> '' then
        Result := Result + ' --key "' + CertDir + '\grpc-key.pem"';
      if GetCmdParam('CA_CERT') <> '' then
        Result := Result + ' --ca-cert "' + CertDir + '\ca-cert.pem"';
    end
    else
    begin
      if GRPCCertEdit.Text <> '' then
        Result := Result + ' --cert "' + CertDir + '\grpc-cert.pem"';
      if GRPCKeyEdit.Text <> '' then
        Result := Result + ' --key "' + CertDir + '\grpc-key.pem"';
      if CACertEdit.Text <> '' then
        Result := Result + ' --ca-cert "' + CertDir + '\ca-cert.pem"';
    end;
  end;

  // OIDC
  if UseOIDC then
  begin
    if WizardSilent then
    begin
      Result := Result + ' --oidc-issuer "' + GetCmdParam('OIDC_ISSUER') + '"';
      Result := Result + ' --oidc-client-id "' + GetCmdParam('OIDC_CLIENT_ID') + '"';
      if GetCmdParam('OIDC_CLIENT_SECRET') <> '' then
        Result := Result + ' --oidc-client-secret "' + GetCmdParam('OIDC_CLIENT_SECRET') + '"';
      if GetCmdParam('OIDC_ADMIN_GROUP') <> '' then
        Result := Result + ' --oidc-admin-group "' + GetCmdParam('OIDC_ADMIN_GROUP') + '"';
    end
    else
    begin
      Result := Result + ' --oidc-issuer "' + OIDCIssuerEdit.Text + '"';
      Result := Result + ' --oidc-client-id "' + OIDCClientIdEdit.Text + '"';
      if OIDCSecretEdit.Text <> '' then
        Result := Result + ' --oidc-client-secret "' + OIDCSecretEdit.Text + '"';
      if OIDCAdminGroupEdit.Text <> '' then
        Result := Result + ' --oidc-admin-group "' + OIDCAdminGroupEdit.Text + '"';
    end;
  end;
end;

// ── Copy certificate files to install directory ──────────────────────────
procedure CopyCertificates;
var
  CertDir: string;
begin
  CertDir := ExpandConstant('{commonappdata}\Yuzu Server\certs');

  if WizardSilent then
  begin
    if GetCmdParam('HTTPS_CERT') <> '' then
      FileCopy(GetCmdParam('HTTPS_CERT'), CertDir + '\https-cert.pem', False);
    if GetCmdParam('HTTPS_KEY') <> '' then
      FileCopy(GetCmdParam('HTTPS_KEY'), CertDir + '\https-key.pem', False);
    if GetCmdParam('GRPC_CERT') <> '' then
      FileCopy(GetCmdParam('GRPC_CERT'), CertDir + '\grpc-cert.pem', False);
    if GetCmdParam('GRPC_KEY') <> '' then
      FileCopy(GetCmdParam('GRPC_KEY'), CertDir + '\grpc-key.pem', False);
    if GetCmdParam('CA_CERT') <> '' then
      FileCopy(GetCmdParam('CA_CERT'), CertDir + '\ca-cert.pem', False);
  end
  else
  begin
    if HTTPSCertEdit.Text <> '' then
      FileCopy(HTTPSCertEdit.Text, CertDir + '\https-cert.pem', False);
    if HTTPSKeyEdit.Text <> '' then
      FileCopy(HTTPSKeyEdit.Text, CertDir + '\https-key.pem', False);
    if GRPCCertEdit.Text <> '' then
      FileCopy(GRPCCertEdit.Text, CertDir + '\grpc-cert.pem', False);
    if GRPCKeyEdit.Text <> '' then
      FileCopy(GRPCKeyEdit.Text, CertDir + '\grpc-key.pem', False);
    if CACertEdit.Text <> '' then
      FileCopy(CACertEdit.Text, CertDir + '\ca-cert.pem', False);
  end;
end;

// ── Build PowerShell arguments for config generation ─────────────────────
function GetConfigGenArgs: string;
var
  DataDir, AdminUser, AdminPass, OpUser, OpPass: string;
begin
  DataDir := ExpandConstant('{commonappdata}\Yuzu Server');

  if WizardSilent then
  begin
    AdminUser := GetCmdParam('ADMIN_USER');
    AdminPass := GetCmdParam('ADMIN_PASS');
    OpUser := GetCmdParam('OPERATOR_USER');
    OpPass := GetCmdParam('OPERATOR_PASS');
  end
  else
  begin
    AdminUser := AdminPage.Values[0];
    AdminPass := AdminPage.Values[1];
    OpUser := OperatorPage.Values[0];
    OpPass := OperatorPage.Values[1];
  end;

  Result := '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{tmp}') + '\generate-config.ps1"' +
            ' -ConfigPath "' + DataDir + '\yuzu-server.cfg"' +
            ' -AdminUser "' + AdminUser + '"' +
            ' -AdminPass "' + AdminPass + '"';
  if OpUser <> '' then
    Result := Result + ' -OperatorUser "' + OpUser + '"' +
              ' -OperatorPass "' + OpPass + '"';
end;

function ShouldStartService: Boolean;
begin
  if WizardSilent then
    Result := not HasCmdFlag('NOSTART')
  else
    Result := True;
end;

// ── Post-install: generate config, copy certs, register service ──────────
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  BinPath, SvcArgs: string;
begin
  if CurStep = ssPostInstall then
  begin
    // 1. Generate yuzu-server.cfg with PBKDF2 hashed credentials. The script
    // writes the hashes only into a file with a verified Administrators+SYSTEM
    // ACL and exits non-zero on any failure (#5176 review, #5196). A failure
    // must not leave a running server: skip cert copy and service
    // registration, and exit setup with ConfigGenExitCode.
    if (not Exec('powershell.exe', GetConfigGenArgs, '', SW_HIDE, ewWaitUntilTerminated, ResultCode))
       or (ResultCode <> 0) then
    begin
      ConfigGenFailed := True;
      Log('Failed to write a securely permissioned server configuration (exit code ' +
          IntToStr(ResultCode) + '). The YuzuServer service was not registered; ' +
          'setup will exit with code ' + IntToStr(ConfigGenExitCode) + '.');
      // Never show this box on a silent install: a plain MsgBox is not
      // suppressed by /SUPPRESSMSGBOXES (#5147). The Log line records it.
      if not WizardSilent then
        MsgBox('The server configuration could not be written with secure permissions ' +
               '(exit code ' + IntToStr(ResultCode) + '), so the Yuzu Server service ' +
               'was not registered. See the setup log, fix the cause and run setup again.',
               mbError, MB_OK);
      Exit;
    end;

    // 2. Copy certificate files
    CopyCertificates;

    // 3. Register the Windows service
    BinPath := ExpandConstant('{app}') + '\bin\yuzu-server.exe';
    Exec(BinPath, '--install-service', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // 4. Configure service with full command line
    SvcArgs := GetServiceArgs;
    Exec('sc.exe', 'config YuzuServer binPath= "' + BinPath + ' ' + SvcArgs + '"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // 5. Start service (unless /NOSTART)
    if ShouldStartService then
      Exec('sc.exe', 'start YuzuServer', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  if ConfigGenFailed then
    Result := ConfigGenExitCode
  else
    Result := 0;
end;

// ── Stop service before upgrade ──────────────────────────────────────────
function PrepareToInstall(var NeedsRestart: Boolean): string;
var
  ResultCode: Integer;
begin
  Result := '';
  Exec('sc.exe', 'stop YuzuServer', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(2000);
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
                'This includes databases, configuration, certificates, and all server state.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        DelTree(ExpandConstant('{commonappdata}\Yuzu Server'), True, True, True);
      end;
  end;
end;
