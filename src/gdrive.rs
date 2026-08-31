// SPDX-License-Identifier: Apache-2.0

//! Google Drive remote backup: OAuth2 login (device flow, falling back to
//! authorization-code + PKCE on a loopback redirect) with credentials
//! encrypted at rest, a thin Drive v3 REST client, and backup/restore
//! orchestration on top of the existing `.tsb` container.
//!
//! Two distinct passwords (mirrored in the CLI help and README):
//! - **Master password** — encrypts the stored Google OAuth credentials.
//! - **Backup password** — encrypts each `.tsb` (prompted per backup/restore,
//!   identical to the local flow).

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::archive;
use crate::backup;
use crate::container;
use crate::crypto::KdfParams;
use crate::error::{Error, Result};
use crate::paths;
use crate::prompt;
use crate::restore;
use crate::snapshot::{self, Reason};
use crate::util;

/// Least-privilege OAuth scope: only files created by this app.
pub const GDRIVE_SCOPE: &str = "https://www.googleapis.com/auth/drive.file";
/// Suffix appended to user-chosen vault names, and the marker-file name
/// inside each vault folder that identifies it as tool-managed.
pub const VAULT_TAG: &str = ".tsbak-vault";
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
const DEVICE_CODE_URL: &str = "https://oauth2.googleapis.com/device/code";
const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DRIVE_API: &str = "https://www.googleapis.com/drive/v3";
const UPLOAD_API: &str = "https://www.googleapis.com/upload/drive/v3/files";

/// OAuth client id baked into the binary (the maintainer's Google Cloud
/// project). `gdrive login` works out of the box with it; override with
/// `TSBAK_GDRIVE_CLIENT_ID` to use your own client.
pub const DEFAULT_CLIENT_ID: &str =
    "455697777200-n4f1hk4sje222v1a08t11kasaof3bu49.apps.googleusercontent.com";

/// Client secret for [`DEFAULT_CLIENT_ID`]. That client is configured as
/// *confidential*, so Google's token endpoint requires the secret. A
/// desktop-client secret only identifies the *app* to Google — it does not
/// authenticate or grant access to any user account.
pub const DEFAULT_CLIENT_SECRET: &str = "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";

/// Optional build-time client id override (`GDRIVE_CLIENT_ID_DEFAULT` env
/// at compile time), for distros that want to bake in their own client.
const BUILD_CLIENT_ID: Option<&'static str> = option_env!("GDRIVE_CLIENT_ID_DEFAULT");

/// Resolve the OAuth2 client id: env `TSBAK_GDRIVE_CLIENT_ID`, else the
/// build-time default, else the baked-in [`DEFAULT_CLIENT_ID`].
pub fn client_id() -> String {
    if let Ok(v) = std::env::var("TSBAK_GDRIVE_CLIENT_ID") {
        let t = v.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if let Some(v) = BUILD_CLIENT_ID {
        let t = v.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    DEFAULT_CLIENT_ID.to_string()
}

/// Resolve the OAuth client secret: env `TSBAK_GDRIVE_CLIENT_SECRET`, else
/// the baked-in [`DEFAULT_CLIENT_SECRET`] **only when** the resolved client
/// is the baked-in one (a custom client may be public and must not receive
/// a foreign secret). Public desktop clients otherwise need no secret
/// (login flows use PKCE); confidential clients require it at Google's
/// token endpoint.
pub fn client_secret() -> Option<String> {
    if let Ok(v) = std::env::var("TSBAK_GDRIVE_CLIENT_SECRET") {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    (client_id() == DEFAULT_CLIENT_ID).then(|| DEFAULT_CLIENT_SECRET.to_string())
}

/// Append `&client_secret=…` to a urlencoded body when a secret is set.
fn push_client_secret(body: &mut String, client_secret: Option<&str>) {
    if let Some(s) = client_secret.filter(|s| !s.is_empty()) {
        body.push_str(&format!("&client_secret={}", url_encode(s)));
    }
}

/// Folder name for a user-chosen vault: `<name>.tsbak-vault`.
pub fn vault_folder_name(name: &str) -> String {
    format!("{name}{VAULT_TAG}")
}

// ---------------------------------------------------------------------------
// Credential store
// ---------------------------------------------------------------------------

/// Plaintext content of the encrypted credential store (a `.tsb` container
/// whose payload is this JSON blob).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Creds {
    pub email: String,
    pub client_id: String,
    /// Optional OAuth client secret. Public desktop clients don't need one
    /// (the login flows use PKCE); confidential clients require it at
    /// Google's token endpoint.
    #[serde(default)]
    pub client_secret: Option<String>,
    pub refresh_token: String,
    #[serde(default)]
    pub access_token: String,
    /// Unix seconds at which `access_token` expires.
    #[serde(default)]
    pub expires_at: i64,
}

impl Creds {
    /// True if the access token is expired (or will be within 60s).
    pub fn token_expired(&self) -> bool {
        self.access_token.is_empty()
            || util::current_time().unix_timestamp() >= self.expires_at - 60
    }
}

/// Write the credential store (encrypted with `master_password`).
pub fn save_creds(path: &Path, master_password: &[u8], creds: &Creds) -> Result<()> {
    let json = serde_json::to_vec_pretty(creds)?;
    container::write(path, master_password, &KdfParams::default(), &json)
}

/// Read and decrypt the credential store.
pub fn load_creds(path: &Path, master_password: &[u8]) -> Result<Creds> {
    if !path.exists() {
        return Err(Error::NotLoggedIn);
    }
    let json = container::read_and_decrypt(path, master_password)?;
    serde_json::from_slice(&json).map_err(|e| Error::BadFormat {
        detail: format!("credential blob: {e}"),
        offset: 0,
    })
}

// ---------------------------------------------------------------------------
// OAuth2 device flow + token refresh
// ---------------------------------------------------------------------------

fn default_interval() -> u64 {
    5
}
fn default_expiry() -> u64 {
    300
}

#[derive(Deserialize)]
struct DeviceCodeResp {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default = "default_interval")]
    interval: u64,
    #[serde(default = "default_expiry")]
    expires_in: u64,
}

#[derive(Deserialize)]
struct TokenResp {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// Tokens returned by a successful device flow or refresh.
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

fn post_form(url: &str, body: &str) -> Result<ureq::Response> {
    match ureq::post(url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(body)
    {
        Ok(resp) => Ok(resp),
        // Surface Google's error body (e.g. "invalid_client: Invalid client
        // type.") instead of a bare status code.
        Err(ureq::Error::Status(code, resp)) => {
            let detail = resp.into_string().unwrap_or_default();
            let detail = detail.trim();
            Err(Error::Gdrive(if detail.is_empty() {
                format!("{url}: status code {code}")
            } else {
                format!("{url}: status code {code} — {detail}")
            }))
        }
        Err(e) => Err(Error::Gdrive(e.to_string())),
    }
}

fn token_error(resp: &TokenResp) -> Result<()> {
    match &resp.error {
        Some(err) => Err(Error::Gdrive(format!(
            "google oauth error: {err} {}",
            resp.error_description.as_deref().unwrap_or("")
        ))),
        None => Ok(()),
    }
}

/// Minimal percent-encoding for form values.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Run the OAuth2 device flow: print the user code, poll until the user
/// authorizes, and return the token pair.
pub fn device_flow(client_id: &str, client_secret: Option<&str>) -> Result<OAuthTokens> {
    let body = format!(
        "client_id={}&scope={}&access_type=offline&prompt=consent",
        url_encode(client_id),
        url_encode(GDRIVE_SCOPE)
    );
    let resp: DeviceCodeResp = post_form(DEVICE_CODE_URL, &body)?
        .into_json()
        .map_err(|e| Error::Gdrive(e.to_string()))?;

    eprintln!("To authorize this tool, visit:");
    eprintln!("  {}", resp.verification_uri);
    eprintln!("and enter the code:  {}", resp.user_code);
    eprintln!("Waiting for authorization …");

    let interval_secs = resp.interval.max(1);
    let deadline = util::current_time() + time::Duration::seconds(resp.expires_in.max(1) as i64);
    loop {
        if util::current_time() >= deadline {
            return Err(Error::Gdrive(
                "device authorization expired; run login again".into(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_secs(interval_secs));
        let mut body = format!(
            "client_id={}&grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={}",
            url_encode(client_id),
            url_encode(&resp.device_code)
        );
        push_client_secret(&mut body, client_secret);
        let tresp: TokenResp = post_form(TOKEN_URL, &body)?
            .into_json()
            .map_err(|e| Error::Gdrive(e.to_string()))?;
        if let Some(err) = &tresp.error {
            match err.as_str() {
                "authorization_pending" => continue,
                "slow_down" => {
                    std::thread::sleep(std::time::Duration::from_secs(interval_secs));
                    continue;
                }
                other => {
                    return Err(Error::Gdrive(format!(
                        "device flow failed: {other} {}",
                        tresp.error_description.as_deref().unwrap_or("")
                    )));
                }
            }
        }
        let refresh = tresp
            .refresh_token
            .clone()
            .ok_or_else(|| Error::Gdrive("google did not return a refresh token".into()))?;
        let access = if tresp.access_token.is_empty() {
            return Err(Error::Gdrive(
                "google did not return an access token".into(),
            ));
        } else {
            tresp.access_token.clone()
        };
        let expires_at =
            util::current_time().unix_timestamp() + tresp.expires_in.unwrap_or(3600) as i64;
        return Ok(OAuthTokens {
            access_token: access,
            refresh_token: refresh,
            expires_at,
        });
    }
}

/// Exchange a refresh token for a fresh access token.
pub fn refresh_access_token(
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) -> Result<(String, i64)> {
    let mut body = format!(
        "client_id={}&grant_type=refresh_token&refresh_token={}",
        url_encode(client_id),
        url_encode(refresh_token)
    );
    push_client_secret(&mut body, client_secret);
    let tresp: TokenResp = post_form(TOKEN_URL, &body)?
        .into_json()
        .map_err(|e| Error::Gdrive(e.to_string()))?;
    token_error(&tresp)?;
    let access = if tresp.access_token.is_empty() {
        return Err(Error::Gdrive("refresh returned no access token".into()));
    } else {
        tresp.access_token.clone()
    };
    let expires_at =
        util::current_time().unix_timestamp() + tresp.expires_in.unwrap_or(3600) as i64;
    Ok((access, expires_at))
}

// ---------------------------------------------------------------------------
// Authorization-code flow (loopback redirect, PKCE)
//
// Fallback for clients where the device flow is not offered (Google
// answers `invalid_client` to /device/code). This is the standard desktop
// login used by gcloud/gh: bind a one-shot listener on 127.0.0.1, open the
// browser to the consent URL, catch the redirect, and exchange the code.
// ---------------------------------------------------------------------------

/// Page the callback listener sends back to the browser.
const CALLBACK_PAGE: &str = "<!doctype html><html><head><meta charset=\"utf-8\">
<title>termius-backup</title></head>
<body style=\"font-family:sans-serif;text-align:center;margin-top:4em\">
<h2>\u{2713} Authorized</h2>
<p>Google access for <b>termius-backup</b> is complete. You can close this
window and return to the terminal.</p>
</body></html>";

/// True when a device-flow error means the device flow itself is not
/// offered for this client (a 401 `invalid_client`), as opposed to a
/// network or user-side failure.
fn device_flow_unavailable(e: &Error) -> bool {
    matches!(e, Error::Gdrive(m) if m.contains("invalid_client"))
}

/// base64url (no padding), for PKCE values.
fn base64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// PKCE code verifier: 32 random bytes, base64url-encoded (43 chars —
/// within the RFC 7636 43–128 range).
fn pkce_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64url(&bytes)
}

/// PKCE `S256` code challenge: BASE64URL(SHA-256(verifier)).
pub(crate) fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    base64url(&Sha256::digest(verifier.as_bytes()))
}

/// `n` random bytes as lowercase hex (for the `state` parameter).
fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode a query-string component.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the OAuth2 callback query: surface `error=…` if present, verify
/// `state`, and return the authorization `code`.
pub(crate) fn parse_callback(query: &str, expected_state: &str) -> Result<String> {
    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    let mut err: Option<String> = None;
    let mut err_desc: Option<String> = None;
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(p) => p,
            None => continue,
        };
        match url_decode(k).as_str() {
            "code" => code = Some(url_decode(v)),
            "state" => state = Some(url_decode(v)),
            "error" => err = Some(url_decode(v)),
            "error_description" => err_desc = Some(url_decode(v)),
            _ => {}
        }
    }
    if let Some(err) = err {
        return Err(Error::Gdrive(format!(
            "browser login failed: {err} {}",
            err_desc.unwrap_or_default()
        )));
    }
    let state =
        state.ok_or_else(|| Error::Gdrive("callback missing the state parameter".into()))?;
    if state != expected_state {
        return Err(Error::Gdrive(
            "callback state mismatch; login failed".into(),
        ));
    }
    match code {
        Some(c) if !c.is_empty() => Ok(c),
        _ => Err(Error::Gdrive("callback missing the code parameter".into())),
    }
}

/// Best-effort: open `url` in the user's default browser.
fn open_browser(url: &str) -> bool {
    let (prog, args): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("open", &[url])
    } else if cfg!(target_os = "windows") {
        ("cmd", &["/C", "start", "", url])
    } else {
        ("xdg-open", &[url])
    };
    std::process::Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

/// Wait for the browser's redirect on the loopback listener and return the
/// authorization `code`. Answers the request with a small "you can close
/// this window" page. Times out after 10 minutes.
fn accept_callback(listener: &std::net::TcpListener, state: &str) -> Result<String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::Gdrive(format!("callback listener: {e}")))?;
    let deadline = util::current_time() + time::Duration::seconds(600);
    let (mut stream, _addr) = loop {
        match listener.accept() {
            Ok(s) => break s,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if util::current_time() >= deadline {
                    return Err(Error::Gdrive(
                        "timed out waiting for the browser redirect; run login again".into(),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => return Err(Error::Gdrive(format!("callback listener: {e}"))),
        }
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    // We only need the request line; read until the first CRLF.
    let mut buf = [0u8; 16_384];
    let mut total = 0usize;
    while total < buf.len() {
        let n = stream
            .read(&mut buf[total..])
            .map_err(|e| Error::Gdrive(format!("callback read: {e}")))?;
        if n == 0 {
            break;
        }
        total += n;
        if total >= 2 && &buf[total - 2..total] == b"\r\n" {
            break;
        }
    }
    let req = String::from_utf8_lossy(&buf[..total]);
    let query = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|p| p.strip_prefix('/'))
        .and_then(|p| p.split_once('?'))
        .map(|(_, q)| q)
        .ok_or_else(|| Error::Gdrive("callback request had no query string".into()))?;
    let code = parse_callback(query, state)?;
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\
         \r\nConnection: close\r\n\r\n{CALLBACK_PAGE}",
        CALLBACK_PAGE.len()
    );
    let _ = stream.write_all(reply.as_bytes());
    let _ = stream.flush();
    Ok(code)
}

/// Authorization-code flow with PKCE and a loopback redirect. Returns the
/// token pair on success.
pub fn auth_code_loopback(client_id: &str, client_secret: Option<&str>) -> Result<OAuthTokens> {
    let verifier = pkce_verifier();
    let state = random_hex(16);
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| Error::Gdrive(format!("could not bind a loopback callback listener: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::Gdrive(format!("callback listener: {e}")))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/");
    let url = format!(
        "{AUTH_URL}?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline\
         &prompt=consent&state={}&code_challenge={}&code_challenge_method=S256",
        url_encode(client_id),
        url_encode(&redirect_uri),
        url_encode(GDRIVE_SCOPE),
        state,
        url_encode(&pkce_challenge(&verifier)),
    );
    eprintln!("Visit this URL in a browser to authorize this tool:");
    eprintln!("  {url}");
    if std::io::stdin().is_terminal() {
        eprintln!("Press Enter to open it in your browser …");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        if !open_browser(&url) {
            eprintln!("(could not launch a browser automatically — open the URL above yourself)");
        }
    }
    eprintln!("Waiting for the browser to redirect back …");
    let code = accept_callback(&listener, &state)?;
    let mut body = format!(
        "client_id={}&grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}",
        url_encode(client_id),
        url_encode(&code),
        url_encode(&redirect_uri),
        url_encode(&verifier),
    );
    push_client_secret(&mut body, client_secret);
    let tresp: TokenResp = post_form(TOKEN_URL, &body)?
        .into_json()
        .map_err(|e| Error::Gdrive(e.to_string()))?;
    token_error(&tresp)?;
    let refresh = tresp
        .refresh_token
        .clone()
        .ok_or_else(|| Error::Gdrive("google did not return a refresh token".into()))?;
    let access = if tresp.access_token.is_empty() {
        return Err(Error::Gdrive(
            "google did not return an access token".into(),
        ));
    } else {
        tresp.access_token.clone()
    };
    let expires_at =
        util::current_time().unix_timestamp() + tresp.expires_in.unwrap_or(3600) as i64;
    Ok(OAuthTokens {
        access_token: access,
        refresh_token: refresh,
        expires_at,
    })
}

// ---------------------------------------------------------------------------
// Drive v3 REST client
// ---------------------------------------------------------------------------

/// A tool-managed vault folder (name ends with `VAULT_TAG` and contains a
/// valid `.tsbak-vault` marker file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFolder {
    pub id: String,
    pub name: String,
    /// Timestamp of the newest `.tsb` child, if any.
    pub last_backup: Option<time::OffsetDateTime>,
    pub backup_count: u64,
}

/// A remote `.tsb` backup file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBackup {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub created: Option<time::OffsetDateTime>,
}

/// Abstraction over the Google Drive API so orchestration is unit-testable
/// with an in-memory mock (no network in CI).
pub trait GdriveClient {
    /// List tool-managed vault folders, newest last-backup first.
    fn list_vaults(&mut self) -> Result<Vec<VaultFolder>>;
    /// List `.tsb` backups in a vault folder, newest first.
    fn list_backups(&mut self, folder_id: &str) -> Result<Vec<RemoteBackup>>;
    /// Find-or-create a vault folder for `name` (including its marker file).
    fn ensure_vault(&mut self, name: &str) -> Result<String>;
    /// Upload `data` as a file named `name` into `folder_id`; returns id.
    fn upload_file(&mut self, folder_id: &str, name: &str, data: &[u8]) -> Result<String>;
    /// Download a file's bytes; returns the content.
    fn download_file(&mut self, file_id: &str) -> Result<Vec<u8>>;
}

#[derive(Deserialize)]
struct DriveFile {
    id: String,
    name: String,
    #[serde(rename = "mimeType", default)]
    mime: String,
    /// Drive reports size as a decimal string.
    #[serde(default)]
    size: Option<String>,
    #[serde(default)]
    created_time: Option<String>,
}

#[derive(Deserialize)]
struct FileList {
    #[serde(default)]
    files: Vec<DriveFile>,
}

#[derive(Deserialize)]
struct FileCreated {
    id: String,
}

#[derive(Serialize, Deserialize)]
struct VaultMarker {
    kind: String,
    version: u8,
    created_at: String,
    tool_version: String,
}

fn parse_rfc3339(s: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

/// The real Drive v3 REST client.
pub struct HttpGdriveClient {
    access_token: String,
}

impl HttpGdriveClient {
    pub fn new(access_token: String) -> Self {
        HttpGdriveClient { access_token }
    }

    fn authed(&self, req: ureq::Request) -> ureq::Request {
        req.set("Authorization", &format!("Bearer {}", self.access_token))
    }

    fn list_children(&self, folder_id: &str) -> Result<Vec<DriveFile>> {
        let q = url_encode(&format!("'{folder_id}' in parents and trashed=false"));
        let resp = self
            .authed(ureq::get(&format!(
                "{DRIVE_API}/files?q={q}&pageSize=1000&fields=files(id,name,mimeType,size,createdTime)"
            )))
            .call()?;
        let fl: FileList = resp.into_json().map_err(|e| Error::Gdrive(e.to_string()))?;
        Ok(fl.files)
    }
}

impl GdriveClient for HttpGdriveClient {
    fn list_vaults(&mut self) -> Result<Vec<VaultFolder>> {
        let q = url_encode(&format!(
            "name contains '{VAULT_TAG}' and mimeType='{FOLDER_MIME}' and trashed=false"
        ));
        let resp = self
            .authed(ureq::get(&format!(
                "{DRIVE_API}/files?q={q}&pageSize=1000&fields=files(id,name)"
            )))
            .call()?;
        let fl: FileList = resp.into_json().map_err(|e| Error::Gdrive(e.to_string()))?;

        let mut vaults = Vec::new();
        for f in fl.files {
            if !f.mime.ends_with("folder") && f.mime != FOLDER_MIME {
                continue;
            }
            let children = self.list_children(&f.id)?;
            let marker = children
                .iter()
                .find(|c| c.name == VAULT_TAG)
                .map(|c| self.download_file(&c.id))
                .transpose()?;
            let marker_ok = match &marker {
                Some(bytes) => serde_json::from_slice::<VaultMarker>(bytes)
                    .map(|m| m.kind == "tsbak-vault")
                    .unwrap_or(false),
                None => false,
            };
            if !marker_ok {
                continue;
            }
            let tsbs: Vec<&DriveFile> = children
                .iter()
                .filter(|c| c.name.ends_with(".tsb"))
                .collect();
            let last = tsbs
                .iter()
                .filter_map(|c| c.created_time.as_deref().and_then(parse_rfc3339))
                .max();
            vaults.push(VaultFolder {
                id: f.id.clone(),
                name: f.name.clone(),
                last_backup: last,
                backup_count: tsbs.len() as u64,
            });
        }
        // Newest last-backup first (None last).
        vaults.sort_by(|a, b| {
            b.last_backup
                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
                .cmp(&a.last_backup.unwrap_or(time::OffsetDateTime::UNIX_EPOCH))
        });
        Ok(vaults)
    }

    fn list_backups(&mut self, folder_id: &str) -> Result<Vec<RemoteBackup>> {
        let children = self.list_children(folder_id)?;
        let mut backups: Vec<RemoteBackup> = children
            .into_iter()
            .filter(|c| c.name.ends_with(".tsb"))
            .map(|c| RemoteBackup {
                id: c.id,
                name: c.name,
                size: c.size.and_then(|s| s.parse().ok()).unwrap_or(0),
                created: c.created_time.as_deref().and_then(parse_rfc3339),
            })
            .collect();
        backups.sort_by(|a, b| {
            b.created
                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
                .cmp(&a.created.unwrap_or(time::OffsetDateTime::UNIX_EPOCH))
        });
        Ok(backups)
    }

    fn ensure_vault(&mut self, name: &str) -> Result<String> {
        let folder_name = vault_folder_name(name);
        let q = url_encode(&format!(
            "name = '{folder_name}' and mimeType='{FOLDER_MIME}' and trashed=false"
        ));
        let resp = self
            .authed(ureq::get(&format!(
                "{DRIVE_API}/files?q={q}&fields=files(id,name)"
            )))
            .call()?;
        let fl: FileList = resp.into_json().map_err(|e| Error::Gdrive(e.to_string()))?;

        let existing = fl.files.into_iter().next();
        let folder_id = match existing {
            Some(f) => f.id,
            None => {
                let resp = self
                    .authed(ureq::post(&format!("{DRIVE_API}/files")))
                    .set("Content-Type", "application/json")
                    .send_json(serde_json::json!({
                        "name": folder_name,
                        "mimeType": FOLDER_MIME,
                    }))?;
                let created: FileCreated =
                    resp.into_json().map_err(|e| Error::Gdrive(e.to_string()))?;
                created.id
            }
        };

        // Ensure the marker file exists.
        let children = self.list_children(&folder_id)?;
        if !children.iter().any(|c| c.name == VAULT_TAG) {
            let marker = VaultMarker {
                kind: "tsbak-vault".into(),
                version: 1,
                created_at: util::local_timestamp_string(&util::current_time()),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            let bytes = serde_json::to_vec_pretty(&marker)?;
            let resp = self
                .authed(ureq::post(&format!(
                    "{UPLOAD_API}?uploadType=media&fields=id"
                )))
                .set("Content-Type", "application/json")
                .send_bytes(&bytes)?;
            let _created: FileCreated =
                resp.into_json().map_err(|e| Error::Gdrive(e.to_string()))?;
        }
        Ok(folder_id)
    }

    fn upload_file(&mut self, folder_id: &str, name: &str, data: &[u8]) -> Result<String> {
        // Random multipart boundary.
        let mut nb = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nb);
        let boundary = format!("tsbak{}", util::hex::encode_lower_owned(&nb));
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/json; charset UTF-8\r\n\r\n");
        body.extend_from_slice(
            serde_json::to_vec(&serde_json::json!({
                "name": name,
                "parents": [folder_id],
            }))?
            .as_slice(),
        );
        body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let resp = self
            .authed(ureq::post(&format!(
                "{UPLOAD_API}?uploadType=multipart&fields=id"
            )))
            .set(
                "Content-Type",
                &format!("multipart/related; boundary={boundary}"),
            )
            .send_bytes(&body)?;
        let created: FileCreated = resp.into_json().map_err(|e| Error::Gdrive(e.to_string()))?;
        Ok(created.id)
    }

    fn download_file(&mut self, file_id: &str) -> Result<Vec<u8>> {
        let resp = self
            .authed(ureq::get(&format!("{DRIVE_API}/files/{file_id}?alt=media")))
            .call()?;
        let mut buf = Vec::new();
        resp.into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| Error::Gdrive(e.to_string()))?;
        Ok(buf)
    }
}

/// In-memory mock of [`GdriveClient`] for offline unit tests.
#[derive(Debug, Default)]
pub struct MockGdriveClient {
    /// (id, name, has_marker)
    pub folders: Vec<(String, String, bool)>,
    /// (id, folder_id, name, data, seq)
    pub files: Vec<(String, String, String, Vec<u8>, u64)>,
    next_id: u64,
}

impl MockGdriveClient {
    pub fn new() -> Self {
        Self::default()
    }
    fn alloc_id(&mut self) -> String {
        self.next_id += 1;
        format!("mock-{}", self.next_id)
    }
    /// The most recently uploaded file's bytes (test helper).
    pub fn last_upload(&self) -> Option<&[u8]> {
        self.files.last().map(|f| f.3.as_slice())
    }
}

impl GdriveClient for MockGdriveClient {
    fn list_vaults(&mut self) -> Result<Vec<VaultFolder>> {
        let mut vaults = Vec::new();
        for (id, name, has_marker) in self.folders.iter() {
            if !name.ends_with(VAULT_TAG) || !has_marker {
                continue;
            }
            let tsbs: Vec<&(String, String, String, Vec<u8>, u64)> = self
                .files
                .iter()
                .filter(|f| &f.1 == id && f.2.ends_with(".tsb"))
                .collect();
            let last_seq = tsbs.iter().map(|f| f.4).max();
            vaults.push(VaultFolder {
                id: id.clone(),
                name: name.clone(),
                // The mock has no wall-clock times; expose a synthetic time
                // ordered by upload sequence so "newest first" is testable.
                last_backup: last_seq
                    .map(|s| time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(s as i64)),
                backup_count: tsbs.len() as u64,
            });
        }
        vaults.sort_by(|a, b| {
            b.last_backup
                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
                .cmp(&a.last_backup.unwrap_or(time::OffsetDateTime::UNIX_EPOCH))
        });
        Ok(vaults)
    }

    fn list_backups(&mut self, folder_id: &str) -> Result<Vec<RemoteBackup>> {
        let mut backups: Vec<RemoteBackup> = self
            .files
            .iter()
            .filter(|f| f.1 == folder_id && f.2.ends_with(".tsb"))
            .map(|f| RemoteBackup {
                id: f.0.clone(),
                name: f.2.clone(),
                size: f.3.len() as u64,
                created: Some(
                    time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(f.4 as i64),
                ),
            })
            .collect();
        backups.sort_by(|a, b| {
            b.created
                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
                .cmp(&a.created.unwrap_or(time::OffsetDateTime::UNIX_EPOCH))
        });
        Ok(backups)
    }

    fn ensure_vault(&mut self, name: &str) -> Result<String> {
        let folder_name = vault_folder_name(name);
        if let Some((id, _, has_marker)) =
            self.folders.iter_mut().find(|(_, n, _)| *n == folder_name)
        {
            *has_marker = true;
            return Ok(id.clone());
        }
        let id = self.alloc_id();
        self.folders.push((id.clone(), folder_name, true));
        Ok(id)
    }

    fn upload_file(&mut self, folder_id: &str, name: &str, data: &[u8]) -> Result<String> {
        let id = self.alloc_id();
        self.files.push((
            id.clone(),
            folder_id.to_string(),
            name.to_string(),
            data.to_vec(),
            self.next_id,
        ));
        Ok(id)
    }

    fn download_file(&mut self, file_id: &str) -> Result<Vec<u8>> {
        self.files
            .iter()
            .find(|f| f.0 == file_id)
            .map(|f| f.3.clone())
            .ok_or_else(|| Error::Gdrive(format!("mock: no file {file_id}")))
    }
}

// ---------------------------------------------------------------------------
// Session + orchestration
// ---------------------------------------------------------------------------

/// An authenticated Drive session: decrypted credentials + a live client.
pub struct Session {
    creds: Creds,
    client: Box<dyn GdriveClient>,
}

impl Session {
    /// The Google account these credentials belong to.
    pub fn email(&self) -> &str {
        &self.creds.email
    }

    /// Production constructor: load + decrypt the credential store, refresh
    /// the access token if expired (persisting it), and open a real client.
    pub fn open(creds_path: &Path, master_password: &[u8]) -> Result<Self> {
        let mut creds = load_creds(creds_path, master_password)?;
        if creds.token_expired() {
            // Refresh with the client the login actually used (stored in
            // the credential blob), not the currently resolved one — the
            // two may differ if the user switched clients since login.
            eprintln!("Refreshing Google access token …");
            let (at, exp) = refresh_access_token(
                &creds.client_id,
                creds.client_secret.as_deref(),
                &creds.refresh_token,
            )?;
            creds.access_token = at;
            creds.expires_at = exp;
            save_creds(creds_path, master_password, &creds)?;
        }
        let access_token = creds.access_token.clone();
        Ok(Session {
            creds,
            client: Box::new(HttpGdriveClient::new(access_token)),
        })
    }

    /// Constructor for tests / custom clients.
    pub fn new_with_client(creds: Creds, client: Box<dyn GdriveClient>) -> Self {
        Session { creds, client }
    }

    /// Forward to the underlying client (see [`GdriveClient`]).
    pub fn list_vaults(&mut self) -> Result<Vec<VaultFolder>> {
        self.client.list_vaults()
    }
    pub fn list_backups(&mut self, folder_id: &str) -> Result<Vec<RemoteBackup>> {
        self.client.list_backups(folder_id)
    }
    pub fn ensure_vault(&mut self, name: &str) -> Result<String> {
        self.client.ensure_vault(name)
    }
    pub fn upload_file(&mut self, folder_id: &str, name: &str, data: &[u8]) -> Result<String> {
        self.client.upload_file(folder_id, name, data)
    }
    pub fn download_file(&mut self, file_id: &str) -> Result<Vec<u8>> {
        self.client.download_file(file_id)
    }
}

/// Load credentials (prompting for the master password) and open a session.
pub fn open_session(creds_path: &Path) -> Result<Session> {
    if !creds_path.exists() {
        return Err(Error::NotLoggedIn);
    }
    let master = prompt::read_password("Google Drive master password: ")?;
    Session::open(creds_path, master.as_bytes())
}

/// Prompt for the master password (with re-entry + weak gate), then load
/// and decrypt the credential store.
fn read_master_password(creds_path: &Path) -> Result<Creds> {
    let pw = prompt::ask_password("master password (Google Drive credentials)", true, false)?;
    load_creds(creds_path, pw.as_bytes())
}

/// `gdrive login`: device flow → store encrypted credentials.
pub fn run_login(creds_path: &Path) -> Result<()> {
    if creds_path.exists()
        && !prompt::confirm("Already logged in. Re-login and replace the stored credentials?")?
    {
        return Err(Error::Canceled("login canceled".into()));
    }
    let client_id = client_id();
    let client_secret = client_secret();
    let email = prompt::ask_string("Google Drive account email (labels this backup):", None)?;
    let tokens = match device_flow(&client_id, client_secret.as_deref()) {
        Ok(t) => t,
        Err(e) if device_flow_unavailable(&e) => {
            eprintln!();
            eprintln!("Google did not offer the device flow for this client, so");
            eprintln!("falling back to browser login (loopback redirect).");
            auth_code_loopback(&client_id, client_secret.as_deref())?
        }
        Err(e) => return Err(e),
    };
    let master = prompt::ask_password("master password (Google Drive credentials)", true, false)?;
    let creds = Creds {
        email,
        client_id,
        client_secret,
        refresh_token: tokens.refresh_token,
        access_token: tokens.access_token,
        expires_at: tokens.expires_at,
    };
    save_creds(creds_path, master.as_bytes(), &creds)?;
    eprintln!(
        "Logged in. Credentials stored encrypted at {}",
        creds_path.display()
    );
    Ok(())
}

/// `gdrive logout`: delete the credential store.
pub fn run_logout(creds_path: &Path) -> Result<()> {
    if !creds_path.exists() {
        eprintln!("Not logged in; nothing to remove.");
        return Ok(());
    }
    std::fs::remove_file(creds_path)?;
    eprintln!("Credentials removed from {}.", creds_path.display());
    Ok(())
}

/// `gdrive status`: show the linked account.
pub fn run_status(creds_path: &Path) -> Result<()> {
    if !creds_path.exists() {
        return Err(Error::NotLoggedIn);
    }
    let creds = read_master_password(creds_path)?;
    eprintln!("Google Drive account: {}", creds.email);
    eprintln!("Credentials stored at:    {}", creds_path.display());
    eprintln!("Token expires:            {} (auto-refreshed on use)", {
        time::OffsetDateTime::from_unix_timestamp(creds.expires_at)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    });
    Ok(())
}

/// Encrypt `plaintext` into a `.tsb` container using explicit KDF params.
fn encrypt_with(params: &KdfParams, password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let tmp = tempfile::NamedTempFile::new()?;
    container::write(tmp.path(), password, params, plaintext)?;
    Ok(std::fs::read(tmp.path())?)
}

/// Encrypt `plaintext` into an in-memory `.tsb` container (production KDF).
fn encrypt_to_tsb(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_with(&KdfParams::default(), password, plaintext)
}

/// Options for `gdrive backup`.
pub struct BackupOptions<'a> {
    pub termius_dir: Option<&'a Path>,
    /// Vault name (prompts if absent).
    pub name: Option<&'a str>,
    pub password_file: Option<&'a Path>,
    pub password_env: Option<&'a str>,
    pub creds_path: &'a Path,
    pub yes: bool,
}

/// Run a Google Drive backup. Returns `(vault_name, drive_file_id)`.
pub fn run_backup(opts: BackupOptions<'_>) -> Result<(String, String)> {
    let src = paths::resolve_termius_dir(opts.termius_dir)?;

    // Unlock the stored Google credentials first (asks for the master
    // password when already logged in) so a wrong master fails fast, before
    // any backup work.
    let mut session = open_session(opts.creds_path)?;

    let name = match opts.name {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => prompt::ask_string(
            "Name for this backup (a <name>.tsbak-vault folder on Drive):",
            None,
        )?,
    };
    let vault_name = vault_folder_name(&name);

    let now = util::current_time();
    let file_name = format!("{}-termius.tsb", util::local_timestamp_string(&now));

    // Backup password (re-entry + weak gate) — encrypts the payload.
    let password = backup::acquire_password(opts.password_file, opts.password_env, true, opts.yes)?;

    eprintln!("Packing {} …", src.display());
    let mut payload = Vec::new();
    let meta = archive::pack(&src, &mut payload, &util::local_timestamp_string(&now))?;
    eprintln!(
        "Packed {} entries ({} bytes).",
        meta.entry_count, meta.byte_size
    );
    let tsb = encrypt_to_tsb(password.as_bytes(), &payload)?;
    for b in payload.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }

    let folder_id = session.ensure_vault(&name)?;
    let file_id = session.upload_file(&folder_id, &file_name, &tsb)?;
    eprintln!("Uploaded {file_name} to vault '{vault_name}' (Drive file id {file_id}).");
    Ok((vault_name, file_id))
}

/// Options for `gdrive restore`.
pub struct RestoreOptions<'a> {
    pub termius_dir: Option<&'a Path>,
    pub snapshots_dir: Option<&'a Path>,
    pub password_file: Option<&'a Path>,
    pub password_env: Option<&'a str>,
    pub creds_path: &'a Path,
    pub yes: bool,
}

/// Run a Google Drive restore: list vaults → pick → list backups → pick →
/// download → decrypt → (re)confirm → restore into the live dir.
pub fn run_restore(opts: RestoreOptions<'_>) -> Result<PathBuf> {
    let mut session = open_session(opts.creds_path)?;

    // 1. List and choose a vault.
    let vaults = session.list_vaults()?;
    if vaults.is_empty() {
        return Err(Error::NotFound(
            "no backup vaults found on Google Drive".into(),
        ));
    }
    eprintln!("Backup vaults on Google Drive (newest last backup first):");
    let vault_labels: Vec<String> = vaults
        .iter()
        .map(|v| {
            let last = v
                .last_backup
                .map(|t| util::local_timestamp_string(&t))
                .unwrap_or_else(|| "no backups".into());
            format!(
                "{}  (last backup: {last}, {} backup(s))",
                v.name, v.backup_count
            )
        })
        .collect();
    let vi = prompt::choose("Select a vault", &vault_labels)?;
    let vault = &vaults[vi];

    // 2. List and choose a backup.
    let backups = session.list_backups(&vault.id)?;
    if backups.is_empty() {
        return Err(Error::NotFound(format!(
            "vault '{}' has no backups",
            vault.name
        )));
    }
    eprintln!("Backups in vault '{}':", vault.name);
    let backup_labels: Vec<String> = backups
        .iter()
        .map(|b| {
            let d = b
                .created
                .map(|t| util::local_timestamp_string(&t))
                .unwrap_or_default();
            format!("{}  ({} bytes, created {d})", b.name, b.size)
        })
        .collect();
    let bi = prompt::choose("Select a backup to restore", &backup_labels)?;
    let backup = &backups[bi];

    // 3. Download to a temp file.
    let tsb_bytes = session.download_file(&backup.id)?;
    let tmp = tempfile::NamedTempFile::new()?;
    std::fs::write(tmp.path(), &tsb_bytes)?;

    // 4. Destination + snapshot store.
    let dest =
        paths::resolve_termius_dir(opts.termius_dir).or_else(|_| match opts.termius_dir {
            Some(p) => Ok(p.to_path_buf()),
            None => paths::default_termius_dir(),
        })?;
    let snaps = paths::resolve_snapshots_dir(opts.snapshots_dir)?;

    // 5. Summary + first confirmation.
    let header = container::read_header(tmp.path())?;
    eprintln!("Backup file : {} / {}", vault.name, backup.name);
    eprintln!("Restore into: {}", dest.display());
    eprintln!("{}\n", container::format_info(&header));
    if !opts.yes
        && !prompt::confirm(
            "This will REPLACE the current Termius directory with the \
             contents of this backup. A snapshot of the current directory \
             will be taken first. Proceed?",
        )?
    {
        return Err(Error::Canceled("restore canceled".into()));
    }

    // 6. Pre-restore snapshot of the live dir (rollback safety net).
    let mut snap_taken: Option<snapshot::Manifest> = None;
    if dest.is_dir() {
        let now = util::current_time();
        let trigger_sha = util::sha256_file(tmp.path()).unwrap_or_default();
        eprintln!("Snapshotting current Termius directory …");
        let m = snapshot::create(
            &snaps,
            &dest,
            Reason::PreRestore,
            Some((tmp.path(), &trigger_sha)),
            &now,
        )?;
        eprintln!("Created pre-restore snapshot: {}", m.id);
        snap_taken = Some(m);
    } else {
        eprintln!("No existing Termius directory to snapshot; proceeding.");
    }

    // 7. Acquire the backup password and decrypt.
    let password =
        backup::acquire_password(opts.password_file, opts.password_env, false, opts.yes)?;
    eprintln!("Decrypting …");
    let payload = container::read_and_decrypt(tmp.path(), password.as_bytes()).map_err(|e| {
        eprintln!("Decryption failed: {e}");
        if let Some(m) = &snap_taken {
            eprintln!(
                "Your previous data was preserved in snapshot {} — \
                 use `rollback` to restore it.",
                m.id
            );
        }
        e
    })?;

    // 8. Second confirmation: decryption verified, apply now?
    if !opts.yes
        && !prompt::confirm(
            "Decryption succeeded. Restore this backup over the current \
             Termius directory now?",
        )?
    {
        return Err(Error::Canceled("restore canceled before applying".into()));
    }

    // 9. Unpack, verify, swap into place.
    eprintln!("Unpacking …");
    let staging = tempfile::tempdir_in(dest.parent().unwrap_or(Path::new(".")))?;
    let meta = archive::unpack(&payload, staging.path())?;
    eprintln!(
        "Archive metadata: {} entries, {} bytes, created {}",
        meta.entry_count, meta.byte_size, meta.created_at
    );
    if let Err(e) = archive::verify(staging.path(), &meta) {
        return Err(Error::Integrity(format!(
            "decrypted archive failed integrity check before restore: {e}"
        )));
    }
    restore::replace_dir(&dest, staging.path())?;
    eprintln!("Restore complete: {}", dest.display());
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams {
            m_kib: 1024,
            t: 1,
            p: 1,
        }
    }

    fn creds(email: &str) -> Creds {
        Creds {
            email: email.into(),
            client_id: "test-client".into(),
            client_secret: None,
            refresh_token: "rt".into(),
            access_token: "at".into(),
            expires_at: util::current_time().unix_timestamp() + 3600,
        }
    }

    /// Fast-KDF credential envelope helpers (test speed).
    fn save_creds_fast(path: &Path, pw: &[u8], c: &Creds) -> Result<()> {
        let json = serde_json::to_vec_pretty(c)?;
        container::write(path, pw, &fast(), &json)
    }
    fn load_creds_fast(path: &Path, pw: &[u8]) -> Result<Creds> {
        if !path.exists() {
            return Err(Error::NotLoggedIn);
        }
        let json = container::read_and_decrypt(path, pw)?;
        serde_json::from_slice(&json).map_err(|e| Error::BadFormat {
            detail: format!("credential blob: {e}"),
            offset: 0,
        })
    }

    fn tsb_file(payload: &[u8], pw: &str) -> Vec<u8> {
        encrypt_with(&fast(), pw.as_bytes(), payload).unwrap()
    }

    /// Byte-oriented decrypt helper for tests.
    fn read_and_decrypt_bytes(data: &[u8], pw: &[u8]) -> Result<Vec<u8>> {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), data).unwrap();
        container::read_and_decrypt(tmp.path(), pw)
    }

    #[test]
    fn creds_round_trip_and_wrong_master_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("creds.tsb");
        let c = creds("a@b.com");
        save_creds_fast(&path, b"master-pw-123", &c).unwrap();
        let got = load_creds_fast(&path, b"master-pw-123").unwrap();
        assert_eq!(got, c);
        assert!(matches!(
            load_creds_fast(&path, b"wrong-master"),
            Err(Error::PasswordRejected)
        ));
        assert!(matches!(
            load_creds_fast(&tmp.path().join("missing.tsb"), b"x"),
            Err(Error::NotLoggedIn)
        ));
    }

    #[test]
    fn creds_save_creates_missing_parent_dirs() {
        // First `gdrive login` on a fresh machine: the config subdirectory
        // does not exist yet — saving must not fail with
        // "No such file or directory" (the user's original os-error-2 bug).
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("deep/nested/gdrive-creds.tsb");
        assert!(!path.parent().unwrap().exists());
        let c = creds("a@b.com");
        save_creds_fast(&path, b"master-pw-123", &c).unwrap();
        let got = load_creds_fast(&path, b"master-pw-123").unwrap();
        assert_eq!(got, c);
    }

    #[test]
    fn token_expired_flag() {
        let mut c = creds("a@b.com");
        c.expires_at = util::current_time().unix_timestamp() + 3600;
        assert!(!c.token_expired());
        c.expires_at = util::current_time().unix_timestamp() - 10;
        assert!(c.token_expired());
        c.access_token.clear();
        assert!(c.token_expired());
    }

    #[test]
    fn vault_folder_name_derivation() {
        assert_eq!(vault_folder_name("laptop"), "laptop.tsbak-vault");
    }

    #[test]
    fn mock_ensure_vault_is_idempotent() {
        let mut m = MockGdriveClient::new();
        let a = m.ensure_vault("x").unwrap();
        let b = m.ensure_vault("x").unwrap();
        assert_eq!(a, b);
        assert_eq!(m.folders.len(), 1);
    }

    #[test]
    fn mock_list_vaults_filters_unmarked_and_unsuffixed() {
        let mut m = MockGdriveClient::new();
        m.ensure_vault("real").unwrap();
        // A folder with the suffix but no marker.
        m.folders
            .push(("no-marker".into(), "fake.tsbak-vault".into(), false));
        // A folder with a marker but no suffix.
        m.folders.push(("other".into(), "my-docs".into(), true));
        let vaults = m.list_vaults().unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].name, "real.tsbak-vault");
    }

    #[test]
    fn backup_encrypts_and_upload_is_valid_tsb() {
        let mut m = MockGdriveClient::new();
        let fid = m.ensure_vault("laptop").unwrap();
        let tsb = tsb_file(b"payload-bytes", "backup-pw-1");
        m.upload_file(&fid, "2026-01-01-termius.tsb", &tsb).unwrap();
        let uploaded = m.last_upload().unwrap();
        assert!(
            uploaded.starts_with(container::MAGIC),
            "uploaded file is a .tsb"
        );
    }

    #[test]
    fn restore_journey_with_mock() {
        // Build a small termius-like tree, encrypt it, and store it in the mock.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("hosts.json"), b"[{\"name\":\"a\"}]").unwrap();
        let mut payload = Vec::new();
        let _meta = archive::pack(src.path(), &mut payload, "2026-01-01T00:00:00Z").unwrap();
        let tsb = tsb_file(&payload, "backup-pw-9");

        let mut m = MockGdriveClient::new();
        let fid = m.ensure_vault("laptop").unwrap();
        m.upload_file(&fid, "2026-01-01-termius.tsb", &tsb).unwrap();
        m.upload_file(&fid, "2026-01-02-termius.tsb", &tsb).unwrap();

        let vaults = m.list_vaults().unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].backup_count, 2);
        let backups = m.list_backups(&vaults[0].id).unwrap();
        assert_eq!(backups.len(), 2);
        // Newest first.
        assert_eq!(backups[0].name, "2026-01-02-termius.tsb");

        let data = m.download_file(&backups[0].id).unwrap();
        // Wrong password fails cleanly.
        assert!(read_and_decrypt_bytes(&data, b"nope").is_err());
        let pt = read_and_decrypt_bytes(&data, b"backup-pw-9").unwrap();
        assert_eq!(pt, payload);
    }

    // --- authorization-code / loopback flow -------------------------------

    #[test]
    fn pkce_challenge_matches_rfc7636_vector() {
        // RFC 7636 §Appendix-B test vector (cross-checked with openssl).
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn pkce_verifier_is_in_rfc7636_length_range() {
        let v = pkce_verifier();
        assert!((43..=128).contains(&v.len()));
        assert!(v
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')));
    }

    #[test]
    fn parse_callback_extracts_code_and_percent_decodes() {
        let q = "code=4%2FAbCdEfG-HiJk&state=00112233445566778899aabbccddeeff\
                 &scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.file";
        let code = parse_callback(q, "00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(code, "4/AbCdEfG-HiJk");
    }

    #[test]
    fn parse_callback_rejects_state_mismatch() {
        assert!(parse_callback("code=abc&state=other", "expected").is_err());
    }

    #[test]
    fn parse_callback_rejects_missing_code() {
        assert!(parse_callback("state=expected", "expected").is_err());
    }

    #[test]
    fn parse_callback_surfaces_google_error() {
        let e = parse_callback(
            "error=access_denied&error_description=The+user+denied&state=expected",
            "expected",
        )
        .unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("access_denied"), "{msg}");
    }

    #[test]
    fn device_flow_unavailable_detects_invalid_client() {
        let not_found = Error::Gdrive(
            "https://oauth2.googleapis.com/device/code: status code 401 — \
             {\"error\": \"invalid_client\", \"error_description\": \
             \"The OAuth client was not found.\"}"
                .into(),
        );
        let bad_type = Error::Gdrive(
            "https://oauth2.googleapis.com/device/code: status code 401 — \
             {\"error\": \"invalid_client\", \"error_description\": \
             \"Invalid client type.\"}"
                .into(),
        );
        assert!(device_flow_unavailable(&not_found));
        assert!(device_flow_unavailable(&bad_type));
        assert!(!device_flow_unavailable(&Error::Gdrive(
            "network timeout".into()
        )));
        assert!(!device_flow_unavailable(&Error::NotLoggedIn));
    }

    #[test]
    fn push_client_secret_appends_only_when_set() {
        let mut a = String::from("x=1");
        push_client_secret(&mut a, Some("sec ret"));
        assert_eq!(a, "x=1&client_secret=sec%20ret");
        let mut b = String::from("x=1");
        push_client_secret(&mut b, None);
        push_client_secret(&mut b, Some(""));
        assert_eq!(b, "x=1");
    }

    #[test]
    fn client_resolution_baked_in_default_and_env_overrides() {
        std::env::remove_var("TSBAK_GDRIVE_CLIENT_ID");
        std::env::remove_var("TSBAK_GDRIVE_CLIENT_SECRET");

        // No env: the baked-in default client is used, and its secret is
        // supplied automatically (the client is confidential).
        assert_eq!(client_id(), DEFAULT_CLIENT_ID);
        assert_eq!(client_secret().as_deref(), Some(DEFAULT_CLIENT_SECRET));

        // Env client id wins; the baked-in secret is NOT offered for a
        // foreign client.
        std::env::set_var("TSBAK_GDRIVE_CLIENT_ID", "custom-client-id");
        assert_eq!(client_id(), "custom-client-id");
        assert_eq!(client_secret(), None);

        // An explicit env secret always wins.
        std::env::set_var("TSBAK_GDRIVE_CLIENT_SECRET", "custom-secret");
        assert_eq!(client_secret().as_deref(), Some("custom-secret"));

        // Back to the default client: the baked-in secret returns.
        std::env::remove_var("TSBAK_GDRIVE_CLIENT_ID");
        std::env::remove_var("TSBAK_GDRIVE_CLIENT_SECRET");
        assert_eq!(client_id(), DEFAULT_CLIENT_ID);
        assert_eq!(client_secret().as_deref(), Some(DEFAULT_CLIENT_SECRET));
    }

    #[test]
    fn creds_roundtrip_preserves_optional_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.tsb");
        let mut c = creds("a@b.c");
        c.client_secret = Some("GOCSPX-test".into());
        save_creds_fast(&path, b"pw", &c).unwrap();
        assert_eq!(
            load_creds_fast(&path, b"pw")
                .unwrap()
                .client_secret
                .as_deref(),
            Some("GOCSPX-test")
        );
        // No secret: the field deserializes to None (backwards compatible).
        let c2 = creds("a@b.c");
        save_creds_fast(&path, b"pw", &c2).unwrap();
        assert_eq!(load_creds_fast(&path, b"pw").unwrap().client_secret, None);
    }
}
