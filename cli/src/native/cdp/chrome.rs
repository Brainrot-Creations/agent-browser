use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine;
use sha2::{Digest, Sha256};

use super::discovery::discover_cdp_url;

pub struct ChromeProcess {
    child: Child,
    pub ws_url: String,
    temp_user_data_dir: Option<PathBuf>,
}

impl ChromeProcess {
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Wait for Chrome to exit on its own (after Browser.close CDP command),
    /// falling back to kill() if it doesn't exit within the timeout.
    /// This allows Chrome to flush cookies and other state to the user-data-dir.
    pub fn wait_or_kill(&mut self, timeout: Duration) {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(50);

        while start.elapsed() < timeout {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(poll_interval),
                Err(_) => break,
            }
        }

        self.kill();
    }
}

impl Drop for ChromeProcess {
    fn drop(&mut self) {
        self.kill();
        if let Some(ref dir) = self.temp_user_data_dir {
            for attempt in 0..3 {
                match std::fs::remove_dir_all(dir) {
                    Ok(()) => break,
                    Err(_) if attempt < 2 => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        // Use write! instead of eprintln! to avoid panicking
                        // if the daemon's stderr pipe is broken (parent dropped it).
                        let _ = writeln!(
                            std::io::stderr(),
                            "Warning: failed to clean up temp profile {}: {}",
                            dir.display(),
                            e
                        );
                    }
                }
            }
        }
    }
}

pub struct LaunchOptions {
    pub headless: bool,
    pub executable_path: Option<String>,
    pub proxy: Option<String>,
    pub proxy_bypass: Option<String>,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
    pub profile: Option<String>,
    pub args: Vec<String>,
    pub allow_file_access: bool,
    pub extensions: Option<Vec<String>>,
    pub storage_state: Option<String>,
    pub user_agent: Option<String>,
    pub ignore_https_errors: bool,
    pub ca_cert: Option<String>,
    pub color_scheme: Option<String>,
    pub download_path: Option<String>,
}

impl Default for LaunchOptions {
    fn default() -> Self {
        Self {
            headless: true,
            executable_path: None,
            proxy: None,
            proxy_bypass: None,
            proxy_username: None,
            proxy_password: None,
            profile: None,
            args: Vec::new(),
            allow_file_access: false,
            extensions: None,
            storage_state: None,
            user_agent: None,
            ignore_https_errors: false,
            ca_cert: None,
            color_scheme: None,
            download_path: None,
        }
    }
}

struct ChromeArgs {
    args: Vec<String>,
    user_data_dir: PathBuf,
    temp_user_data_dir: Option<PathBuf>,
}

/// Compute a base64-encoded SHA-256 hash of the SubjectPublicKeyInfo (SPKI)
/// from a PEM or DER certificate file. This is the format Chromium expects
/// for `--ignore-certificate-errors-spki-list`.
fn compute_spki_hash(cert_path: &str) -> Result<String, String> {
    let data = std::fs::read(cert_path)
        .map_err(|e| format!("Failed to read CA certificate '{}': {}", cert_path, e))?;

    // Extract DER-encoded certificate bytes
    let der_bytes = if data.starts_with(b"-----BEGIN") {
        // PEM: extract base64 content between BEGIN/END markers
        let pem_str = std::str::from_utf8(&data)
            .map_err(|e| format!("CA certificate is not valid UTF-8: {}", e))?;
        decode_pem_certificate(pem_str)?
    } else {
        // Assume DER
        data
    };

    // Parse the certificate to extract SubjectPublicKeyInfo
    let spki = extract_spki_from_der(&der_bytes)?;

    // SHA-256 hash of the SPKI, then base64-encode
    let hash = Sha256::digest(spki);
    Ok(base64::engine::general_purpose::STANDARD.encode(hash))
}

/// Decode a PEM certificate to DER bytes.
fn decode_pem_certificate(pem: &str) -> Result<Vec<u8>, String> {
    let mut in_cert = false;
    let mut b64 = String::new();

    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN CERTIFICATE") {
            in_cert = true;
            continue;
        }
        if trimmed.starts_with("-----END CERTIFICATE") {
            break;
        }
        if in_cert {
            b64.push_str(trimmed);
        }
    }

    if b64.is_empty() {
        return Err("No certificate found in PEM file".to_string());
    }

    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("Failed to decode PEM base64: {}", e))
}

/// Extract the SubjectPublicKeyInfo (SPKI) field from a DER-encoded X.509
/// certificate.  Uses minimal ASN.1 parsing — just enough to walk the
/// top-level SEQUENCE → TBSCertificate → skip version/serial/sigAlg/issuer/
/// validity → subject → subjectPublicKeyInfo.
fn extract_spki_from_der(der: &[u8]) -> Result<&[u8], String> {
    // Top-level SEQUENCE (Certificate)
    let (cert_content, _) = read_asn1_sequence(der)?;
    // First element: TBSCertificate SEQUENCE
    let (tbs, _) = read_asn1_sequence(cert_content)?;

    let mut pos = 0;

    // Field 0: version [0] EXPLICIT (optional — present if v2 or v3)
    if pos < tbs.len() && tbs[pos] == 0xA0 {
        let (_, consumed) = read_asn1_element(&tbs[pos..])?;
        pos += consumed;
    }

    // Field 1: serialNumber INTEGER
    let (_, consumed) = read_asn1_element(&tbs[pos..])?;
    pos += consumed;

    // Field 2: signature AlgorithmIdentifier SEQUENCE
    let (_, consumed) = read_asn1_element(&tbs[pos..])?;
    pos += consumed;

    // Field 3: issuer Name SEQUENCE
    let (_, consumed) = read_asn1_element(&tbs[pos..])?;
    pos += consumed;

    // Field 4: validity SEQUENCE
    let (_, consumed) = read_asn1_element(&tbs[pos..])?;
    pos += consumed;

    // Field 5: subject Name SEQUENCE
    let (_, consumed) = read_asn1_element(&tbs[pos..])?;
    pos += consumed;

    // Field 6: subjectPublicKeyInfo SEQUENCE — this is the SPKI
    let (_, consumed) = read_asn1_element(&tbs[pos..])?;
    Ok(&tbs[pos..pos + consumed])
}

/// Read the length from an ASN.1 TLV and return (total_element_bytes, header_size).
fn read_asn1_length(data: &[u8], offset: usize) -> Result<(usize, usize), String> {
    if offset >= data.len() {
        return Err("ASN.1 parse error: unexpected end of data".to_string());
    }
    let first = data[offset] as usize;
    if first < 0x80 {
        Ok((first, 1))
    } else {
        let num_bytes = first & 0x7F;
        if num_bytes == 0 || num_bytes > 4 {
            return Err("ASN.1 parse error: unsupported length encoding".to_string());
        }
        let mut length = 0usize;
        for i in 0..num_bytes {
            if offset + 1 + i >= data.len() {
                return Err("ASN.1 parse error: length bytes truncated".to_string());
            }
            length = (length << 8) | (data[offset + 1 + i] as usize);
        }
        Ok((length, 1 + num_bytes))
    }
}

/// Read a complete ASN.1 element (tag + length + value) and return
/// (content_slice, total_consumed_bytes).
fn read_asn1_element(data: &[u8]) -> Result<(&[u8], usize), String> {
    if data.is_empty() {
        return Err("ASN.1 parse error: empty data".to_string());
    }
    let (length, len_size) = read_asn1_length(data, 1)?;
    let header_size = 1 + len_size;
    let total = header_size + length;
    if total > data.len() {
        return Err("ASN.1 parse error: element extends past end of data".to_string());
    }
    Ok((&data[header_size..total], total))
}

/// Read an ASN.1 SEQUENCE and return (content_slice, total_consumed_bytes).
fn read_asn1_sequence(data: &[u8]) -> Result<(&[u8], usize), String> {
    if data.is_empty() || data[0] != 0x30 {
        return Err("ASN.1 parse error: expected SEQUENCE tag (0x30)".to_string());
    }
    read_asn1_element(data)
}

fn build_chrome_args(options: &LaunchOptions) -> Result<ChromeArgs, String> {
    let mut args = vec![
        "--remote-debugging-port=0".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-backgrounding-occluded-windows".to_string(),
        "--disable-component-update".to_string(),
        "--disable-default-apps".to_string(),
        "--disable-hang-monitor".to_string(),
        "--disable-popup-blocking".to_string(),
        "--disable-prompt-on-repost".to_string(),
        "--disable-sync".to_string(),
        "--disable-features=Translate".to_string(),
        "--enable-features=NetworkService,NetworkServiceInProcess".to_string(),
        "--metrics-recording-only".to_string(),
        "--password-store=basic".to_string(),
        "--use-mock-keychain".to_string(),
    ];

    let has_extensions = options
        .extensions
        .as_ref()
        .is_some_and(|exts| !exts.is_empty());

    // Extensions require headed mode in native Chrome (content scripts are not
    // injected in headless mode).  Skip --headless when extensions are loaded.
    if options.headless && !has_extensions {
        args.push("--headless=new".to_string());
        // Enable SwiftShader software rendering in headless mode.  This
        // prevents silent crashes in environments where GPU drivers are
        // missing or restricted (VMs, containers, some cloud machines)
        // while preserving WebGL support.  Playwright uses the same flag.
        args.push("--enable-unsafe-swiftshader".to_string());
    }

    if let Some(ref proxy) = options.proxy {
        args.push(format!("--proxy-server={}", proxy));
    }

    if let Some(ref bypass) = options.proxy_bypass {
        args.push(format!("--proxy-bypass-list={}", bypass));
    }

    if let Some(ref ca_cert) = options.ca_cert {
        let spki_hash = compute_spki_hash(ca_cert)?;
        args.push(format!(
            "--ignore-certificate-errors-spki-list={}",
            spki_hash
        ));
    }

    let (user_data_dir, temp_user_data_dir) = if let Some(ref profile) = options.profile {
        let expanded = expand_tilde(profile);
        let dir = PathBuf::from(&expanded);
        args.push(format!("--user-data-dir={}", expanded));
        (dir, None)
    } else {
        let dir =
            std::env::temp_dir().join(format!("agent-browser-chrome-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create temp profile dir: {}", e))?;
        args.push(format!("--user-data-dir={}", dir.display()));
        (dir.clone(), Some(dir))
    };

    if options.allow_file_access {
        args.push("--allow-file-access-from-files".to_string());
        args.push("--allow-file-access".to_string());
    }

    if let Some(ref exts) = options.extensions {
        if !exts.is_empty() {
            let ext_list = exts.join(",");
            args.push(format!("--load-extension={}", ext_list));
            args.push(format!("--disable-extensions-except={}", ext_list));
        }
    }

    let has_window_size = options
        .args
        .iter()
        .any(|a| a.starts_with("--start-maximized") || a.starts_with("--window-size="));

    if !has_window_size && options.headless && !has_extensions {
        args.push("--window-size=1280,720".to_string());
    }

    args.extend(options.args.iter().cloned());

    if should_disable_sandbox(&args) {
        args.push("--no-sandbox".to_string());
    }

    if should_disable_dev_shm(&args) {
        args.push("--disable-dev-shm-usage".to_string());
    }

    Ok(ChromeArgs {
        args,
        user_data_dir,
        temp_user_data_dir,
    })
}

pub fn launch_chrome(options: &LaunchOptions) -> Result<ChromeProcess, String> {
    let chrome_path = match &options.executable_path {
        Some(p) => PathBuf::from(p),
        None => {
            find_chrome().ok_or("Chrome not found. Run `agent-browser install` to download Chrome, or use --executable-path.")?
        }
    };

    let max_attempts = 3;
    let mut last_err = String::new();

    for attempt in 1..=max_attempts {
        match try_launch_chrome(&chrome_path, options) {
            Ok(process) => return Ok(process),
            Err(e) => {
                last_err = e;
                if attempt < max_attempts {
                    // Use write! instead of eprintln! to avoid panicking
                    // if the daemon's stderr pipe is broken (parent dropped it).
                    let _ = writeln!(
                        std::io::stderr(),
                        "[chrome] Launch attempt {}/{} failed, retrying in 500ms...",
                        attempt,
                        max_attempts
                    );
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }

    Err(last_err)
}

fn try_launch_chrome(chrome_path: &Path, options: &LaunchOptions) -> Result<ChromeProcess, String> {
    let ChromeArgs {
        args,
        user_data_dir,
        temp_user_data_dir,
    } = build_chrome_args(options)?;

    // Mitigate stale DevToolsActivePort risk (e.g., previous crash left it behind).
    // Puppeteer does similar cleanup before spawning.
    let _ = std::fs::remove_file(user_data_dir.join("DevToolsActivePort"));

    let cleanup_temp_dir = |dir: &Option<PathBuf>| {
        if let Some(ref d) = dir {
            let _ = std::fs::remove_dir_all(d);
        }
    };

    let mut child = Command::new(chrome_path)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            cleanup_temp_dir(&temp_user_data_dir);
            format!("Failed to launch Chrome at {:?}: {}", chrome_path, e)
        })?;

    // Shared overall deadline so we don't double-wait (poll + stderr fallback).
    let deadline = std::time::Instant::now() + Duration::from_secs(30);

    // Primary path: use DevToolsActivePort written into user-data-dir.
    // This is more reliable on Windows than scraping stderr for "DevTools listening on ...",
    // which can be missing/empty depending on how Chrome is launched.
    let ws_url = match wait_for_devtools_active_port(&mut child, &user_data_dir, deadline) {
        Ok(url) => url,
        Err(primary_err) => {
            // Fallback: scrape stderr (legacy behavior) for better diagnostics.
            let stderr = child.stderr.take().ok_or_else(|| {
                let _ = child.kill();
                cleanup_temp_dir(&temp_user_data_dir);
                "Failed to capture Chrome stderr".to_string()
            })?;
            let reader = BufReader::new(stderr);
            match wait_for_ws_url_until(reader, deadline) {
                Ok(url) => url,
                Err(fallback_err) => {
                    let _ = child.kill();
                    cleanup_temp_dir(&temp_user_data_dir);
                    return Err(format!(
                        "{}\n(also tried parsing stderr) {}",
                        primary_err, fallback_err
                    ));
                }
            }
        }
    };

    Ok(ChromeProcess {
        child,
        ws_url,
        temp_user_data_dir,
    })
}

fn wait_for_devtools_active_port(
    child: &mut Child,
    user_data_dir: &Path,
    deadline: std::time::Instant,
) -> Result<String, String> {
    let poll_interval = Duration::from_millis(50);

    while std::time::Instant::now() <= deadline {
        if let Ok(Some(status)) = child.try_wait() {
            // Chrome exited before writing DevToolsActivePort -- report the
            // exit code so the caller can surface it alongside stderr output.
            let code = status
                .code()
                .map(|c| format!("{}", c))
                .unwrap_or_else(|| "unknown".to_string());
            return Err(format!(
                "Chrome exited early (exit code: {}) without writing DevToolsActivePort",
                code
            ));
        }

        if let Some((port, ws_path)) = read_devtools_active_port(user_data_dir) {
            let ws_url = format!("ws://127.0.0.1:{}{}", port, ws_path);
            return Ok(ws_url);
        }

        std::thread::sleep(poll_interval);
    }

    Err("Timeout waiting for DevToolsActivePort".to_string())
}

fn wait_for_ws_url_until(
    reader: BufReader<std::process::ChildStderr>,
    deadline: std::time::Instant,
) -> Result<String, String> {
    let prefix = "DevTools listening on ";
    let mut stderr_lines: Vec<String> = Vec::new();

    for line in reader.lines() {
        if std::time::Instant::now() > deadline {
            return Err(chrome_launch_error(
                "Timeout waiting for Chrome DevTools URL",
                &stderr_lines,
            ));
        }
        let line = line.map_err(|e| format!("Failed to read Chrome stderr: {}", e))?;
        if let Some(url) = line.strip_prefix(prefix) {
            return Ok(url.trim().to_string());
        }
        stderr_lines.push(line);
    }

    Err(chrome_launch_error(
        "Chrome exited before providing DevTools URL",
        &stderr_lines,
    ))
}

fn chrome_launch_error(message: &str, stderr_lines: &[String]) -> String {
    let relevant: Vec<&String> = stderr_lines
        .iter()
        .filter(|l| {
            let lower = l.to_lowercase();
            lower.contains("error")
                || lower.contains("fatal")
                || lower.contains("sandbox")
                || lower.contains("namespace")
                || lower.contains("permission")
                || lower.contains("cannot")
                || lower.contains("failed")
                || lower.contains("abort")
        })
        .collect();

    if relevant.is_empty() {
        if stderr_lines.is_empty() {
            return format!(
                "{} (no stderr output from Chrome)\nHint: try passing --args \"--no-sandbox\" if Chrome crashes silently in your environment",
                message
            );
        }
        let last_lines: Vec<&String> = stderr_lines.iter().rev().take(5).collect();
        return format!(
            "{}\nChrome stderr (last {} lines):\n  {}",
            message,
            last_lines.len(),
            last_lines
                .into_iter()
                .rev()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }

    let hint = if relevant.iter().any(|l| {
        let lower = l.to_lowercase();
        lower.contains("sandbox") || lower.contains("namespace")
    }) {
        "\nHint: try --args \"--no-sandbox\" (required in containers, VMs, and some Linux setups)"
    } else {
        ""
    };

    format!(
        "{}\nChrome stderr:\n  {}{}",
        message,
        relevant
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n  "),
        hint
    )
}

pub fn find_chrome() -> Option<PathBuf> {
    // 1. Check Chrome downloaded by `agent-browser install`
    if let Some(p) = crate::install::find_installed_chrome() {
        return Some(p);
    }

    // 2. Check system-installed Chrome
    #[cfg(target_os = "macos")]
    {
        let candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ];
        for c in &candidates {
            let p = PathBuf::from(c);
            if p.exists() {
                return Some(p);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let candidates = [
            "google-chrome",
            "google-chrome-stable",
            "chromium-browser",
            "chromium",
            "brave-browser",
            "brave-browser-stable",
        ];
        for name in &candidates {
            if let Ok(output) = Command::new("which").arg(name).output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !path.is_empty() {
                        return Some(PathBuf::from(path));
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ];
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let chrome = PathBuf::from(&local).join(r"Google\Chrome\Application\chrome.exe");
            if chrome.exists() {
                return Some(chrome);
            }
            let brave =
                PathBuf::from(&local).join(r"BraveSoftware\Brave-Browser\Application\brave.exe");
            if brave.exists() {
                return Some(brave);
            }
        }
        for c in &candidates {
            let p = PathBuf::from(c);
            if p.exists() {
                return Some(p);
            }
        }
    }

    // 3. Fallback: check Playwright's browser cache (for existing installs)
    if let Some(p) = find_playwright_chromium() {
        return Some(p);
    }

    None
}

pub fn read_devtools_active_port(user_data_dir: &Path) -> Option<(u16, String)> {
    let path = user_data_dir.join("DevToolsActivePort");
    let content = std::fs::read_to_string(&path).ok()?;
    let mut lines = content.lines();
    let port: u16 = lines.next()?.trim().parse().ok()?;
    let ws_path = lines
        .next()
        .unwrap_or("/devtools/browser")
        .trim()
        .to_string();
    Some((port, ws_path))
}

pub async fn auto_connect_cdp() -> Result<String, String> {
    let user_data_dirs = get_chrome_user_data_dirs();

    for dir in &user_data_dirs {
        if let Some((port, ws_path)) = read_devtools_active_port(dir) {
            // Try HTTP endpoint first (pre-M144)
            if let Ok(ws_url) = discover_cdp_url("127.0.0.1", port, None).await {
                return Ok(ws_url);
            }
            // M144+: direct WebSocket — verify the port is actually listening
            // before returning, otherwise a stale DevToolsActivePort file
            // (left behind after Chrome exits/crashes) produces a confusing
            // "connection refused" error instead of falling through.
            if is_port_reachable(port) {
                let ws_url = format!("ws://127.0.0.1:{}{}", port, ws_path);
                return Ok(ws_url);
            }
            // Port is dead — remove the stale file so future runs skip it.
            let stale = dir.join("DevToolsActivePort");
            let _ = std::fs::remove_file(&stale);
        }
    }

    // Fallback: probe common ports
    for port in [9222u16, 9229] {
        if let Ok(ws_url) = discover_cdp_url("127.0.0.1", port, None).await {
            return Ok(ws_url);
        }
    }

    Err("No running Chrome instance found. Launch Chrome with --remote-debugging-port or use --cdp.".to_string())
}

fn is_port_reachable(port: u16) -> bool {
    use std::net::TcpStream;
    let addr = format!("127.0.0.1:{}", port);
    TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(500)).is_ok()
}

fn get_chrome_user_data_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            let base = home.join("Library/Application Support");
            for name in [
                "Google/Chrome",
                "Google/Chrome Canary",
                "Chromium",
                "BraveSoftware/Brave-Browser",
            ] {
                dirs.push(base.join(name));
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = dirs::home_dir() {
            let config = home.join(".config");
            for name in [
                "google-chrome",
                "google-chrome-unstable",
                "chromium",
                "BraveSoftware/Brave-Browser",
            ] {
                dirs.push(config.join(name));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let base = PathBuf::from(local);
            for name in [
                r"Google\Chrome\User Data",
                r"Google\Chrome SxS\User Data",
                r"Chromium\User Data",
                r"BraveSoftware\Brave-Browser\User Data",
            ] {
                dirs.push(base.join(name));
            }
        }
    }

    dirs
}

/// Returns true if Chrome's sandbox should be disabled because the environment
/// doesn't support it (containers, VMs, CI runners, running as root).
fn should_disable_sandbox(existing_args: &[String]) -> bool {
    if existing_args.iter().any(|a| a == "--no-sandbox") {
        return false; // already set by user
    }

    // CI environments (GitHub Actions, GitLab CI, etc.) often lack user namespace
    // support due to AppArmor or kernel restrictions.
    if std::env::var("CI").is_ok() {
        return true;
    }

    #[cfg(unix)]
    {
        // Root user -- standard container default, Chrome sandbox requires non-root
        if unsafe { libc::geteuid() } == 0 {
            return true;
        }

        // Docker container
        if Path::new("/.dockerenv").exists() {
            return true;
        }

        // Podman container
        if Path::new("/run/.containerenv").exists() {
            return true;
        }

        // Generic container detection: cgroup contains docker/kubepods/lxc
        if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
            if cgroup.contains("docker") || cgroup.contains("kubepods") || cgroup.contains("lxc") {
                return true;
            }
        }
    }

    false
}

/// Returns true if Chrome should use disk instead of /dev/shm for shared memory.
/// On CI runners and containers, /dev/shm is often too small (64MB default),
/// which causes Chrome to crash mid-session.
fn should_disable_dev_shm(existing_args: &[String]) -> bool {
    if existing_args.iter().any(|a| a == "--disable-dev-shm-usage") {
        return false;
    }

    if std::env::var("CI").is_ok() {
        return true;
    }

    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            return true;
        }
        if Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists() {
            return true;
        }
        if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
            if cgroup.contains("docker") || cgroup.contains("kubepods") || cgroup.contains("lxc") {
                return true;
            }
        }
    }

    false
}

/// Search Playwright's browser cache for a Chromium binary.
/// Legacy fallback for users who previously installed Chromium via Playwright.
fn find_playwright_chromium() -> Option<PathBuf> {
    let mut search_dirs = Vec::new();

    if let Ok(custom) = std::env::var("PLAYWRIGHT_BROWSERS_PATH") {
        search_dirs.push(PathBuf::from(custom));
    }

    if let Some(home) = dirs::home_dir() {
        search_dirs.push(home.join(".cache/ms-playwright"));
    }

    for dir in &search_dirs {
        if !dir.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            let mut matches: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .map(|n| n.starts_with("chromium-"))
                        .unwrap_or(false)
                })
                .filter_map(|e| {
                    let candidate = build_playwright_binary_path(&e.path());
                    if candidate.exists() {
                        Some(candidate)
                    } else {
                        None
                    }
                })
                .collect();
            // Sort descending so the newest version wins
            matches.sort();
            matches.reverse();
            if let Some(p) = matches.into_iter().next() {
                return Some(p);
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn build_playwright_binary_path(chromium_dir: &Path) -> PathBuf {
    chromium_dir.join("chrome-linux64/chrome")
}

#[cfg(target_os = "macos")]
fn build_playwright_binary_path(chromium_dir: &Path) -> PathBuf {
    chromium_dir.join("chrome-mac/Chromium.app/Contents/MacOS/Chromium")
}

#[cfg(target_os = "windows")]
fn build_playwright_binary_path(chromium_dir: &Path) -> PathBuf {
    chromium_dir.join("chrome-win/chrome.exe")
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('~') {
        if let Some(home) = dirs::home_dir() {
            return home
                .join(rest.strip_prefix('/').unwrap_or(rest))
                .to_string_lossy()
                .to_string();
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::EnvGuard;

    #[cfg(unix)]
    fn spawn_noop_child() -> Child {
        Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[cfg(windows)]
    fn spawn_noop_child() -> Child {
        Command::new("cmd.exe")
            .args(["/C", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[test]
    fn test_find_chrome_returns_some_on_host() {
        // This test only makes sense on systems with Chrome installed
        if cfg!(target_os = "macos") || cfg!(target_os = "linux") {
            let result = find_chrome();
            // Don't assert Some -- CI may not have Chrome
            if let Some(path) = result {
                assert!(path.exists());
            }
        }
    }

    #[test]
    fn test_expand_tilde() {
        let expanded = expand_tilde("~/test/path");
        assert!(!expanded.starts_with('~'));
        assert!(expanded.ends_with("test/path"));
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        assert_eq!(expand_tilde("/absolute/path"), "/absolute/path");
    }

    #[test]
    fn test_read_devtools_active_port_missing() {
        let result = read_devtools_active_port(Path::new("/nonexistent"));
        assert!(result.is_none());
    }

    #[test]
    fn test_should_disable_sandbox_skips_if_already_set() {
        let args = vec!["--headless=new".to_string(), "--no-sandbox".to_string()];
        assert!(!should_disable_sandbox(&args));
    }

    #[test]
    fn test_chrome_launch_error_no_stderr() {
        let msg = chrome_launch_error("Chrome exited", &[]);
        assert!(msg.contains("no stderr output"));
        assert!(msg.contains("Hint:"));
        assert!(msg.contains("--no-sandbox"));
    }

    #[test]
    fn test_chrome_launch_error_with_sandbox_hint() {
        let lines = vec![
            "some log line".to_string(),
            "Failed to move to new namespace: sandbox error".to_string(),
        ];
        let msg = chrome_launch_error("Chrome exited", &lines);
        assert!(msg.contains("sandbox error"));
        assert!(msg.contains("Hint:"));
        assert!(msg.contains("--no-sandbox"));
    }

    #[test]
    fn test_chrome_launch_error_generic() {
        let lines = vec!["info line".to_string(), "another info line".to_string()];
        let msg = chrome_launch_error("Chrome exited", &lines);
        assert!(msg.contains("last 2 lines"));
    }

    #[test]
    fn test_find_playwright_chromium_nonexistent() {
        let _guard = EnvGuard::new(&["PLAYWRIGHT_BROWSERS_PATH"]);
        _guard.set("PLAYWRIGHT_BROWSERS_PATH", "/nonexistent/path");
        let result = find_playwright_chromium();
        assert!(result.is_none());
    }

    #[test]
    fn test_build_args_headless_includes_headless_flag() {
        let opts = LaunchOptions {
            headless: true,
            ..Default::default()
        };
        let result = build_chrome_args(&opts).unwrap();
        assert!(result.args.iter().any(|a| a == "--headless=new"));
        assert!(result
            .args
            .iter()
            .any(|a| a == "--enable-unsafe-swiftshader"));
        assert!(result.args.iter().any(|a| a == "--window-size=1280,720"));
        // Temp dir created when no profile
        assert!(result.temp_user_data_dir.is_some());
        let dir = result.temp_user_data_dir.unwrap();
        assert!(dir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_args_headed_no_headless_flag() {
        let opts = LaunchOptions {
            headless: false,
            ..Default::default()
        };
        let result = build_chrome_args(&opts).unwrap();
        assert!(!result.args.iter().any(|a| a.contains("--headless")));
        assert!(!result
            .args
            .iter()
            .any(|a| a == "--enable-unsafe-swiftshader"));
        assert!(!result.args.iter().any(|a| a.starts_with("--window-size=")));
        // Temp dir created when no profile
        assert!(result.temp_user_data_dir.is_some());
        let dir = result.temp_user_data_dir.unwrap();
        assert!(dir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_args_temp_user_data_dir_created() {
        let opts = LaunchOptions::default();
        let result = build_chrome_args(&opts).unwrap();
        let dir = result.temp_user_data_dir.as_ref().unwrap();
        assert!(dir.exists());
        assert!(result
            .args
            .iter()
            .any(|a| a.starts_with("--user-data-dir=")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_build_args_profile_no_temp_dir() {
        let opts = LaunchOptions {
            profile: Some("/tmp/my-profile".to_string()),
            ..Default::default()
        };
        let result = build_chrome_args(&opts).unwrap();
        assert!(result.temp_user_data_dir.is_none());
        assert!(result
            .args
            .iter()
            .any(|a| a == "--user-data-dir=/tmp/my-profile"));
    }

    #[test]
    fn test_build_args_custom_window_size_not_overridden() {
        let opts = LaunchOptions {
            headless: true,
            args: vec!["--window-size=1920,1080".to_string()],
            ..Default::default()
        };
        let result = build_chrome_args(&opts).unwrap();
        assert!(!result.args.iter().any(|a| a == "--window-size=1280,720"));
        assert!(result.args.iter().any(|a| a == "--window-size=1920,1080"));
        if let Some(ref dir) = result.temp_user_data_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn test_build_args_start_maximized_suppresses_default_window_size() {
        let opts = LaunchOptions {
            headless: true,
            args: vec!["--start-maximized".to_string()],
            ..Default::default()
        };
        let result = build_chrome_args(&opts).unwrap();
        assert!(!result.args.iter().any(|a| a == "--window-size=1280,720"));
        assert!(result.args.iter().any(|a| a == "--start-maximized"));
        if let Some(ref dir) = result.temp_user_data_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn test_build_args_disables_translate() {
        let opts = LaunchOptions::default();
        let result = build_chrome_args(&opts).unwrap();
        assert!(result
            .args
            .iter()
            .any(|a| a.contains("--disable-features") && a.contains("Translate")));
        if let Some(ref dir) = result.temp_user_data_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn test_build_args_headless_with_extensions_skips_headless_flag() {
        let opts = LaunchOptions {
            headless: true,
            extensions: Some(vec!["/tmp/my-ext".to_string()]),
            ..Default::default()
        };
        let result = build_chrome_args(&opts).unwrap();
        assert!(
            !result.args.iter().any(|a| a.contains("--headless")),
            "headless flag should be omitted when extensions are present"
        );
        assert!(
            !result.args.iter().any(|a| a.contains("--window-size")),
            "window-size should be omitted when extensions force headed mode"
        );
        assert!(result
            .args
            .iter()
            .any(|a| a.starts_with("--load-extension=")));
        if let Some(ref dir) = result.temp_user_data_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn test_build_args_headed_with_extensions_no_headless_flag() {
        let opts = LaunchOptions {
            headless: false,
            extensions: Some(vec!["/tmp/my-ext".to_string()]),
            ..Default::default()
        };
        let result = build_chrome_args(&opts).unwrap();
        assert!(
            !result.args.iter().any(|a| a.contains("--headless")),
            "headless flag should not be present in headed mode"
        );
        assert!(result
            .args
            .iter()
            .any(|a| a.starts_with("--load-extension=")));
        if let Some(ref dir) = result.temp_user_data_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn test_chrome_process_drop_cleans_temp_dir() {
        let dir = std::env::temp_dir().join(format!(
            "agent-browser-chrome-drop-test-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::create_dir_all(&dir);
        assert!(dir.exists());

        {
            // Simulate a ChromeProcess with a temp dir but a dummy child.
            // We can't actually spawn Chrome here, but we can verify the Drop
            // logic by creating a small helper process.
            let child = spawn_noop_child();
            let _process = ChromeProcess {
                child,
                ws_url: String::new(),
                temp_user_data_dir: Some(dir.clone()),
            };
            // _process dropped here
        }

        assert!(!dir.exists(), "Temp dir should be cleaned up on drop");
    }

    // Self-signed RSA-2048 test certificate (CN=test-ca).
    // Generated with: openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=test-ca"
    const TEST_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDBTCCAe2gAwIBAgIUFhZ9tlfduuEvOIOcGuOA7E0SSL4wDQYJKoZIhvcNAQEL\n\
BQAwEjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNjAzMjUxNDE5MDVaFw0yNzAzMjUx\n\
NDE5MDVaMBIxEDAOBgNVBAMMB3Rlc3QtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n\
DwAwggEKAoIBAQDcgmzozr7Ia72OCsxk2uKUFhM6wR0H69cv4qO5OViu+0qFoYr6\n\
Bny2o+Q/ooqCCYveamPukYlZMFilnk9b4M2VwxK72pOVTkvyWUWpIJrV6OQKqsaf\n\
DNgDdl4U4i2U/HKKNXTNtaVPzc3d40rcwy8dHVzFaTs8o7UG73foHQ2/7KQ6sY5d\n\
gjOchbLDlhN2Nkyc4WxXEipesonUogLzZxx9gSMZN6VmXaIyijncAFxO9vSenTQd\n\
FstTlTI/FCPQU2cg5K3rtToPli3j7z9oeeMrrt3pp1xmU5/cliz5kQ3CXxbH1UR3\n\
uFAaW09wTsK+fSo8rBgGWO5JU706M1aL5wvXAgMBAAGjUzBRMB0GA1UdDgQWBBR3\n\
yFGDemoQUIFA/YW1BJYhT6hlhzAfBgNVHSMEGDAWgBR3yFGDemoQUIFA/YW1BJYh\n\
T6hlhzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCq5bl2J+JO\n\
LpOZG4n4xbQUi456bV40a9lxFwXyR4toiOnLc9QTiFLtrRRMjiAYBlpnp7Aq7rPK\n\
0dxGhFsNhTHYv5bKF3Wt6EKnfmjC5J2PQ4j4fZbqnBJVNhtP3/QdTg/Alx2DgVlP\n\
vUaYBYvyM8aeAGCvlTr9XbciLgDHrO6xE0mppF87jG3DbVIqhGAa8z7KR286Hmw3\n\
JtnWOCSAT+dNsAXmz4ebm7kp9OnpLLKjvrNEUNPA20J5S+BXTtPv7x/koRwSX35M\n\
9yOorGsG0RB4CaEy4fpiKTewGNMdHNoZNevXB1s7jm3YdW5BDxvG4Su5RGqAjS+Y\n\
49s7jC+okfzl\n\
-----END CERTIFICATE-----\n";

    // Expected SPKI hash for TEST_PEM, computed with:
    // openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
    const TEST_PEM_SPKI_HASH: &str = "bGmEVcmCy5Btl3rFpi8tv60akkmtflu5gzLmS9JlnD0=";

    #[test]
    fn test_compute_spki_hash_pem() {
        let dir = std::env::temp_dir().join(format!("spki-test-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("test-ca.crt");
        std::fs::write(&cert_path, TEST_PEM).unwrap();

        let hash = compute_spki_hash(cert_path.to_str().unwrap()).unwrap();
        assert_eq!(
            hash, TEST_PEM_SPKI_HASH,
            "SPKI hash should match openssl-computed value"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_spki_hash_nonexistent_file() {
        let result = compute_spki_hash("/nonexistent/path/to/cert.pem");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read"));
    }

    #[test]
    fn test_compute_spki_hash_invalid_pem() {
        let dir = std::env::temp_dir().join(format!("spki-test-invalid-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("invalid.crt");
        std::fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\nnot-valid-base64!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let result = compute_spki_hash(cert_path.to_str().unwrap());
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compute_spki_hash_empty_pem() {
        let dir = std::env::temp_dir().join(format!("spki-test-empty-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("empty.crt");
        std::fs::write(
            &cert_path,
            "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();

        let result = compute_spki_hash(cert_path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No certificate found"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_args_ca_cert_adds_spki_list() {
        let dir = std::env::temp_dir().join(format!("spki-args-test-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("test-ca.crt");
        std::fs::write(&cert_path, TEST_PEM).unwrap();

        let opts = LaunchOptions {
            ca_cert: Some(cert_path.to_str().unwrap().to_string()),
            ..Default::default()
        };
        let result = build_chrome_args(&opts).unwrap();
        assert!(
            result
                .args
                .iter()
                .any(|a| a.starts_with("--ignore-certificate-errors-spki-list=")),
            "Should add --ignore-certificate-errors-spki-list when ca_cert is set"
        );

        if let Some(ref d) = result.temp_user_data_dir {
            let _ = std::fs::remove_dir_all(d);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_decode_pem_certificate_extracts_first_cert() {
        // Multi-cert PEM should extract only the first certificate
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n\
-----BEGIN CERTIFICATE-----\nZGVm\n-----END CERTIFICATE-----\n";
        let decoded = decode_pem_certificate(pem).unwrap();
        assert_eq!(decoded, b"abc"); // "YWJj" decodes to "abc"
    }

    #[test]
    fn test_asn1_length_short_form() {
        let data = [0x05]; // length = 5
        let (len, size) = read_asn1_length(&data, 0).unwrap();
        assert_eq!(len, 5);
        assert_eq!(size, 1);
    }

    #[test]
    fn test_asn1_length_long_form() {
        let data = [0x82, 0x01, 0x00]; // 2 bytes of length = 256
        let (len, size) = read_asn1_length(&data, 0).unwrap();
        assert_eq!(len, 256);
        assert_eq!(size, 3);
    }

    /// EC P-256 certificate — different SPKI structure from RSA.
    /// Verified against: openssl x509 -pubkey -noout | openssl pkey -pubin -outform der |
    ///                   openssl dgst -sha256 -binary | base64
    #[test]
    fn test_compute_spki_hash_ec_cert() {
        let ec_pem = "-----BEGIN CERTIFICATE-----\n\
MIIBeTCCAR+gAwIBAgIUC77fmNcp/aMfqP4lKAzS5d6jIkswCgYIKoZIzj0EAwIw\n\
EjEQMA4GA1UEAwwHZWMtdGVzdDAeFw0yNjAzMjUxNDQwMDhaFw0yNzAzMjUxNDQw\n\
MDhaMBIxEDAOBgNVBAMMB2VjLXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n\
AAQBnhhpB1hXMU9ApP03C+h8cCNXmFnt1ceEXG2HF435Wr/Ky+OQZzpjMT/F5p6b\n\
d9NZybE1SEwHjFDGSih77kR3o1MwUTAdBgNVHQ4EFgQUHhS1zOh00+tnCdSonx+B\n\
9J9k3GowHwYDVR0jBBgwFoAUHhS1zOh00+tnCdSonx+B9J9k3GowDwYDVR0TAQH/\n\
BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAj1qMNlpw9ydvcHHmyDTEl1a57fH2\n\
VXKy7lhMb3nDiq8CIBmql5q02Sl8+aztTKjtEtOfCtcqGghI+rLkQG7jI51x\n\
-----END CERTIFICATE-----\n";

        let dir = std::env::temp_dir().join(format!("spki-ec-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("ec-ca.crt");
        std::fs::write(&cert_path, ec_pem).unwrap();

        let hash = compute_spki_hash(cert_path.to_str().unwrap()).unwrap();
        assert_eq!(hash, "j4u7vkJhMUO1e0mrG0BsLqT56MELt1SAYDhN0iHyvD4=");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// DER-encoded certificate (binary, not PEM).
    #[test]
    fn test_compute_spki_hash_der_cert() {
        // Convert TEST_PEM to DER and verify we get the same hash
        let der = decode_pem_certificate(TEST_PEM).unwrap();
        let dir = std::env::temp_dir().join(format!("spki-der-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("test-ca.der");
        std::fs::write(&cert_path, &der).unwrap();

        let hash = compute_spki_hash(cert_path.to_str().unwrap()).unwrap();
        assert_eq!(
            hash, TEST_PEM_SPKI_HASH,
            "DER cert should produce same hash as PEM"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
