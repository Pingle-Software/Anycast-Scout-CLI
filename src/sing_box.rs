use crate::sing_box_installer::{
    AUTO_SING_BOX_BIN, SingBoxInstallOptions, SingBoxInstallResult, ensure_sing_box_binary,
};
use anyhow::{Context, Result, anyhow, bail};
use futures::StreamExt;
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;
use tokio::fs;
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep};
use url::Url;

const CONFIG_USER_AGENT_FALLBACK: &str = "SFI/1.13 sing-box/latest";
const SING_BOX_VERSION: &str = "latest";
const URLTEST_TAG: &str = "anycast-scout-urltest";
const URLTEST_URL: &str = "https://cp.cloudflare.com/generate_204";
const DOWNLOAD_URL_BASE: &str = "https://httpbin.org/bytes";
const URLTEST_TIMEOUT: Duration = Duration::from_millis(10_000);

#[derive(Clone, Debug)]
pub struct SingBoxUrlTestConfig {
    pub config_source: String,
    pub candidate_ip: IpAddr,
    pub outbound_tag: String,
    pub min_download_bytes: u64,
    pub sing_box_bin: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SingBoxUrlTestResult {
    pub outbound_tag: String,
    pub urltest_tag: String,
    pub candidate_ip: IpAddr,
    pub test_url: String,
    pub download_url: String,
    pub min_download_bytes: u64,
    pub download_bytes: Option<u64>,
    #[serde(default)]
    pub sing_box_version: Option<String>,
    #[serde(default)]
    pub sing_box_binary: Option<String>,
    #[serde(default)]
    pub sing_box_download: Option<SingBoxInstallResult>,
    pub delay_ms: Option<u64>,
    pub ok: bool,
    pub message: String,
}

pub async fn run_sing_box_urltest(config: SingBoxUrlTestConfig) -> Result<SingBoxUrlTestResult> {
    let resolved_sing_box = resolve_sing_box_binary(&config).await?;
    let sing_box_version = detect_sing_box_version(&resolved_sing_box.path).await;
    let config_user_agent = effective_config_user_agent(
        sing_box_version.as_deref(),
        resolved_sing_box.install.as_ref(),
    );
    let source_config = load_config(&config.config_source, &config_user_agent).await?;
    let temp_dir = TempDir::new().context("failed to create temporary sing-box directory")?;
    let controller = allocate_controller_addr()?;
    let download_proxy = allocate_controller_addr()?;
    let headless_config =
        build_headless_config(&source_config, &config, &controller, &download_proxy)?;
    let config_path = temp_dir.path().join("sing-box-urltest.json");

    fs::write(&config_path, serde_json::to_vec_pretty(&headless_config)?).await?;
    check_sing_box_config(&resolved_sing_box.path, &config_path, temp_dir.path()).await?;

    let mut child = start_sing_box(&resolved_sing_box.path, &config_path, temp_dir.path())?;
    let result = run_delay_test(
        &config,
        &controller,
        &download_proxy,
        sing_box_version,
        resolved_sing_box.path.display().to_string(),
        resolved_sing_box.install,
    )
    .await;
    stop_child(&mut child).await;

    result
}

fn effective_config_user_agent(
    detected_version: Option<&str>,
    install: Option<&SingBoxInstallResult>,
) -> String {
    let version = install
        .map(|install| install.version.clone())
        .or_else(|| detected_version.and_then(parse_sing_box_version_line));
    if let Some(version) = version {
        format!("SFI/{version} sing-box/{version}")
    } else {
        CONFIG_USER_AGENT_FALLBACK.to_string()
    }
}

fn parse_sing_box_version_line(line: &str) -> Option<String> {
    line.strip_prefix("sing-box version ")
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .map(str::to_string)
}

struct ResolvedSingBox {
    path: PathBuf,
    install: Option<SingBoxInstallResult>,
}

async fn resolve_sing_box_binary(config: &SingBoxUrlTestConfig) -> Result<ResolvedSingBox> {
    let bin = config.sing_box_bin.trim();
    if bin.eq_ignore_ascii_case(AUTO_SING_BOX_BIN) {
        let install = ensure_sing_box_binary(SingBoxInstallOptions {
            version: SING_BOX_VERSION.to_string(),
            cache_dir: None,
            force: false,
        })
        .await?;
        let path = PathBuf::from(&install.binary_path);
        return Ok(ResolvedSingBox {
            path,
            install: Some(install),
        });
    }

    Ok(ResolvedSingBox {
        path: PathBuf::from(bin),
        install: None,
    })
}

async fn load_config(source: &str, user_agent: &str) -> Result<Value> {
    let bytes = if let Some(url) = remote_config_url(source)? {
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(user_agent)
            .build()?;
        let response = client
            .get(url)
            .send()
            .await
            .with_context(|| format!("failed to fetch config from {source}"))?;

        if !response.status().is_success() {
            bail!("config endpoint returned HTTP {}", response.status());
        }

        response.bytes().await?.to_vec()
    } else {
        fs::read(source)
            .await
            .with_context(|| format!("failed to read config from {source}"))?
    };

    serde_json::from_slice(&bytes).context("failed to parse sing-box JSON config")
}

fn remote_config_url(source: &str) -> Result<Option<Url>> {
    let looks_remote = source.starts_with("https://") || source.starts_with("http://");
    let Ok(url) = Url::parse(source) else {
        if looks_remote {
            bail!("invalid remote sing-box config URL");
        }
        return Ok(None);
    };

    match url.scheme() {
        "https" => Ok(Some(url)),
        "http" => bail!("remote sing-box config URL must use https"),
        _ => Ok(None),
    }
}

fn build_headless_config(
    source_config: &Value,
    config: &SingBoxUrlTestConfig,
    controller: &SocketAddr,
    download_proxy: &SocketAddr,
) -> Result<Value> {
    let outbounds = source_config
        .get("outbounds")
        .and_then(Value::as_array)
        .context("sing-box config has no outbounds array")?;

    let mut outbound = outbounds
        .iter()
        .find(|outbound| outbound.get("tag").and_then(Value::as_str) == Some(&config.outbound_tag))
        .cloned()
        .with_context(|| format!("outbound tag not found: {}", config.outbound_tag))?;

    let outbound_obj = outbound
        .as_object_mut()
        .context("selected outbound is not a JSON object")?;
    outbound_obj.insert(
        "server".to_string(),
        Value::String(config.candidate_ip.to_string()),
    );
    normalize_headless_outbound(outbound_obj);

    Ok(json!({
        "log": {
            "level": "info",
            "timestamp": false
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "download-proxy",
                "listen": download_proxy.ip().to_string(),
                "listen_port": download_proxy.port()
            }
        ],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct"
            },
            outbound
        ],
        "experimental": {
            "clash_api": {
                "external_controller": controller.to_string()
            },
            "cache_file": {
                "enabled": false
            }
        },
        "route": {
            "final": config.outbound_tag
        }
    }))
}

fn normalize_headless_outbound(outbound: &mut serde_json::Map<String, Value>) {
    // These socket hints are useful in the full client config, but they can
    // make standalone macOS/CI delay probes fail before the proxy handshake.
    outbound.remove("tcp_fast_open");
    outbound.remove("tcp_multi_path");
}

fn allocate_controller_addr() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

async fn check_sing_box_config(bin: &Path, config_path: &Path, work_dir: &Path) -> Result<()> {
    let output = Command::new(bin)
        .arg("check")
        .arg("-c")
        .arg(config_path)
        .arg("-D")
        .arg(work_dir)
        .arg("--disable-color")
        .output()
        .await
        .context("failed to execute sing-box check")?;

    if !output.status.success() {
        bail!(
            "sing-box check failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

async fn detect_sing_box_version(bin: &Path) -> Option<String> {
    let output = Command::new(bin).arg("version").output().await.ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

fn start_sing_box(bin: &Path, config_path: &Path, work_dir: &Path) -> Result<Child> {
    Command::new(bin)
        .arg("run")
        .arg("-c")
        .arg(config_path)
        .arg("-D")
        .arg(work_dir)
        .arg("--disable-color")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start sing-box")
}

async fn run_delay_test(
    config: &SingBoxUrlTestConfig,
    controller: &SocketAddr,
    download_proxy: &SocketAddr,
    sing_box_version: Option<String>,
    sing_box_binary: String,
    sing_box_download: Option<SingBoxInstallResult>,
) -> Result<SingBoxUrlTestResult> {
    let client = Client::builder().timeout(URLTEST_TIMEOUT).build()?;
    wait_for_controller(&client, controller, URLTEST_TIMEOUT).await?;
    let download_url = download_url_for(config.min_download_bytes);

    let mut url = Url::parse(&format!("http://{controller}"))?;
    url.path_segments_mut()
        .map_err(|_| anyhow!("failed to build clash API URL"))?
        .extend(["proxies", &config.outbound_tag, "delay"]);
    url.query_pairs_mut()
        .append_pair("timeout", &URLTEST_TIMEOUT.as_millis().to_string())
        .append_pair("url", URLTEST_URL);

    let response = match client.get(url).send().await {
        Ok(response) => response,
        Err(error) => {
            return Ok(SingBoxUrlTestResult {
                outbound_tag: config.outbound_tag.clone(),
                urltest_tag: URLTEST_TAG.to_string(),
                candidate_ip: config.candidate_ip,
                test_url: URLTEST_URL.to_string(),
                download_url,
                min_download_bytes: config.min_download_bytes,
                download_bytes: None,
                sing_box_version,
                sing_box_binary: Some(sing_box_binary),
                sing_box_download,
                delay_ms: None,
                ok: false,
                message: if error.is_timeout() {
                    "selected outbound delay test timed out".to_string()
                } else {
                    format!("selected outbound delay test failed: {error}")
                },
            });
        }
    };
    let status = response.status();
    let value: Value = response.json().await.unwrap_or_else(|_| json!({}));

    if !status.is_success() {
        return Ok(SingBoxUrlTestResult {
            outbound_tag: config.outbound_tag.clone(),
            urltest_tag: URLTEST_TAG.to_string(),
            candidate_ip: config.candidate_ip,
            test_url: URLTEST_URL.to_string(),
            download_url,
            min_download_bytes: config.min_download_bytes,
            download_bytes: None,
            sing_box_version,
            sing_box_binary: Some(sing_box_binary),
            sing_box_download,
            delay_ms: None,
            ok: false,
            message: value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("selected outbound delay test failed")
                .to_string(),
        });
    }

    let delay_ms = value.get("delay").and_then(Value::as_u64);
    let download = if delay_ms.is_some() {
        run_download_test(config, download_proxy, &download_url).await?
    } else {
        DownloadCheck::skipped()
    };
    let ok = delay_ms.is_some() && download.ok;
    let message = match (delay_ms, download.message) {
        (Some(delay_ms), Some(download_message)) => {
            format!("urltest succeeded in {delay_ms} ms; {download_message}")
        }
        (Some(delay_ms), None) => format!("urltest succeeded in {delay_ms} ms"),
        (None, _) => "selected outbound delay response did not include delay".to_string(),
    };

    Ok(SingBoxUrlTestResult {
        outbound_tag: config.outbound_tag.clone(),
        urltest_tag: URLTEST_TAG.to_string(),
        candidate_ip: config.candidate_ip,
        test_url: URLTEST_URL.to_string(),
        download_url,
        min_download_bytes: config.min_download_bytes,
        download_bytes: download.bytes,
        sing_box_version,
        sing_box_binary: Some(sing_box_binary),
        sing_box_download,
        delay_ms,
        ok,
        message,
    })
}

struct DownloadCheck {
    ok: bool,
    bytes: Option<u64>,
    message: Option<String>,
}

impl DownloadCheck {
    fn skipped() -> Self {
        Self {
            ok: true,
            bytes: None,
            message: None,
        }
    }
}

async fn run_download_test(
    config: &SingBoxUrlTestConfig,
    download_proxy: &SocketAddr,
    download_url: &str,
) -> Result<DownloadCheck> {
    if config.min_download_bytes == 0 {
        return Ok(DownloadCheck::skipped());
    }

    let proxy = Proxy::http(format!("http://{download_proxy}"))
        .context("failed to configure sing-box download proxy")?;
    let client = Client::builder()
        .timeout(URLTEST_TIMEOUT)
        .proxy(proxy)
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()?;

    let response = client
        .get(download_url)
        .send()
        .await
        .with_context(|| format!("download request failed: {download_url}"))?;
    let status = response.status();
    if !status.is_success() {
        return Ok(DownloadCheck {
            ok: false,
            bytes: Some(0),
            message: Some(format!(
                "download failed status={} bytes=0 min={}",
                status.as_u16(),
                config.min_download_bytes
            )),
        });
    }

    let bytes =
        read_min_download_bytes(response, config.min_download_bytes, URLTEST_TIMEOUT).await?;
    let ok = bytes >= config.min_download_bytes;
    Ok(DownloadCheck {
        ok,
        bytes: Some(bytes),
        message: Some(format!(
            "download {} bytes={} min={}",
            if ok { "ok" } else { "failed" },
            bytes,
            config.min_download_bytes
        )),
    })
}

async fn read_min_download_bytes(
    response: reqwest::Response,
    min_bytes: u64,
    timeout: Duration,
) -> Result<u64> {
    let started = Instant::now();
    let mut bytes = 0_u64;
    let mut stream = response.bytes_stream();

    while bytes < min_bytes && started.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(500), stream.next()).await {
            Ok(Some(Ok(chunk))) => bytes = bytes.saturating_add(chunk.len() as u64),
            Ok(Some(Err(error))) => return Err(error.into()),
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    Ok(bytes)
}

fn download_url_for(min_download_bytes: u64) -> String {
    format!("{DOWNLOAD_URL_BASE}/{min_download_bytes}")
}

async fn wait_for_controller(
    client: &Client,
    controller: &SocketAddr,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let url = format!("http://{controller}/proxies");

    loop {
        if Instant::now() >= deadline {
            bail!("timed out waiting for sing-box clash API");
        }

        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
        {
            return Ok(());
        }

        sleep(Duration::from_millis(100)).await;
    }
}

async fn stop_child(child: &mut Child) {
    match child.try_wait() {
        Ok(Some(_)) => {}
        Ok(None) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        Err(_) => {
            let _ = child.kill().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_config_patches_selected_outbound_only() {
        let source = json!({
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {
                    "type": "trojan",
                    "tag": "CDN",
                    "server": "156.255.123.3",
                    "server_port": 443,
                    "password": "",
                    "tcp_fast_open": true,
                    "tcp_multi_path": true,
                    "tls": {"enabled": true, "server_name": "edge.example.com"}
                }
            ]
        });
        let config = SingBoxUrlTestConfig {
            config_source: "config.json".to_string(),
            candidate_ip: "104.16.132.229".parse().unwrap(),
            outbound_tag: "CDN".to_string(),
            min_download_bytes: 20480,
            sing_box_bin: "sing-box".to_string(),
        };

        let headless = build_headless_config(
            &source,
            &config,
            &"127.0.0.1:19090".parse().unwrap(),
            &"127.0.0.1:19091".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(headless["outbounds"][1]["server"], "104.16.132.229");
        assert!(headless["outbounds"][1].get("tcp_fast_open").is_none());
        assert!(headless["outbounds"][1].get("tcp_multi_path").is_none());
        assert_eq!(
            headless["experimental"]["clash_api"]["external_controller"],
            "127.0.0.1:19090"
        );
        assert_eq!(headless["inbounds"][0]["type"], "mixed");
        assert_eq!(headless["inbounds"][0]["listen_port"], 19091);
        assert_eq!(headless["route"]["final"], "CDN");
    }

    #[test]
    fn headless_config_preserves_authorization_from_config() {
        let source = json!({
            "outbounds": [
                {
                    "type": "trojan",
                    "tag": "CDN",
                    "server": "156.255.123.3",
                    "server_port": 443,
                    "password": "",
                    "transport": {
                        "type": "httpupgrade",
                        "headers": {
                            "Authorization": "Bearer from-config"
                        }
                    }
                }
            ]
        });
        let config = SingBoxUrlTestConfig {
            config_source: "config.json".to_string(),
            candidate_ip: "104.16.132.229".parse().unwrap(),
            outbound_tag: "CDN".to_string(),
            min_download_bytes: 20480,
            sing_box_bin: "sing-box".to_string(),
        };

        let headless = build_headless_config(
            &source,
            &config,
            &"127.0.0.1:19090".parse().unwrap(),
            &"127.0.0.1:19091".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(
            headless["outbounds"][1]["transport"]["headers"]["Authorization"],
            "Bearer from-config"
        );
    }

    #[test]
    fn auto_config_user_agent_uses_downloaded_version() {
        let install = SingBoxInstallResult {
            version: "1.13.11".to_string(),
            tag: "v1.13.11".to_string(),
            platform: "darwin-arm64".to_string(),
            asset_name: "sing-box-1.13.11-darwin-arm64.tar.gz".to_string(),
            download_url: "https://example.invalid/sing-box.tar.gz".to_string(),
            sha256: Some("abc".to_string()),
            binary_path: "/tmp/sing-box".to_string(),
            downloaded: false,
        };

        assert_eq!(
            effective_config_user_agent(None, Some(&install)),
            "SFI/1.13.11 sing-box/1.13.11"
        );
    }

    #[test]
    fn auto_config_user_agent_can_use_detected_binary_version() {
        assert_eq!(
            effective_config_user_agent(Some("sing-box version 1.13.11"), None),
            "SFI/1.13.11 sing-box/1.13.11"
        );
    }

    #[test]
    fn remote_config_rejects_plaintext_http() {
        let error = remote_config_url("http://example.com/config.json")
            .unwrap_err()
            .to_string();

        assert!(error.contains("must use https"));
    }

    #[test]
    fn remote_config_accepts_https() {
        assert!(
            remote_config_url("https://example.com/config.json")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn remote_config_rejects_malformed_remote_url() {
        let error = remote_config_url("https://").unwrap_err().to_string();

        assert!(error.contains("invalid remote sing-box config URL"));
    }

    #[test]
    fn download_url_tracks_requested_minimum_bytes() {
        assert_eq!(download_url_for(65_536), "https://httpbin.org/bytes/65536");
    }
}
