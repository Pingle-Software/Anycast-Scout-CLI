use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use futures::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tar::Archive;
use tokio::fs;
use tokio::io::AsyncWriteExt;

pub const AUTO_SING_BOX_BIN: &str = "auto";

const GITHUB_API_BASE: &str = "https://api.github.com/repos/SagerNet/sing-box";

#[derive(Clone, Debug)]
pub struct SingBoxInstallOptions {
    pub version: String,
    pub cache_dir: Option<PathBuf>,
    pub force: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SingBoxInstallResult {
    pub version: String,
    pub tag: String,
    pub platform: String,
    pub asset_name: String,
    pub download_url: String,
    pub sha256: Option<String>,
    pub binary_path: String,
    pub downloaded: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    digest: Option<String>,
}

pub async fn ensure_sing_box_binary(
    options: SingBoxInstallOptions,
) -> Result<SingBoxInstallResult> {
    let client = github_client()?;
    let release = fetch_release(&client, &options.version).await?;
    if release.prerelease {
        bail!(
            "sing-box release {} is a prerelease; use latest stable or a stable tag",
            release.tag_name
        );
    }

    let version = release_version(&release.tag_name);
    let platform = current_platform()?;
    let asset_name = asset_name(&version, &platform);
    let asset = release
        .assets
        .into_iter()
        .find(|asset| asset.name == asset_name)
        .with_context(|| {
            format!(
                "sing-box release {} has no asset {}",
                release.tag_name, asset_name
            )
        })?;

    let cache_root = options.cache_dir.unwrap_or_else(default_cache_dir);
    let install_dir = cache_root.join("sing-box").join(&version).join(&platform);
    let binary_path = install_dir.join(binary_name());
    if binary_path.exists() && !options.force {
        return Ok(SingBoxInstallResult {
            version,
            tag: release.tag_name,
            platform,
            asset_name: asset.name,
            download_url: asset.browser_download_url,
            sha256: expected_sha256(&asset.digest),
            binary_path: binary_path.display().to_string(),
            downloaded: false,
        });
    }

    fs::create_dir_all(&install_dir)
        .await
        .with_context(|| format!("failed to create {}", install_dir.display()))?;
    let archive_path = install_dir.join(format!(".{}.download", asset.name));
    let downloaded_sha256 =
        download_asset(&client, &asset.browser_download_url, &archive_path).await?;
    let expected_sha256 = expected_sha256(&asset.digest);
    if let Some(expected) = &expected_sha256
        && downloaded_sha256 != *expected
    {
        bail!(
            "sing-box asset checksum mismatch for {}: expected {}, got {}",
            asset.name,
            expected,
            downloaded_sha256
        );
    }

    extract_sing_box_binary(&archive_path, &binary_path).await?;
    let _ = fs::remove_file(&archive_path).await;

    Ok(SingBoxInstallResult {
        version,
        tag: release.tag_name,
        platform,
        asset_name: asset.name,
        download_url: asset.browser_download_url,
        sha256: expected_sha256.or(Some(downloaded_sha256)),
        binary_path: binary_path.display().to_string(),
        downloaded: true,
    })
}

fn github_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("anycast-scout/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build GitHub client")
}

async fn fetch_release(client: &Client, version: &str) -> Result<GithubRelease> {
    let version = version.trim();
    let url = if version.is_empty() || version.eq_ignore_ascii_case("latest") {
        format!("{GITHUB_API_BASE}/releases/latest")
    } else {
        format!("{GITHUB_API_BASE}/releases/tags/{}", normalize_tag(version))
    };

    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to query {url}"))?;
    if !response.status().is_success() {
        bail!("GitHub release query returned HTTP {}", response.status());
    }
    response
        .json::<GithubRelease>()
        .await
        .context("failed to parse GitHub release response")
}

async fn download_asset(client: &Client, url: &str, path: &Path) -> Result<String> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to download {url}"))?;
    if !response.status().is_success() {
        bail!(
            "sing-box asset download returned HTTP {}",
            response.status()
        );
    }

    let mut stream = response.bytes_stream();
    let mut file = fs::File::create(path)
        .await
        .with_context(|| format!("failed to create {}", path.display()))?;
    let mut hasher = Sha256::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("failed to read sing-box asset stream")?;
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    file.flush()
        .await
        .with_context(|| format!("failed to flush {}", path.display()))?;

    Ok(hex_lower(&hasher.finalize()))
}

async fn extract_sing_box_binary(archive_path: &Path, binary_path: &Path) -> Result<()> {
    let archive_path = archive_path.to_path_buf();
    let binary_path = binary_path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let tmp_path = binary_path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp_path);

        let file = File::open(&archive_path)
            .with_context(|| format!("failed to open {}", archive_path.display()))?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);
        for entry in archive
            .entries()
            .context("failed to read sing-box archive")?
        {
            let mut entry = entry.context("failed to read sing-box archive entry")?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry
                .path()
                .context("failed to read sing-box archive entry path")?;
            if path.file_name().and_then(|name| name.to_str()) != Some(binary_name()) {
                continue;
            }

            let mut out = File::create(&tmp_path)
                .with_context(|| format!("failed to create {}", tmp_path.display()))?;
            io::copy(&mut entry, &mut out)
                .with_context(|| format!("failed to extract {}", binary_path.display()))?;
            set_executable(&tmp_path)?;
            std::fs::rename(&tmp_path, &binary_path).with_context(|| {
                format!(
                    "failed to install {} to {}",
                    tmp_path.display(),
                    binary_path.display()
                )
            })?;
            return Ok(());
        }

        bail!(
            "sing-box archive {} did not contain {}",
            archive_path.display(),
            binary_name()
        )
    })
    .await
    .context("failed to join sing-box extraction task")?
}

fn default_cache_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("ANYCAST_SCOUT_SING_BOX_CACHE") {
        return PathBuf::from(path);
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Caches")
                .join("anycast-scout");
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local).join("anycast-scout");
        }
    }

    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(xdg).join("anycast-scout");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".cache").join("anycast-scout");
    }
    std::env::temp_dir().join("anycast-scout")
}

fn current_platform() -> Result<String> {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        other => bail!("automatic sing-box download is not supported on {other} yet"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => bail!("automatic sing-box download is not supported on {other} yet"),
    };
    Ok(format!("{os}-{arch}"))
}

fn asset_name(version: &str, platform: &str) -> String {
    format!("sing-box-{version}-{platform}.tar.gz")
}

fn binary_name() -> &'static str {
    "sing-box"
}

fn normalize_tag(version: &str) -> String {
    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}

fn release_version(tag: &str) -> String {
    tag.trim_start_matches('v').to_string()
}

fn expected_sha256(digest: &Option<String>) -> Option<String> {
    digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .map(str::to_string)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to chmod {}", path.display()))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_release_tags() {
        assert_eq!(normalize_tag("1.13.11"), "v1.13.11");
        assert_eq!(normalize_tag("v1.13.11"), "v1.13.11");
        assert_eq!(release_version("v1.13.11"), "1.13.11");
    }

    #[test]
    fn builds_expected_asset_name() {
        assert_eq!(
            asset_name("1.13.11", "darwin-arm64"),
            "sing-box-1.13.11-darwin-arm64.tar.gz"
        );
    }

    #[test]
    fn extracts_expected_sha256() {
        assert_eq!(
            expected_sha256(&Some("sha256:abc123".to_string())),
            Some("abc123".to_string())
        );
        assert_eq!(expected_sha256(&Some("abc123".to_string())), None);
    }
}
