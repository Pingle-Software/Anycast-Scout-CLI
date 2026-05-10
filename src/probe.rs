use crate::input::Target;
use crate::rate_limit::RateLimiter;
use futures::{StreamExt, stream};
use reqwest::header::{HeaderMap, SERVER};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Semaphore;
use url::Url;

const CF_RAY_HEADER: &str = "cf-ray";
const MAX_VALIDATION_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct ProbeConfig {
    pub resources: Vec<ValidationResource>,
    pub edge_validation: Option<EdgeValidationConfig>,
    pub timeout: Duration,
    pub speed_url: Option<String>,
    pub speed_duration: Duration,
    pub download_url: Option<String>,
    pub min_download_bytes: u64,
    pub download_timeout: Duration,
    pub user_agent: String,
}

#[derive(Clone, Debug)]
pub struct ValidationResource {
    pub name: String,
    pub url: Url,
    pub expected_status: Vec<u16>,
    pub expected_body: Option<String>,
    pub require_cloudflare_marker: bool,
}

#[derive(Clone, Debug)]
pub struct EdgeValidationConfig {
    pub url: Url,
    pub direct_ip_error_codes: Vec<u16>,
    pub accept_error_codes: Vec<u16>,
    pub reject_error_codes: Vec<u16>,
}

impl ValidationResource {
    pub fn new(
        name: impl Into<String>,
        url: impl AsRef<str>,
        expected_status: Vec<u16>,
        expected_body: Option<String>,
        require_cloudflare_marker: bool,
    ) -> Result<Self, url::ParseError> {
        Ok(Self {
            name: name.into(),
            url: Url::parse(url.as_ref())?,
            expected_status,
            expected_body,
            require_cloudflare_marker,
        })
    }
}

pub fn cloudflare_validation_resources() -> Vec<ValidationResource> {
    vec![
        ValidationResource::new(
            "cloudflare-trace",
            "https://cloudflare.com/cdn-cgi/trace",
            vec![200],
            Some("colo=".to_string()),
            true,
        )
        .expect("built-in URL is valid"),
        ValidationResource::new(
            "cloudflare-dns-trace",
            "https://cloudflare-dns.com/cdn-cgi/trace",
            vec![200],
            Some("colo=".to_string()),
            true,
        )
        .expect("built-in URL is valid"),
        ValidationResource::new(
            "www-cloudflare-marker",
            "https://www.cloudflare.com/cdn-cgi/trace",
            vec![403],
            None,
            true,
        )
        .expect("built-in URL is valid"),
        ValidationResource::new(
            "cp-generate-204",
            "https://cp.cloudflare.com/generate_204",
            vec![204],
            None,
            true,
        )
        .expect("built-in URL is valid"),
        ValidationResource::new(
            "cp-root-204",
            "https://cp.cloudflare.com/",
            vec![204],
            None,
            true,
        )
        .expect("built-in URL is valid"),
        ValidationResource::new(
            "speed-marker",
            "https://speed.cloudflare.com/__down?bytes=1000",
            vec![403],
            None,
            true,
        )
        .expect("built-in URL is valid"),
    ]
}

pub fn edge_validation_config(
    hostname: &str,
    path: &str,
    direct_ip_error_codes: Vec<u16>,
    accept_error_codes: Vec<u16>,
    reject_error_codes: Vec<u16>,
) -> Result<EdgeValidationConfig, url::ParseError> {
    let trimmed_path = path.trim();
    let normalized_path = if trimmed_path.is_empty() {
        "/"
    } else if trimmed_path.starts_with('/') {
        trimmed_path
    } else {
        return Err(url::ParseError::RelativeUrlWithoutBase);
    };

    Ok(EdgeValidationConfig {
        url: Url::parse(&format!("https://{hostname}{normalized_path}"))?,
        direct_ip_error_codes,
        accept_error_codes,
        reject_error_codes,
    })
}

#[derive(Clone)]
pub struct Scanner {
    config: Arc<ProbeConfig>,
    concurrency: usize,
    limiter: Arc<RateLimiter>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub valid: bool,
    pub status: Option<u16>,
    pub latency_ms: Option<f64>,
    pub speed_mbps: Option<f64>,
    pub download_bytes: Option<u64>,
    pub colo: Option<String>,
    pub server: Option<String>,
    pub reason: String,
    pub resource: Option<String>,
    pub source: String,
    pub asn: Option<u32>,
    #[serde(rename = "org", alias = "name")]
    pub name: Option<String>,
    pub prefix: Option<String>,
}

#[derive(Debug, Error)]
enum ProbeError {
    #[error("invalid speed URL: {0}")]
    InvalidSpeedUrl(String),
    #[error("invalid download URL: {0}")]
    InvalidDownloadUrl(String),
    #[error("speed URL must include a host")]
    MissingSpeedHost,
    #[error("download URL must include a host")]
    MissingDownloadHost,
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
}

struct ObservedResponse {
    status: u16,
    latency_ms: f64,
    headers: HeaderMap,
    body: String,
}

impl Scanner {
    pub fn new(
        config: ProbeConfig,
        concurrency: usize,
        request_interval: Duration,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            config: Arc::new(config),
            concurrency: concurrency.max(1),
            limiter: Arc::new(RateLimiter::new(request_interval)),
        })
    }

    pub fn scan_stream(
        &self,
        targets: Vec<Target>,
    ) -> impl futures::Stream<Item = ScanResult> + '_ {
        let semaphore = Arc::new(Semaphore::new(self.concurrency));

        stream::iter(targets)
            .map(move |target| {
                let scanner = self.clone();
                let semaphore = Arc::clone(&semaphore);

                async move {
                    let _permit = semaphore.acquire_owned().await.expect("semaphore closed");
                    scanner.probe(target).await
                }
            })
            .buffer_unordered(self.concurrency)
    }

    async fn probe(&self, target: Target) -> ScanResult {
        match self.try_probe(&target).await {
            Ok(result) => result,
            Err(error) => ScanResult {
                ip: target.ip,
                port: target.port,
                valid: false,
                status: None,
                latency_ms: None,
                speed_mbps: None,
                download_bytes: None,
                colo: None,
                server: None,
                reason: error.to_string(),
                resource: None,
                source: target.source,
                asn: target.asn,
                name: target.name,
                prefix: target.prefix,
            },
        }
    }

    async fn try_probe(&self, target: &Target) -> Result<ScanResult, ProbeError> {
        if let Some(edge_validation) = &self.config.edge_validation {
            return self.try_probe_edge(target, edge_validation).await;
        }
        self.try_probe_resources(target).await
    }

    async fn try_probe_edge(
        &self,
        target: &Target,
        edge_validation: &EdgeValidationConfig,
    ) -> Result<ScanResult, ProbeError> {
        let direct_client = validation_client_builder(&self.config).build()?;
        let direct_url = Url::parse(&format!("http://{}/", target.ip))
            .expect("candidate IP always produces a valid direct HTTP URL");
        let direct_response = self
            .observed_response(&direct_client, direct_url.clone())
            .await?;
        let direct_classification = classify_edge_direct_response(
            edge_validation,
            direct_response.status,
            &direct_response.headers,
            &direct_response.body,
        );
        let direct_reason = direct_classification.message;
        if !direct_classification.valid {
            return Ok(ScanResult {
                ip: target.ip,
                port: target.port,
                valid: false,
                status: Some(direct_response.status),
                latency_ms: Some(direct_response.latency_ms),
                speed_mbps: None,
                download_bytes: None,
                colo: extract_colo(&direct_response.headers),
                server: header_to_string(&direct_response.headers, SERVER.as_str()),
                reason: direct_reason,
                resource: Some("edge-direct-ip".to_string()),
                source: target.source.clone(),
                asn: target.asn,
                name: target.name.clone(),
                prefix: target.prefix.clone(),
            });
        }

        let edge_client = self.validation_client_for_url(target, &edge_validation.url)?;
        let edge_response = self
            .observed_response(&edge_client, edge_validation.url.clone())
            .await?;
        let edge_classification = classify_edge_host_response(
            edge_validation,
            edge_response.status,
            &edge_response.headers,
            &edge_response.body,
        );
        let mut result = ScanResult {
            ip: target.ip,
            port: target.port,
            valid: edge_classification.valid,
            status: Some(edge_response.status),
            latency_ms: Some(edge_response.latency_ms),
            speed_mbps: None,
            download_bytes: None,
            colo: extract_colo(&edge_response.headers),
            server: header_to_string(&edge_response.headers, SERVER.as_str()),
            reason: combine_messages(direct_reason, Some(edge_classification.message)),
            resource: Some("edge-host".to_string()),
            source: target.source.clone(),
            asn: target.asn,
            name: target.name.clone(),
            prefix: target.prefix.clone(),
        };

        if !result.valid {
            return Ok(result);
        }

        let download = self.validate_download(target).await?;
        result.valid = download.valid;
        result.download_bytes = download.bytes;
        result.reason = combine_messages(result.reason, download.message);
        if result.valid {
            result.speed_mbps = self.measure_speed(target).await?;
        }
        Ok(result)
    }

    async fn try_probe_resources(&self, target: &Target) -> Result<ScanResult, ProbeError> {
        let mut last_result = None;
        let resources = &self.config.resources;
        let start_index = resource_start_index(target, resources.len());
        let client = self.validation_client_for_resources(target, resources)?;

        for offset in 0..resources.len() {
            let resource = &resources[(start_index + offset) % resources.len()];
            self.limiter.wait().await;

            let started = Instant::now();
            let response = client.get(resource.url.clone()).send().await?;
            let latency = started.elapsed();
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = read_limited_text(response, MAX_VALIDATION_BODY_BYTES).await?;
            let classification = classify_resource_response(resource, status, &headers, &body);

            let result = ScanResult {
                ip: target.ip,
                port: target.port,
                valid: classification.valid,
                status: Some(status),
                latency_ms: Some(latency.as_secs_f64() * 1000.0),
                speed_mbps: None,
                download_bytes: None,
                colo: extract_colo(&headers),
                server: header_to_string(&headers, SERVER.as_str()),
                reason: classification.message,
                resource: Some(resource.name.clone()),
                source: target.source.clone(),
                asn: target.asn,
                name: target.name.clone(),
                prefix: target.prefix.clone(),
            };

            if result.valid {
                let mut result = result;
                let download = self.validate_download(target).await?;
                result.valid = download.valid;
                result.download_bytes = download.bytes;
                result.reason = combine_messages(result.reason, download.message);
                if result.valid {
                    result.speed_mbps = self.measure_speed(target).await?;
                }
                return Ok(result);
            }

            last_result = Some(result);
        }

        Ok(last_result.unwrap_or_else(|| ScanResult {
            ip: target.ip,
            port: target.port,
            valid: false,
            status: None,
            latency_ms: None,
            speed_mbps: None,
            download_bytes: None,
            colo: None,
            server: None,
            reason: "no validation resources configured".to_string(),
            resource: None,
            source: target.source.clone(),
            asn: target.asn,
            name: target.name.clone(),
            prefix: target.prefix.clone(),
        }))
    }

    fn validation_client_for_resources(
        &self,
        target: &Target,
        resources: &[ValidationResource],
    ) -> Result<Client, ProbeError> {
        let mut builder = validation_client_builder(&self.config);

        for resource in resources {
            let Some(host) = resource.url.host_str() else {
                continue;
            };
            let port = url_override_port(&resource.url, target);
            builder = builder.resolve(host, SocketAddr::new(target.ip, port));
        }

        Ok(builder.build()?)
    }

    fn validation_client_for_url(&self, target: &Target, url: &Url) -> Result<Client, ProbeError> {
        let mut builder = validation_client_builder(&self.config);
        if let Some(host) = url.host_str() {
            builder = builder.resolve(
                host,
                SocketAddr::new(target.ip, url_override_port(url, target)),
            );
        }
        Ok(builder.build()?)
    }

    async fn observed_response(
        &self,
        client: &Client,
        url: Url,
    ) -> Result<ObservedResponse, ProbeError> {
        self.limiter.wait().await;
        let started = Instant::now();
        let response = client.get(url).send().await?;
        let latency = started.elapsed();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = read_limited_text(response, MAX_VALIDATION_BODY_BYTES).await?;
        Ok(ObservedResponse {
            status,
            latency_ms: latency.as_secs_f64() * 1000.0,
            headers,
            body,
        })
    }

    async fn measure_speed(&self, target: &Target) -> Result<Option<f64>, ProbeError> {
        if self.config.speed_duration.is_zero() {
            return Ok(None);
        }

        let Some(speed_url) = &self.config.speed_url else {
            return Ok(None);
        };

        let url =
            Url::parse(speed_url).map_err(|_| ProbeError::InvalidSpeedUrl(speed_url.clone()))?;
        let host = url.host_str().ok_or(ProbeError::MissingSpeedHost)?;
        let port = url_override_port(&url, target);

        let client = Client::builder()
            .timeout(self.config.speed_duration + Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::limited(3))
            .resolve(host, SocketAddr::new(target.ip, port))
            .user_agent(self.config.user_agent.clone())
            .build()?;

        self.limiter.wait().await;
        let response = client.get(url).send().await?;

        if !response.status().is_success() {
            return Ok(Some(0.0));
        }

        read_speed(response, self.config.speed_duration).await
    }

    async fn validate_download(&self, target: &Target) -> Result<DownloadValidation, ProbeError> {
        if self.config.min_download_bytes == 0 {
            return Ok(DownloadValidation::skipped());
        }

        let Some(download_url) = &self.config.download_url else {
            return Ok(DownloadValidation {
                valid: false,
                bytes: Some(0),
                message: Some(format!(
                    "download miss bytes=0 min={} url=missing",
                    self.config.min_download_bytes
                )),
            });
        };

        let url = Url::parse(download_url)
            .map_err(|_| ProbeError::InvalidDownloadUrl(download_url.clone()))?;
        let host = url.host_str().ok_or(ProbeError::MissingDownloadHost)?;
        let port = url_override_port(&url, target);

        let client = Client::builder()
            .timeout(self.config.download_timeout)
            .redirect(reqwest::redirect::Policy::limited(3))
            .resolve(host, SocketAddr::new(target.ip, port))
            .user_agent(self.config.user_agent.clone())
            .build()?;

        self.limiter.wait().await;
        let response = client.get(url).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Ok(DownloadValidation {
                valid: false,
                bytes: Some(0),
                message: Some(format!(
                    "download miss status={} bytes=0 min={}",
                    status.as_u16(),
                    self.config.min_download_bytes
                )),
            });
        }

        let bytes = read_min_bytes(
            response,
            self.config.min_download_bytes,
            self.config.download_timeout,
        )
        .await?;
        let valid = bytes >= self.config.min_download_bytes;

        Ok(DownloadValidation {
            valid,
            bytes: Some(bytes),
            message: Some(format!(
                "download {} bytes={} min={}",
                if valid { "ok" } else { "miss" },
                bytes,
                self.config.min_download_bytes
            )),
        })
    }
}

fn validation_client_builder(config: &ProbeConfig) -> reqwest::ClientBuilder {
    Client::builder()
        .timeout(config.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(config.user_agent.clone())
}

struct Classification {
    valid: bool,
    message: String,
}

struct DownloadValidation {
    valid: bool,
    bytes: Option<u64>,
    message: Option<String>,
}

impl DownloadValidation {
    fn skipped() -> Self {
        Self {
            valid: true,
            bytes: None,
            message: None,
        }
    }
}

fn classify_resource_response(
    resource: &ValidationResource,
    status: u16,
    headers: &HeaderMap,
    body: &str,
) -> Classification {
    let status_ok =
        resource.expected_status.is_empty() || resource.expected_status.contains(&status);
    let body_ok = resource
        .expected_body
        .as_ref()
        .is_none_or(|expected| body.contains(expected));
    let marker_ok = !resource.require_cloudflare_marker || has_cloudflare_marker(headers);
    let valid = status_ok && body_ok && marker_ok;

    Classification {
        valid,
        message: format!(
            "{} status={} body={} cloudflare={}",
            resource.name,
            if status_ok { "ok" } else { "miss" },
            if body_ok { "ok" } else { "miss" },
            if marker_ok { "ok" } else { "miss" },
        ),
    }
}

fn classify_edge_direct_response(
    config: &EdgeValidationConfig,
    status: u16,
    headers: &HeaderMap,
    body: &str,
) -> Classification {
    let error_code = extract_cloudflare_error_code(body);
    let marker_ok = has_cloudflare_marker(headers);
    let error_ok = error_code.is_some_and(|code| config.direct_ip_error_codes.contains(&code));
    let valid = marker_ok && error_ok;

    Classification {
        valid,
        message: format!(
            "edge-direct status={} error={} cloudflare={}",
            status,
            format_error_code(error_code),
            if marker_ok { "ok" } else { "miss" },
        ),
    }
}

fn classify_edge_host_response(
    config: &EdgeValidationConfig,
    status: u16,
    headers: &HeaderMap,
    body: &str,
) -> Classification {
    let error_code = extract_cloudflare_error_code(body);
    let marker_ok = has_cloudflare_marker(headers);
    let rejected = error_code.is_some_and(|code| config.reject_error_codes.contains(&code));
    let accepted_error = error_code.is_some_and(|code| config.accept_error_codes.contains(&code));
    let status_ok = status < 500;
    let valid = marker_ok && !rejected && (status_ok || accepted_error);

    Classification {
        valid,
        message: format!(
            "edge-host status={} error={} cloudflare={} accepted={} rejected={}",
            status,
            format_error_code(error_code),
            if marker_ok { "ok" } else { "miss" },
            if status_ok || accepted_error {
                "ok"
            } else {
                "miss"
            },
            if rejected { "yes" } else { "no" },
        ),
    }
}

async fn read_speed(response: Response, duration: Duration) -> Result<Option<f64>, ProbeError> {
    let started = Instant::now();
    let mut bytes = 0_u64;
    let mut stream = response.bytes_stream();

    while started.elapsed() < duration {
        match tokio::time::timeout(Duration::from_millis(500), stream.next()).await {
            Ok(Some(Ok(chunk))) => bytes += chunk.len() as u64,
            Ok(Some(Err(error))) => return Err(ProbeError::Request(error)),
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    let elapsed = started.elapsed().as_secs_f64();
    if elapsed == 0.0 {
        return Ok(Some(0.0));
    }

    Ok(Some(bytes as f64 * 8.0 / elapsed / 1_000_000.0))
}

async fn read_limited_text(response: Response, max_bytes: usize) -> Result<String, ProbeError> {
    if max_bytes == 0 {
        return Ok(String::new());
    }

    let capacity = response
        .content_length()
        .unwrap_or(max_bytes as u64)
        .min(max_bytes as u64) as usize;
    let mut body = Vec::with_capacity(capacity);
    let mut stream = response.bytes_stream();

    while body.len() < max_bytes {
        let Some(chunk) = stream.next().await else {
            break;
        };
        let chunk = chunk?;
        let remaining = max_bytes - body.len();
        let take = remaining.min(chunk.len());
        body.extend_from_slice(&chunk[..take]);

        if take < chunk.len() {
            break;
        }
    }

    Ok(String::from_utf8_lossy(&body).into_owned())
}

async fn read_min_bytes(
    response: Response,
    min_bytes: u64,
    timeout: Duration,
) -> Result<u64, ProbeError> {
    let started = Instant::now();
    let mut bytes = 0_u64;
    let mut stream = response.bytes_stream();

    while bytes < min_bytes && started.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(500), stream.next()).await {
            Ok(Some(Ok(chunk))) => bytes = bytes.saturating_add(chunk.len() as u64),
            Ok(Some(Err(error))) => return Err(ProbeError::Request(error)),
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    Ok(bytes)
}

fn combine_messages(base: String, extra: Option<String>) -> String {
    match extra {
        Some(extra) => format!("{base}; {extra}"),
        None => base,
    }
}

fn extract_cloudflare_error_code(body: &str) -> Option<u16> {
    let marker = "error code:";
    let index = body.to_ascii_lowercase().find(marker)?;
    let suffix = &body[index + marker.len()..];
    let digits: String = suffix
        .trim_start()
        .chars()
        .take_while(|char| char.is_ascii_digit())
        .take(4)
        .collect();
    if digits.len() == 4 {
        digits.parse().ok()
    } else {
        None
    }
}

fn format_error_code(error_code: Option<u16>) -> String {
    error_code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn has_cloudflare_marker(headers: &HeaderMap) -> bool {
    let server_is_cloudflare = header_to_string(headers, SERVER.as_str())
        .is_some_and(|server| server.eq_ignore_ascii_case("cloudflare"));

    server_is_cloudflare || headers.contains_key(CF_RAY_HEADER)
}

fn extract_colo(headers: &HeaderMap) -> Option<String> {
    let cf_ray = header_to_string(headers, CF_RAY_HEADER)?;
    let suffix = cf_ray.rsplit_once('-')?.1;
    let colo: String = suffix
        .chars()
        .take_while(|char| char.is_ascii_alphabetic())
        .take(3)
        .collect();

    if colo.len() == 3 {
        Some(colo.to_ascii_uppercase())
    } else {
        None
    }
}

fn header_to_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn resource_start_index(target: &Target, resource_count: usize) -> usize {
    if resource_count == 0 {
        return 0;
    }

    let mut hasher = DefaultHasher::new();
    target.ip.hash(&mut hasher);
    target.port.hash(&mut hasher);
    (hasher.finish() as usize) % resource_count
}

fn url_override_port(url: &Url, target: &Target) -> u16 {
    url.port().unwrap_or(target.port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    use std::io::{Read, Write};

    fn edge_config() -> EdgeValidationConfig {
        edge_validation_config(
            "edge.example.com",
            "/api/v1/events",
            vec![1003],
            Vec::new(),
            vec![1034],
        )
        .unwrap()
    }

    #[test]
    fn resource_requires_status_body_and_cloudflare_marker() {
        let resource = ValidationResource::new(
            "trace",
            "https://www.cloudflare.com/cdn-cgi/trace",
            vec![200],
            Some("colo=".to_string()),
            true,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(SERVER, HeaderValue::from_static("cloudflare"));

        let classification = classify_resource_response(&resource, 200, &headers, "colo=FRA\n");

        assert!(classification.valid);
    }

    #[test]
    fn extracts_cloudflare_error_code_from_plain_text_body() {
        assert_eq!(
            extract_cloudflare_error_code("error code: 1003"),
            Some(1003)
        );
        assert_eq!(extract_cloudflare_error_code("plain body"), None);
    }

    #[test]
    fn edge_direct_validation_requires_1003_with_cloudflare_marker() {
        let mut headers = HeaderMap::new();
        headers.insert(SERVER, HeaderValue::from_static("cloudflare"));
        headers.insert(
            HeaderName::from_static(CF_RAY_HEADER),
            HeaderValue::from_static("8f123abcde-FRA"),
        );

        let classification =
            classify_edge_direct_response(&edge_config(), 403, &headers, "error code: 1003");

        assert!(classification.valid);
    }

    #[test]
    fn edge_host_validation_rejects_1034() {
        let mut headers = HeaderMap::new();
        headers.insert(SERVER, HeaderValue::from_static("cloudflare"));
        headers.insert(
            HeaderName::from_static(CF_RAY_HEADER),
            HeaderValue::from_static("8f123abcde-FRA"),
        );

        let classification =
            classify_edge_host_response(&edge_config(), 403, &headers, "error code: 1034");

        assert!(!classification.valid);
    }

    #[test]
    fn edge_host_validation_accepts_non_5xx_without_error_code() {
        let mut headers = HeaderMap::new();
        headers.insert(SERVER, HeaderValue::from_static("cloudflare"));
        headers.insert(
            HeaderName::from_static(CF_RAY_HEADER),
            HeaderValue::from_static("8f123abcde-HEL"),
        );

        let classification = classify_edge_host_response(&edge_config(), 401, &headers, "");

        assert!(classification.valid);
    }

    #[test]
    fn extracts_cloudflare_colo_from_cf_ray() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(CF_RAY_HEADER),
            HeaderValue::from_static("8f123abcde-SJC"),
        );

        assert_eq!(extract_colo(&headers), Some("SJC".to_string()));
    }

    #[test]
    fn resource_start_index_is_stable_for_same_target() {
        let target = Target {
            ip: "104.16.132.229".parse().unwrap(),
            port: 443,
            source: "test".to_string(),
            asn: None,
            name: None,
            prefix: None,
        };

        assert_eq!(
            resource_start_index(&target, 6),
            resource_start_index(&target, 6)
        );
        assert!(resource_start_index(&target, 6) < 6);
        assert_eq!(resource_start_index(&target, 0), 0);
    }

    #[test]
    fn url_override_port_uses_target_port_unless_url_is_explicit() {
        let target = Target {
            ip: "104.16.132.229".parse().unwrap(),
            port: 8443,
            source: "test".to_string(),
            asn: None,
            name: None,
            prefix: None,
        };

        assert_eq!(
            url_override_port(
                &Url::parse("https://example.com/cdn-cgi/trace").unwrap(),
                &target
            ),
            8443
        );
        assert_eq!(
            url_override_port(
                &Url::parse("https://example.com:9443/cdn-cgi/trace").unwrap(),
                &target,
            ),
            9443
        );
    }

    #[tokio::test]
    async fn validation_body_reader_caps_response_body() {
        crate::install_crypto_provider();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            let body = "a".repeat(MAX_VALIDATION_BODY_BYTES + 1024);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        });

        let response = Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        let body = read_limited_text(response, MAX_VALIDATION_BODY_BYTES)
            .await
            .unwrap();

        assert_eq!(body.len(), MAX_VALIDATION_BODY_BYTES);
        handle.join().unwrap();
    }
}
