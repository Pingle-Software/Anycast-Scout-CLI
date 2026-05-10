use crate::cli::{DiscoveryProviderArg, DiscoveryScopeArg};
use crate::input::{ReadOptions, TargetInput};
use crate::rate_limit::RateLimiter;
use anyhow::{Context, Result, anyhow, bail};
use futures::{Stream, StreamExt};
use ipnet::IpNet;
use reqwest::header::RETRY_AFTER;
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tokio::io::AsyncWriteExt;
use url::Url;

const BGP_TOOLS_TABLE_URL: &str = "https://bgp.tools/table.jsonl";

#[derive(Clone, Debug)]
pub struct DiscoveryOptions {
    pub asns: Vec<u32>,
    pub providers: Vec<DiscoveryProviderArg>,
    pub scope: DiscoveryScopeArg,
    pub merge_providers: bool,
    pub user_agent: String,
    pub request_interval: Duration,
    pub ripestat_min_peers_seeing: u32,
    pub bgp_tools_min_hits: u32,
    pub cache_dir: Option<PathBuf>,
    pub bgp_tools_cache_ttl: Duration,
    pub refresh_cache: bool,
    pub read_options: ReadOptions,
}

#[derive(Debug, Serialize)]
pub struct DiscoveryProviderSummary {
    pub provider: String,
    pub asn: u32,
    pub relation: String,
    pub prefixes: usize,
    pub ipv4_hosts: u64,
}

#[derive(Debug)]
pub struct DiscoveryInputResult {
    pub inputs: Vec<TargetInput>,
    pub summaries: Vec<DiscoveryProviderSummary>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
struct PrefixRecord {
    provider: DiscoveryProviderArg,
    asn: u32,
    relation: PrefixRelation,
    prefix: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
enum PrefixRelation {
    Origin,
    AsPathTransit,
}

impl PrefixRelation {
    fn label(self) -> &'static str {
        match self {
            Self::Origin => "origin",
            Self::AsPathTransit => "as-path",
        }
    }
}

#[derive(Debug, Deserialize)]
struct BgpToolsTableRow {
    #[serde(rename = "CIDR")]
    cidr: String,
    #[serde(rename = "ASN")]
    asn: u32,
    #[serde(rename = "Hits")]
    hits: Option<u32>,
}

pub fn parse_asn(value: &str) -> Result<u32> {
    let value = value.trim();
    let number = value
        .strip_prefix("AS")
        .or_else(|| value.strip_prefix("as"))
        .unwrap_or(value);

    number
        .parse::<u32>()
        .with_context(|| format!("invalid ASN: {value}"))
}

pub fn parse_asns(values: &[String]) -> Result<Vec<u32>> {
    let mut seen = HashSet::new();
    let mut asns = Vec::new();

    for value in values {
        for part in value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            let asn = parse_asn(part)?;
            if seen.insert(asn) {
                asns.push(asn);
            }
        }
    }

    if asns.is_empty() {
        bail!("at least one --asn is required for discovery");
    }

    Ok(asns)
}

pub async fn discover_target_inputs(options: DiscoveryOptions) -> Result<DiscoveryInputResult> {
    if options.asns.is_empty() {
        bail!("at least one ASN is required for discovery");
    }

    let providers = if options.providers.is_empty() {
        vec![
            DiscoveryProviderArg::Ripestat,
            DiscoveryProviderArg::BgpTools,
        ]
    } else {
        options.providers.clone()
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(45))
        .user_agent(options.user_agent.clone())
        .build()?;
    let limiter = RateLimiter::new(options.request_interval);
    let mut remaining: HashSet<u32> = options.asns.iter().copied().collect();
    let mut records = Vec::new();
    let mut summaries = Vec::new();
    let mut warnings = Vec::new();
    let mut attempted_providers = 0_usize;
    let mut failed_providers = 0_usize;

    for provider in providers {
        let provider_asns: Vec<u32> = if options.merge_providers {
            options.asns.clone()
        } else {
            remaining.iter().copied().collect()
        };

        if provider_asns.is_empty() {
            break;
        }

        attempted_providers += 1;
        match discover_with_provider(provider, &provider_asns, &options, &client, &limiter).await {
            Ok(provider_records) => {
                let mut counts: BTreeMap<(u32, PrefixRelation), (usize, u64)> = BTreeMap::new();
                for record in &provider_records {
                    let entry = counts.entry((record.asn, record.relation)).or_default();
                    entry.0 += 1;
                    entry.1 = entry.1.saturating_add(ipv4_host_capacity(&record.prefix));
                }

                for ((asn, relation), (count, ipv4_hosts)) in counts {
                    summaries.push(DiscoveryProviderSummary {
                        provider: provider_name(provider).to_string(),
                        asn,
                        relation: relation.label().to_string(),
                        prefixes: count,
                        ipv4_hosts,
                    });
                    if !options.merge_providers && count > 0 {
                        remaining.remove(&asn);
                    }
                }

                records.extend(provider_records);
            }
            Err(error) => {
                failed_providers += 1;
                warnings.push(format!("{}: {error}", provider_name(provider)));
            }
        }
    }

    fail_if_all_discovery_providers_failed(
        records.len(),
        attempted_providers,
        failed_providers,
        &warnings,
    )?;
    let inputs = records_to_target_inputs(records);

    Ok(DiscoveryInputResult {
        inputs,
        summaries,
        warnings,
    })
}

fn fail_if_all_discovery_providers_failed(
    record_count: usize,
    attempted_providers: usize,
    failed_providers: usize,
    warnings: &[String],
) -> Result<()> {
    if record_count == 0 && attempted_providers > 0 && failed_providers == attempted_providers {
        bail!("all discovery providers failed: {}", warnings.join("; "));
    }

    Ok(())
}

async fn discover_with_provider(
    provider: DiscoveryProviderArg,
    asns: &[u32],
    options: &DiscoveryOptions,
    client: &Client,
    limiter: &RateLimiter,
) -> Result<Vec<PrefixRecord>> {
    match provider {
        DiscoveryProviderArg::Ripestat => discover_ripestat(asns, options, client, limiter).await,
        DiscoveryProviderArg::BgpTools => discover_bgp_tools(asns, options, client, limiter).await,
    }
}

async fn discover_ripestat(
    asns: &[u32],
    options: &DiscoveryOptions,
    client: &Client,
    limiter: &RateLimiter,
) -> Result<Vec<PrefixRecord>> {
    if options.scope != DiscoveryScopeArg::Origin {
        return discover_ripestat_ris_prefixes(asns, options, client, limiter).await;
    }

    let mut records = Vec::new();

    for asn in asns {
        limiter.wait().await;
        let url = Url::parse_with_params(
            "https://stat.ripe.net/data/announced-prefixes/data.json",
            &[
                ("resource", format!("AS{asn}")),
                (
                    "min_peers_seeing",
                    options.ripestat_min_peers_seeing.to_string(),
                ),
            ],
        )?;
        let response = client.get(url).send().await?;

        if response.status().as_u16() == 429 {
            return Err(rate_limit_error("RIPEstat", &response));
        }
        if !response.status().is_success() {
            bail!("RIPEstat returned HTTP {}", response.status());
        }

        let value = response.json::<Value>().await?;
        records.extend(parse_ripestat_prefixes(*asn, &value)?);
    }

    Ok(records)
}

async fn discover_ripestat_ris_prefixes(
    asns: &[u32],
    options: &DiscoveryOptions,
    client: &Client,
    limiter: &RateLimiter,
) -> Result<Vec<PrefixRecord>> {
    let mut records = Vec::new();

    for asn in asns {
        limiter.wait().await;
        let url = Url::parse_with_params(
            "https://stat.ripe.net/data/ris-prefixes/data.json",
            &[
                ("resource", format!("AS{asn}")),
                ("list_prefixes", "true".to_string()),
            ],
        )?;
        let response = client.get(url).send().await?;

        if response.status().as_u16() == 429 {
            return Err(rate_limit_error("RIPEstat", &response));
        }
        if !response.status().is_success() {
            bail!("RIPEstat RIS prefixes returned HTTP {}", response.status());
        }

        let value = response.json::<Value>().await?;
        records.extend(parse_ripestat_ris_prefixes(*asn, options.scope, &value)?);
    }

    Ok(records)
}

fn parse_ripestat_prefixes(asn: u32, value: &Value) -> Result<Vec<PrefixRecord>> {
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if status != "ok" {
        bail!("RIPEstat response status is {status}");
    }

    let prefixes = value
        .pointer("/data/prefixes")
        .and_then(Value::as_array)
        .context("RIPEstat response has no data.prefixes array")?;

    Ok(prefixes
        .iter()
        .filter_map(|entry| entry.get("prefix").and_then(Value::as_str))
        .map(|prefix| PrefixRecord {
            provider: DiscoveryProviderArg::Ripestat,
            asn,
            relation: PrefixRelation::Origin,
            prefix: prefix.to_string(),
        })
        .collect())
}

fn parse_ripestat_ris_prefixes(
    asn: u32,
    scope: DiscoveryScopeArg,
    value: &Value,
) -> Result<Vec<PrefixRecord>> {
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if status != "ok" {
        bail!("RIPEstat RIS prefixes response status is {status}");
    }

    let prefixes = value
        .pointer("/data/prefixes")
        .and_then(Value::as_object)
        .context("RIPEstat response has no data.prefixes object")?;
    let mut records = Vec::new();
    let mut seen = HashSet::new();

    match scope {
        DiscoveryScopeArg::Origin => {
            collect_ris_prefix_records(
                prefixes,
                asn,
                PrefixRelation::Origin,
                "originating",
                &mut seen,
                &mut records,
            );
        }
        DiscoveryScopeArg::AsPath => {
            collect_ris_prefix_records(
                prefixes,
                asn,
                PrefixRelation::AsPathTransit,
                "transiting",
                &mut seen,
                &mut records,
            );
        }
        DiscoveryScopeArg::OriginAndAsPath => {
            collect_ris_prefix_records(
                prefixes,
                asn,
                PrefixRelation::AsPathTransit,
                "transiting",
                &mut seen,
                &mut records,
            );
            collect_ris_prefix_records(
                prefixes,
                asn,
                PrefixRelation::Origin,
                "originating",
                &mut seen,
                &mut records,
            );
        }
    }

    Ok(records)
}

fn collect_ris_prefix_records(
    prefixes: &serde_json::Map<String, Value>,
    asn: u32,
    relation: PrefixRelation,
    key: &str,
    seen: &mut HashSet<(PrefixRelation, String)>,
    records: &mut Vec<PrefixRecord>,
) {
    for family in ["v4", "v6"] {
        let Some(values) = prefixes
            .get(family)
            .and_then(|value| value.get(key))
            .and_then(Value::as_array)
        else {
            continue;
        };

        for prefix in values.iter().filter_map(Value::as_str) {
            if seen.insert((relation, prefix.to_string())) {
                records.push(PrefixRecord {
                    provider: DiscoveryProviderArg::Ripestat,
                    asn,
                    relation,
                    prefix: prefix.to_string(),
                });
            }
        }
    }
}

async fn discover_bgp_tools(
    asns: &[u32],
    options: &DiscoveryOptions,
    client: &Client,
    limiter: &RateLimiter,
) -> Result<Vec<PrefixRecord>> {
    if !scope_includes_origin(options.scope) {
        bail!(
            "bgp.tools table export only supports origin ASN discovery; use RIPEstat for AS_PATH scope"
        );
    }

    let cache_dir = options
        .cache_dir
        .clone()
        .unwrap_or_else(default_cache_dir)
        .join("discovery");
    let table_path = cache_dir.join("bgp-tools-table.jsonl");

    if options.refresh_cache || !cache_is_fresh(&table_path, options.bgp_tools_cache_ttl) {
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("failed to create {}", cache_dir.display()))?;
        limiter.wait().await;
        let response = client.get(BGP_TOOLS_TABLE_URL).send().await?;

        if response.status().as_u16() == 429 {
            return Err(rate_limit_error("bgp.tools", &response));
        }
        if !response.status().is_success() {
            bail!("bgp.tools table export returned HTTP {}", response.status());
        }

        write_bgp_tools_response_atomic(response, &table_path).await?;
    }

    parse_bgp_tools_table_blocking(table_path, asns.to_vec(), options.bgp_tools_min_hits).await
}

async fn parse_bgp_tools_table_blocking(
    path: PathBuf,
    asns: Vec<u32>,
    min_hits: u32,
) -> Result<Vec<PrefixRecord>> {
    tokio::task::spawn_blocking(move || parse_bgp_tools_table(&path, &asns, min_hits))
        .await
        .context("failed to join bgp.tools table parser")?
}

fn parse_bgp_tools_table(path: &Path, asns: &[u32], min_hits: u32) -> Result<Vec<PrefixRecord>> {
    let asns: HashSet<u32> = asns.iter().copied().collect();
    let reader = BufReader::new(
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?,
    );
    let mut records = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.with_context(|| format!("failed to read line {line_number}"))?;
        if line.trim().is_empty() {
            continue;
        }

        let row: BgpToolsTableRow = serde_json::from_str(&line)
            .with_context(|| format!("invalid bgp.tools JSONL at line {line_number}"))?;
        if asns.contains(&row.asn) && row.hits.unwrap_or(0) >= min_hits {
            records.push(PrefixRecord {
                provider: DiscoveryProviderArg::BgpTools,
                asn: row.asn,
                relation: PrefixRelation::Origin,
                prefix: row.cidr,
            });
        }
    }

    Ok(records)
}

fn validate_bgp_tools_table(path: &Path) -> Result<()> {
    let reader = BufReader::new(
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?,
    );
    let mut rows = 0usize;

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.with_context(|| format!("failed to read line {line_number}"))?;
        if line.trim().is_empty() {
            continue;
        }

        let _: BgpToolsTableRow = serde_json::from_str(&line)
            .with_context(|| format!("invalid bgp.tools JSONL at line {line_number}"))?;
        rows += 1;
    }

    if rows == 0 {
        bail!("bgp.tools JSONL cache is empty");
    }

    Ok(())
}

async fn write_bgp_tools_response_atomic(response: Response, path: &Path) -> Result<()> {
    write_bgp_tools_table_stream_atomic(response.bytes_stream(), path).await
}

async fn write_bgp_tools_table_stream_atomic<S, B, E>(stream: S, path: &Path) -> Result<()>
where
    S: Stream<Item = std::result::Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
    E: Into<anyhow::Error>,
{
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("cache path has no file name")?;
    let tmp_path = path.with_file_name(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        monotonic_nanos()
    ));

    let result = async {
        let mut output = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await
            .with_context(|| format!("failed to create {}", tmp_path.display()))?;
        let mut stream = stream;
        let mut bytes_written = 0usize;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(Into::into)
                .context("failed to read response chunk")?;
            let chunk = chunk.as_ref();
            bytes_written = bytes_written
                .checked_add(chunk.len())
                .context("downloaded bgp.tools cache is too large")?;
            output
                .write_all(chunk)
                .await
                .with_context(|| format!("failed to write {}", tmp_path.display()))?;
        }

        if bytes_written == 0 {
            bail!("bgp.tools table export returned an empty body");
        }

        output
            .flush()
            .await
            .with_context(|| format!("failed to flush {}", tmp_path.display()))?;
        output
            .sync_all()
            .await
            .with_context(|| format!("failed to sync {}", tmp_path.display()))?;
        drop(output);

        let validate_path = tmp_path.clone();
        tokio::task::spawn_blocking(move || validate_bgp_tools_table(&validate_path))
            .await
            .context("failed to join bgp.tools cache validator")??;

        tokio::fs::rename(&tmp_path, path).await.with_context(|| {
            format!(
                "failed to rename {} to {}",
                tmp_path.display(),
                path.display()
            )
        })?;
        let sync_path = path.to_path_buf();
        tokio::task::spawn_blocking(move || sync_parent_directory(&sync_path))
            .await
            .context("failed to join bgp.tools cache directory sync")??;

        Ok::<_, anyhow::Error>(())
    }
    .await;

    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp_path).await;
    }

    result
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)
            .with_context(|| format!("failed to open {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("failed to sync {}", parent.display()))?;
    }

    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn monotonic_nanos() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn records_to_target_inputs(records: Vec<PrefixRecord>) -> Vec<TargetInput> {
    records
        .into_iter()
        .map(|record| {
            let provider = provider_name(record.provider);
            let relation = record.relation.label();
            TargetInput {
                value: record.prefix.clone(),
                source: Some(format!(
                    "{provider}:AS{}:{relation}:{}",
                    record.asn, record.prefix
                )),
                asn: Some(record.asn),
                name: Some(format!("AS{} {relation} via {provider}", record.asn)),
                prefix: Some(record.prefix),
            }
        })
        .collect()
}

fn scope_includes_origin(scope: DiscoveryScopeArg) -> bool {
    matches!(
        scope,
        DiscoveryScopeArg::Origin | DiscoveryScopeArg::OriginAndAsPath
    )
}

fn cache_is_fresh(path: &Path, ttl: Duration) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };

    age <= ttl
}

fn default_cache_dir() -> PathBuf {
    if let Some(cache_home) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(cache_home).join("anycast-scout");
    }

    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if cfg!(target_os = "macos") {
            return home.join("Library").join("Caches").join("anycast-scout");
        }
        return home.join(".cache").join("anycast-scout");
    }

    std::env::temp_dir().join("anycast-scout")
}

fn provider_name(provider: DiscoveryProviderArg) -> &'static str {
    match provider {
        DiscoveryProviderArg::Ripestat => "ripestat",
        DiscoveryProviderArg::BgpTools => "bgp-tools",
    }
}

fn ipv4_host_capacity(prefix: &str) -> u64 {
    let Ok(IpNet::V4(net)) = prefix.parse::<IpNet>() else {
        return 0;
    };

    let addresses = 1_u64 << (32 - net.prefix_len());
    if net.prefix_len() <= 30 {
        addresses.saturating_sub(2)
    } else {
        addresses
    }
}

fn rate_limit_error(provider: &str, response: &reqwest::Response) -> anyhow::Error {
    let retry_after = response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(|value| format!("; retry-after={value}"))
        .unwrap_or_default();

    anyhow!("{provider} returned HTTP 429{retry_after}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_asn_forms_and_deduplicates() {
        let asns = parse_asns(&["AS13335".to_string(), "13335, AS15169,".to_string()]).unwrap();

        assert_eq!(asns, vec![13335, 15169]);
    }

    #[test]
    fn rejects_discovery_when_all_attempted_providers_failed() {
        let warnings = vec![
            "ripestat: offline".to_string(),
            "bgp-tools: offline".to_string(),
        ];
        let error = fail_if_all_discovery_providers_failed(0, 2, 2, &warnings)
            .unwrap_err()
            .to_string();

        assert!(error.contains("all discovery providers failed"));
        assert!(error.contains("ripestat: offline"));
    }

    #[test]
    fn keeps_partial_discovery_success_as_warning() {
        let warnings = vec!["ripestat: offline".to_string()];

        fail_if_all_discovery_providers_failed(1, 2, 1, &warnings).unwrap();
    }

    #[test]
    fn parses_ripestat_announced_prefixes() {
        let value = serde_json::json!({
            "status": "ok",
            "data": {
                "prefixes": [
                    {"prefix": "104.16.0.0/13"},
                    {"prefix": "2606:4700::/32"}
                ]
            }
        });

        let records = parse_ripestat_prefixes(13335, &value).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].prefix, "104.16.0.0/13");
    }

    #[test]
    fn parses_ripestat_ris_origin_and_transit_prefixes() {
        let value = serde_json::json!({
            "status": "ok",
            "data": {
                "prefixes": {
                    "v4": {
                        "originating": ["104.16.0.0/13"],
                        "transiting": ["203.0.113.0/24"]
                    },
                    "v6": {
                        "originating": ["2606:4700::/32"],
                        "transiting": ["2001:db8::/48"]
                    }
                }
            }
        });

        let records =
            parse_ripestat_ris_prefixes(13335, DiscoveryScopeArg::OriginAndAsPath, &value).unwrap();

        assert_eq!(records.len(), 4);
        assert_eq!(records[0].relation, PrefixRelation::AsPathTransit);
        assert_eq!(records[0].prefix, "203.0.113.0/24");
        assert_eq!(records[2].relation, PrefixRelation::Origin);
    }

    #[test]
    fn parses_bgp_tools_jsonl_with_hits_filter() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"CIDR":"104.16.0.0/13","ASN":13335,"Hits":500}}"#).unwrap();
        writeln!(file, r#"{{"CIDR":"203.0.113.0/24","ASN":13335,"Hits":1}}"#).unwrap();
        writeln!(file, r#"{{"CIDR":"8.8.8.0/24","ASN":15169,"Hits":500}}"#).unwrap();

        let records = parse_bgp_tools_table(file.path(), &[13335], 10).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].prefix, "104.16.0.0/13");
    }

    #[test]
    fn counts_usable_ipv4_hosts_for_prefixes() {
        assert_eq!(ipv4_host_capacity("192.0.2.0/30"), 2);
        assert_eq!(ipv4_host_capacity("192.0.2.1/32"), 1);
        assert_eq!(ipv4_host_capacity("2606:4700::/32"), 0);
    }

    #[tokio::test]
    async fn writes_bgp_tools_cache_atomically_from_stream() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("bgp-tools-table.jsonl");
        let stream = futures::stream::iter([
            Ok::<_, std::io::Error>(br#"{"CIDR":"104.16.0.0/13","#.to_vec()),
            Ok(br#""ASN":13335,"Hits":500}"#.to_vec()),
            Ok(b"\n".to_vec()),
        ]);

        write_bgp_tools_table_stream_atomic(stream, &cache_path)
            .await
            .unwrap();

        let cache = fs::read_to_string(&cache_path).unwrap();
        assert_eq!(
            cache,
            concat!(r#"{"CIDR":"104.16.0.0/13","ASN":13335,"Hits":500}"#, "\n")
        );
        assert_no_bgp_tools_temp_files(dir.path());
    }

    #[tokio::test]
    async fn failed_bgp_tools_cache_stream_keeps_existing_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("bgp-tools-table.jsonl");
        fs::write(&cache_path, "existing-cache\n").unwrap();
        let stream = futures::stream::iter([
            Ok::<_, std::io::Error>(br#"{"CIDR":"104.16.0.0/13","#.to_vec()),
            Err(std::io::Error::other("network interrupted")),
        ]);

        let error = write_bgp_tools_table_stream_atomic(stream, &cache_path)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("failed to read response chunk"));
        assert_eq!(fs::read_to_string(&cache_path).unwrap(), "existing-cache\n");
        assert_no_bgp_tools_temp_files(dir.path());
    }

    #[tokio::test]
    async fn invalid_bgp_tools_cache_stream_keeps_existing_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("bgp-tools-table.jsonl");
        fs::write(&cache_path, "existing-cache\n").unwrap();
        let stream = futures::stream::iter([Ok::<_, std::io::Error>(
            br#"{"CIDR":"104.16.0.0/13","ASN":13335"#.to_vec(),
        )]);

        let error = write_bgp_tools_table_stream_atomic(stream, &cache_path)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("invalid bgp.tools JSONL"));
        assert_eq!(fs::read_to_string(&cache_path).unwrap(), "existing-cache\n");
        assert_no_bgp_tools_temp_files(dir.path());
    }

    fn assert_no_bgp_tools_temp_files(path: &Path) {
        let leftovers = fs::read_dir(path)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count();

        assert_eq!(leftovers, 0);
    }
}
