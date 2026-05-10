mod cli;
mod discovery;
mod input;
mod probe;
mod rate_limit;
mod report;
mod sing_box;
mod sing_box_installer;

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser};
use cli::{Cli, Commands, DiscoveryArgsShared, TargetExpansionArgs};
use discovery::DiscoveryOptions;
use futures::StreamExt;
use input::{ReadOptions, Target};
use probe::{ProbeConfig, ScanResult, Scanner};
use sing_box::{SingBoxUrlTestConfig, run_sing_box_urltest};
use std::collections::HashSet;
use std::env;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DISCOVERY_TARGET_BATCH_SIZE: usize = 8192;
const DEFAULT_DISCOVERY_USER_AGENT: &str =
    "Pingle anycast-scout bgp discovery - dev@pingle-family.com";
const DEFAULT_DISCOVERY_REQUEST_INTERVAL_MS: u64 = 1000;
const DEFAULT_RIPESTAT_MIN_PEERS_SEEING: u32 = 10;
const DEFAULT_BGP_TOOLS_MIN_HITS: u32 = 10;
const DEFAULT_BGP_TOOLS_CACHE_TTL_MINUTES: u64 = 120;

#[tokio::main]
async fn main() -> Result<()> {
    install_crypto_provider();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Discover(args)) => {
            let asns = discovery::parse_asns(&args.discovery.asn)?;
            let options = discovery_options(
                &args.discovery,
                &args.expansion,
                asns,
                cli::InputFormat::Auto,
            )?;
            stream_discovery_targets(options, args.output.as_deref(), DISCOVERY_TARGET_BATCH_SIZE)
                .await?;
        }
        Some(Commands::Scan(args)) => {
            let edge_validation = edge_validation_from_args(&args)?;
            let config = ProbeConfig {
                resources: probe::cloudflare_validation_resources(),
                edge_validation,
                timeout: Duration::from_millis(args.timeout_ms),
                speed_url: args.speed_url.clone(),
                speed_duration: Duration::from_secs(args.speed_seconds),
                download_url: args.download_url.clone(),
                min_download_bytes: args.min_download_bytes,
                download_timeout: Duration::from_millis(args.download_timeout_ms),
                user_agent: args.user_agent.clone(),
            };

            let scanner = Scanner::new(
                config,
                args.concurrency,
                Duration::from_millis(args.request_interval_ms),
            )?;
            stream_scan_targets(&scanner, &args).await?;
        }
        Some(Commands::SingBoxUrltest(args)) => {
            let config = SingBoxUrlTestConfig {
                config_source: args.config,
                candidate_ip: args.candidate_ip,
                outbound_tag: args.outbound_tag,
                min_download_bytes: args.min_download_bytes,
                sing_box_bin: args.sing_box_bin,
            };

            let result = run_sing_box_urltest(config).await?;
            report::write_json_value(&serde_json::to_value(result)?, args.output.as_deref())?;
        }
        None => {
            let mut command = Cli::command();
            command.print_help()?;
            println!();
        }
    }

    Ok(())
}

fn edge_validation_from_args(args: &cli::ScanArgs) -> Result<Option<probe::EdgeValidationConfig>> {
    let Some(hostname) = args.edge_hostname.as_deref().map(str::trim) else {
        return Ok(None);
    };
    if hostname.is_empty() {
        bail!("edge hostname must not be empty");
    }
    let overlapping_codes = args
        .edge_accept_error_codes
        .iter()
        .copied()
        .filter(|code| args.edge_reject_error_codes.contains(code))
        .collect::<Vec<_>>();
    if !overlapping_codes.is_empty() {
        bail!(
            "edge accept and reject error codes overlap: {}",
            overlapping_codes
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
    }

    Ok(Some(probe::edge_validation_config(
        hostname,
        &args.edge_path,
        args.edge_direct_error_codes.clone(),
        args.edge_accept_error_codes.clone(),
        args.edge_reject_error_codes.clone(),
    )?))
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn read_options(expansion: &TargetExpansionArgs, input_format: cli::InputFormat) -> ReadOptions {
    ReadOptions {
        default_port: expansion.port,
        input_format,
        all_hosts: expansion.all_hosts,
        max_targets: expansion.max_targets,
    }
}

#[cfg(test)]
fn read_targets_from_paths(paths: &[PathBuf], options: &ReadOptions) -> Result<Vec<Target>> {
    reject_repeated_stdin(paths)?;

    let mut targets = Vec::new();
    for path in paths {
        let mut parsed = input::read_targets(path, options)
            .map_err(|error| error.context(format!("failed to parse {}", display_path(path))))?;
        targets.append(&mut parsed);
        dedupe_targets(&mut targets);
        limit_targets(&mut targets, options.max_targets);
        if has_reached_target_limit(targets.len(), options.max_targets) {
            break;
        }
    }

    Ok(targets)
}

fn read_target_inputs_from_paths(
    paths: &[PathBuf],
    options: &ReadOptions,
) -> Result<Vec<input::TargetInput>> {
    reject_repeated_stdin(paths)?;

    let mut inputs = Vec::new();
    for path in paths {
        let mut parsed = input::read_target_inputs(path, options)
            .map_err(|error| error.context(format!("failed to parse {}", display_path(path))))?;
        inputs.append(&mut parsed);
    }

    Ok(inputs)
}

fn reject_repeated_stdin(paths: &[PathBuf]) -> Result<()> {
    let stdin_count = paths
        .iter()
        .filter(|path| path.as_path() == Path::new("-"))
        .count();
    if stdin_count > 1 {
        bail!("stdin input '-' can be used only once");
    }

    Ok(())
}

fn display_path(path: &Path) -> String {
    if path == Path::new("-") {
        "stdin".to_string()
    } else {
        path.display().to_string()
    }
}

#[cfg(test)]
fn dedupe_targets(targets: &mut Vec<Target>) {
    let mut seen = HashSet::new();
    targets.retain(|target| seen.insert((target.ip, target.port)));
}

#[cfg(test)]
fn limit_targets(targets: &mut Vec<Target>, max_targets: usize) {
    if max_targets > 0 {
        targets.truncate(max_targets);
    }
}

fn has_reached_target_limit(current: usize, max_targets: usize) -> bool {
    max_targets > 0 && current >= max_targets
}

async fn stream_discovery_targets(
    options: DiscoveryOptions,
    output: Option<&Path>,
    batch_size: usize,
) -> Result<()> {
    let read_options = options.read_options.clone();
    let result = discovery::discover_target_inputs(options).await?;
    report_discovery_inputs(&result);

    let mut writer = report::TargetStreamWriter::new(output)?;
    let mut total = 0_usize;
    for batch in input::target_batches_from_inputs(result.inputs, &read_options, batch_size)? {
        let batch = batch?;
        total += batch.len();
        writer.write_batch(&batch)?;
        eprintln!("discovery targets written={total}");
    }
    writer.finish()?;
    eprintln!("discovered targets={total}");

    Ok(())
}

#[derive(Debug, Default)]
struct ScanSummary {
    scanned: usize,
    valid: usize,
}

#[derive(Debug, Default)]
struct ScanResumeState {
    summary: ScanSummary,
    seen: HashSet<TargetKey>,
}

type TargetKey = (IpAddr, u16);

async fn stream_scan_targets(scanner: &Scanner, args: &cli::ScanArgs) -> Result<ScanSummary> {
    if let Some(max_valid) = args.max_valid
        && max_valid == 0
    {
        bail!("max-valid must be greater than zero");
    }

    let batch_size = effective_stream_batch_size(args);
    let mut resume_state = scan_resume_state(args)?;
    if args.resume && resume_state.summary.scanned > 0 {
        report::print_summary_counts(resume_state.summary.scanned, resume_state.summary.valid);
    }
    let mut writer = report::ResultStreamWriter::new(args.output.as_deref(), args.resume)?;
    if has_reached_valid_limit(resume_state.summary.valid, args.max_valid) {
        writer.finish()?;
        return Ok(resume_state.summary);
    }
    let mut saw_targets = false;

    if !args.input.is_empty() {
        let options = read_options(&args.expansion, args.input_format);
        let inputs = read_target_inputs_from_paths(&args.input, &options)?;
        for batch in input::target_batches_from_inputs(inputs, &options, batch_size)? {
            let batch = pending_scan_targets(batch?, &resume_state.seen);
            if batch.is_empty() {
                continue;
            }
            saw_targets = true;
            if !scan_and_write_batch(scanner, &mut writer, batch, args, &mut resume_state).await? {
                writer.finish()?;
                return Ok(resume_state.summary);
            }
        }
    }

    if !args.discovery.asn.is_empty()
        && !has_reached_target_limit(resume_state.summary.scanned, args.expansion.max_targets)
    {
        let asns = discovery::parse_asns(&args.discovery.asn)?;
        let mut discovery_options =
            discovery_options(&args.discovery, &args.expansion, asns, args.input_format)?;
        discovery_options.read_options.max_targets =
            remaining_target_limit(args.expansion.max_targets, resume_state.summary.scanned);
        let read_options = discovery_options.read_options.clone();
        let discovery_result = discovery::discover_target_inputs(discovery_options).await?;
        report_discovery_inputs(&discovery_result);

        for batch in
            input::target_batches_from_inputs(discovery_result.inputs, &read_options, batch_size)?
        {
            let batch = pending_scan_targets(batch?, &resume_state.seen);
            if batch.is_empty() {
                continue;
            }
            saw_targets = true;
            if !scan_and_write_batch(scanner, &mut writer, batch, args, &mut resume_state).await? {
                writer.finish()?;
                return Ok(resume_state.summary);
            }
        }
    }

    writer.finish()?;

    if !saw_targets && resume_state.summary.scanned == 0 {
        bail!("no scan targets: provide --input, --asn, or both");
    }

    Ok(resume_state.summary)
}

async fn scan_and_write_batch(
    scanner: &Scanner,
    writer: &mut report::ResultStreamWriter,
    batch: Vec<Target>,
    args: &cli::ScanArgs,
    resume_state: &mut ScanResumeState,
) -> Result<bool> {
    if batch.is_empty() {
        return Ok(true);
    }

    eprintln!("scan batch targets={}", batch.len());
    let mut results = scanner.scan_stream(batch);
    while let Some(result) = results.next().await {
        resume_state.summary.scanned += 1;
        if result.valid {
            resume_state.summary.valid += 1;
        }
        writer.write_result(&result)?;
        resume_state.seen.insert(scan_result_key(&result));
        report::print_summary_counts(resume_state.summary.scanned, resume_state.summary.valid);

        if let Some(max_valid) = args.max_valid
            && resume_state.summary.valid >= max_valid
        {
            eprintln!(
                "max-valid reached valid={} limit={max_valid}",
                resume_state.summary.valid
            );
            return Ok(false);
        }
    }

    Ok(true)
}

fn scan_resume_state(args: &cli::ScanArgs) -> Result<ScanResumeState> {
    if !args.resume {
        return Ok(ScanResumeState::default());
    }

    let output = args
        .output
        .as_deref()
        .context("--resume requires --output")?;
    if !output.exists() {
        return Ok(ScanResumeState::default());
    }

    let mut reader = csv::Reader::from_path(output)
        .with_context(|| format!("failed to read {}", output.display()))?;
    let mut state = ScanResumeState::default();
    for result in reader.deserialize::<ScanResult>() {
        let result = result.with_context(|| {
            format!("failed to parse existing scan result {}", output.display())
        })?;
        state.summary.scanned += 1;
        if result.valid {
            state.summary.valid += 1;
        }
        state.seen.insert(scan_result_key(&result));
    }
    Ok(state)
}

fn pending_scan_targets(batch: Vec<Target>, seen: &HashSet<TargetKey>) -> Vec<Target> {
    batch
        .into_iter()
        .filter(|target| !seen.contains(&target_key(target)))
        .collect()
}

fn target_key(target: &Target) -> TargetKey {
    (target.ip, target.port)
}

fn scan_result_key(result: &ScanResult) -> TargetKey {
    (result.ip, result.port)
}

fn remaining_target_limit(max_targets: usize, already_scanned: usize) -> usize {
    if max_targets == 0 {
        0
    } else {
        max_targets.saturating_sub(already_scanned)
    }
}

fn has_reached_valid_limit(valid: usize, max_valid: Option<usize>) -> bool {
    max_valid.is_some_and(|limit| valid >= limit)
}

fn effective_stream_batch_size(args: &cli::ScanArgs) -> usize {
    args.concurrency.max(1).saturating_mul(8).max(1)
}

fn discovery_options(
    discovery: &DiscoveryArgsShared,
    expansion: &TargetExpansionArgs,
    asns: Vec<u32>,
    input_format: cli::InputFormat,
) -> Result<DiscoveryOptions> {
    let bgp_tools_cache_ttl_minutes = env_u64(
        "ANYCAST_SCOUT_BGP_TOOLS_CACHE_TTL_MINUTES",
        DEFAULT_BGP_TOOLS_CACHE_TTL_MINUTES,
    );
    let bgp_tools_cache_ttl_secs = bgp_tools_cache_ttl_minutes
        .checked_mul(60)
        .context("ANYCAST_SCOUT_BGP_TOOLS_CACHE_TTL_MINUTES is too large")?;

    Ok(DiscoveryOptions {
        asns,
        providers: vec![
            cli::DiscoveryProviderArg::Ripestat,
            cli::DiscoveryProviderArg::BgpTools,
        ],
        scope: discovery.discovery_scope,
        merge_providers: true,
        user_agent: env_string(
            "ANYCAST_SCOUT_DISCOVERY_USER_AGENT",
            DEFAULT_DISCOVERY_USER_AGENT,
        ),
        request_interval: Duration::from_millis(env_u64(
            "ANYCAST_SCOUT_DISCOVERY_REQUEST_INTERVAL_MS",
            DEFAULT_DISCOVERY_REQUEST_INTERVAL_MS,
        )),
        ripestat_min_peers_seeing: env_u32(
            "ANYCAST_SCOUT_RIPESTAT_MIN_PEERS_SEEING",
            DEFAULT_RIPESTAT_MIN_PEERS_SEEING,
        ),
        bgp_tools_min_hits: env_u32(
            "ANYCAST_SCOUT_BGP_TOOLS_MIN_HITS",
            DEFAULT_BGP_TOOLS_MIN_HITS,
        ),
        cache_dir: env_path("ANYCAST_SCOUT_DISCOVERY_CACHE_DIR"),
        bgp_tools_cache_ttl: Duration::from_secs(bgp_tools_cache_ttl_secs),
        refresh_cache: env_bool("ANYCAST_SCOUT_REFRESH_DISCOVERY_CACHE"),
        read_options: read_options(expansion, input_format),
    })
}

fn env_string(name: &str, fallback: &str) -> String {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn env_u64(name: &str, fallback: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(fallback)
}

fn env_u32(name: &str, fallback: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(fallback)
}

fn env_bool(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name).map(PathBuf::from)
}

fn report_discovery_inputs(result: &discovery::DiscoveryInputResult) {
    for warning in &result.warnings {
        eprintln!("discovery warning: {warning}");
    }

    for summary in &result.summaries {
        eprintln!(
            "discovered provider={} asn=AS{} relation={} prefixes={} ipv4_hosts={}",
            summary.provider, summary.asn, summary.relation, summary.prefixes, summary.ipv4_hosts
        );
    }

    eprintln!("discovered target_inputs={}", result.inputs.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use cli::InputFormat;
    use std::fs;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn options() -> ReadOptions {
        ReadOptions {
            default_port: 443,
            input_format: InputFormat::Auto,
            all_hosts: false,
            max_targets: 100,
        }
    }

    fn scan_args(output: Option<PathBuf>, resume: bool) -> cli::ScanArgs {
        cli::ScanArgs {
            input: Vec::new(),
            discovery: DiscoveryArgsShared {
                asn: Vec::new(),
                discovery_scope: cli::DiscoveryScopeArg::Origin,
            },
            input_format: InputFormat::Auto,
            output,
            resume,
            expansion: TargetExpansionArgs {
                port: 443,
                all_hosts: false,
                max_targets: 100,
            },
            concurrency: 1,
            request_interval_ms: 0,
            max_valid: None,
            timeout_ms: 1000,
            speed_url: None,
            speed_seconds: 0,
            download_url: None,
            min_download_bytes: 0,
            download_timeout_ms: 1000,
            edge_hostname: None,
            edge_path: "/".to_string(),
            edge_direct_error_codes: vec![1003],
            edge_accept_error_codes: Vec::new(),
            edge_reject_error_codes: vec![1034],
            user_agent: "test".to_string(),
        }
    }

    fn discovery_args() -> DiscoveryArgsShared {
        DiscoveryArgsShared {
            asn: vec!["AS13335".to_string()],
            discovery_scope: cli::DiscoveryScopeArg::Origin,
        }
    }

    #[test]
    fn reads_multiple_input_files_and_dedupes_targets() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.txt");
        let second = dir.path().join("second.txt");
        fs::write(&first, "1.1.1.1\n1.1.1.2\n").unwrap();
        fs::write(&second, "1.1.1.1\n1.1.1.3\n").unwrap();

        let targets = read_targets_from_paths(&[first, second], &options()).unwrap();

        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].ip.to_string(), "1.1.1.1");
        assert_eq!(targets[1].ip.to_string(), "1.1.1.2");
        assert_eq!(targets[2].ip.to_string(), "1.1.1.3");
    }

    #[test]
    fn applies_max_targets_across_multiple_input_files() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.txt");
        let second = dir.path().join("second.txt");
        fs::write(&first, "1.1.1.1\n1.1.1.2\n").unwrap();
        fs::write(&second, "1.1.1.3\n1.1.1.4\n").unwrap();

        let mut options = options();
        options.max_targets = 3;
        let targets = read_targets_from_paths(&[first, second], &options).unwrap();

        assert_eq!(targets.len(), 3);
        assert_eq!(targets[2].ip.to_string(), "1.1.1.3");
    }

    #[test]
    fn zero_max_targets_keeps_all_input_files() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.txt");
        let second = dir.path().join("second.txt");
        fs::write(&first, "1.1.1.1\n1.1.1.2\n").unwrap();
        fs::write(&second, "1.1.1.3\n1.1.1.4\n").unwrap();

        let mut options = options();
        options.max_targets = 0;
        let targets = read_targets_from_paths(&[first, second], &options).unwrap();

        assert_eq!(targets.len(), 4);
        assert_eq!(targets[3].ip.to_string(), "1.1.1.4");
    }

    #[test]
    fn rejects_repeated_stdin_inputs() {
        let paths = vec![PathBuf::from("-"), PathBuf::from("-")];
        let error = reject_repeated_stdin(&paths).unwrap_err().to_string();

        assert!(error.contains("stdin input '-' can be used only once"));
    }

    #[test]
    fn reads_direct_input_as_unexpanded_target_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("targets.txt");
        fs::write(&path, "10.0.0.0/8\n").unwrap();

        let inputs = read_target_inputs_from_paths(&[path], &options()).unwrap();

        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].value, "10.0.0.0/8");
    }

    #[test]
    fn resume_state_reads_existing_scan_output() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("scan.csv");
        fs::write(
            &output,
            "ip,port,valid,status,latency_ms,speed_mbps,download_bytes,colo,server,reason,resource,source,asn,org,prefix\n\
             1.1.1.1,443,true,200,12.5,,20480,SJC,cloudflare,ok,trace,fixture,13335,Cloudflare,1.1.1.0/24\n\
             1.1.1.2,443,false,,,,,,,timeout,,fixture,,,\n",
        )
        .unwrap();

        let args = scan_args(Some(output), true);
        let state = scan_resume_state(&args).unwrap();

        assert_eq!(state.summary.scanned, 2);
        assert_eq!(state.summary.valid, 1);
        assert!(
            state
                .seen
                .contains(&(IpAddr::from_str("1.1.1.1").unwrap(), 443))
        );
        assert!(
            state
                .seen
                .contains(&(IpAddr::from_str("1.1.1.2").unwrap(), 443))
        );
    }

    #[test]
    fn resume_state_requires_output_path() {
        let args = scan_args(None, true);
        let error = scan_resume_state(&args).unwrap_err().to_string();

        assert!(error.contains("--resume requires --output"));
    }

    #[test]
    fn pending_scan_targets_skip_resumed_results() {
        let seen = HashSet::from([(IpAddr::from_str("1.1.1.1").unwrap(), 443)]);
        let targets = vec![
            Target {
                ip: IpAddr::from_str("1.1.1.1").unwrap(),
                port: 443,
                source: "seen".to_string(),
                asn: None,
                name: None,
                prefix: None,
            },
            Target {
                ip: IpAddr::from_str("1.1.1.2").unwrap(),
                port: 443,
                source: "pending".to_string(),
                asn: None,
                name: None,
                prefix: None,
            },
        ];

        let pending = pending_scan_targets(targets, &seen);

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].ip, IpAddr::from_str("1.1.1.2").unwrap());
    }

    #[test]
    fn resume_valid_count_satisfies_max_valid_limit() {
        assert!(has_reached_valid_limit(3, Some(3)));
        assert!(!has_reached_valid_limit(2, Some(3)));
        assert!(!has_reached_valid_limit(3, None));
    }

    #[test]
    fn discovery_options_uses_fixed_provider_merge_policy() {
        let discovery = discovery_args();
        let expansion = TargetExpansionArgs {
            port: 443,
            all_hosts: false,
            max_targets: 100,
        };

        let options =
            discovery_options(&discovery, &expansion, vec![13335], InputFormat::Auto).unwrap();

        assert!(options.merge_providers);
        assert_eq!(options.providers.len(), 2);
    }
}
