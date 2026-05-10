use crate::cli::InputFormat;
use anyhow::{Context, Result, bail};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
    pub source: String,
    pub asn: Option<u32>,
    pub name: Option<String>,
    pub prefix: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ReadOptions {
    pub default_port: u16,
    pub input_format: InputFormat,
    pub all_hosts: bool,
    pub max_targets: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetInput {
    pub value: String,
    pub source: Option<String>,
    pub asn: Option<u32>,
    pub name: Option<String>,
    pub prefix: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct TargetMeta {
    source: Option<String>,
    asn: Option<u32>,
    name: Option<String>,
    prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JsonTargetRecord {
    ip: IpAddr,
    port: Option<u16>,
    source: Option<String>,
    asn: Option<u32>,
    #[serde(alias = "org")]
    name: Option<String>,
    prefix: Option<String>,
}

#[cfg(test)]
pub fn read_targets(path: &Path, options: &ReadOptions) -> Result<Vec<Target>> {
    validate_options(options)?;

    let input = read_input(path)?;
    match detect_format(&input, options.input_format) {
        InputFormat::Text => parse_text(&input, options),
        InputFormat::Csv => parse_csv(&input, options),
        InputFormat::Json => parse_json(&input, options),
        InputFormat::Auto => unreachable!("auto format is resolved by detect_format"),
    }
}

pub fn read_target_inputs(path: &Path, options: &ReadOptions) -> Result<Vec<TargetInput>> {
    validate_options(options)?;

    let input = read_input(path)?;
    match detect_format(&input, options.input_format) {
        InputFormat::Text => parse_text_inputs(&input, options),
        InputFormat::Csv => parse_csv_inputs(&input, options),
        InputFormat::Json => parse_json_inputs(&input, options),
        InputFormat::Auto => unreachable!("auto format is resolved by detect_format"),
    }
}

pub fn target_batches_from_inputs(
    inputs: Vec<TargetInput>,
    options: &ReadOptions,
    batch_size: usize,
) -> Result<TargetBatchIter> {
    validate_options(options)?;
    Ok(TargetBatchIter::new(inputs, options.clone(), batch_size))
}

fn validate_options(options: &ReadOptions) -> Result<()> {
    if options.default_port == 0 {
        bail!("default port must be greater than zero");
    }

    Ok(())
}

fn read_input(path: &Path) -> Result<Vec<u8>> {
    let mut input = Vec::new();

    if path == Path::new("-") {
        io::stdin()
            .read_to_end(&mut input)
            .context("failed to read stdin")?;
    } else {
        File::open(path)
            .with_context(|| format!("failed to open {}", path.display()))?
            .read_to_end(&mut input)
            .with_context(|| format!("failed to read {}", path.display()))?;
    }

    Ok(input)
}

fn detect_format(input: &[u8], requested: InputFormat) -> InputFormat {
    if requested != InputFormat::Auto {
        return requested;
    }

    if let Some(line) = first_non_empty_line(input)
        && looks_like_csv_header(line)
    {
        return InputFormat::Csv;
    }

    match input
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
    {
        Some(b'[' | b'{') => InputFormat::Json,
        _ => InputFormat::Text,
    }
}

fn first_non_empty_line(input: &[u8]) -> Option<&str> {
    std::str::from_utf8(input).ok()?.lines().find_map(|line| {
        let trimmed = line.trim_start_matches('\u{feff}').trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn looks_like_csv_header(line: &str) -> bool {
    let mut columns = line
        .split(',')
        .map(|column| column.trim().trim_matches('"').to_ascii_lowercase());
    matches!(columns.next().as_deref(), Some("ip")) && columns.any(|column| column == "port")
}

#[cfg(test)]
fn parse_text(input: &[u8], options: &ReadOptions) -> Result<Vec<Target>> {
    let reader = BufReader::new(input);
    let mut builder = TargetBuilder::new(options);
    let mut errors = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.with_context(|| format!("failed to read line {line_number}"))?;
        let trimmed = strip_comment(&line);

        if trimmed.is_empty() {
            continue;
        }

        if let Err(error) = builder.add_value(trimmed, TargetMeta::default()) {
            errors.push(format!("line {line_number}: {error}"));
        }
    }

    if !errors.is_empty() {
        bail!("invalid input:\n{}", errors.join("\n"));
    }

    Ok(builder.finish())
}

fn parse_text_inputs(input: &[u8], options: &ReadOptions) -> Result<Vec<TargetInput>> {
    let reader = BufReader::new(input);
    let mut inputs = Vec::new();
    let mut errors = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.with_context(|| format!("failed to read line {line_number}"))?;
        let trimmed = strip_comment(&line);

        if trimmed.is_empty() {
            continue;
        }

        if let Err(error) = validate_target_value(trimmed, options.default_port) {
            errors.push(format!("line {line_number}: {error}"));
            continue;
        }

        inputs.push(TargetInput {
            value: trimmed.to_string(),
            source: None,
            asn: None,
            name: None,
            prefix: None,
        });
    }

    if !errors.is_empty() {
        bail!("invalid input:\n{}", errors.join("\n"));
    }

    Ok(inputs)
}

#[cfg(test)]
fn parse_json(input: &[u8], options: &ReadOptions) -> Result<Vec<Target>> {
    let records: Vec<JsonTargetRecord> =
        serde_json::from_slice(input).context("failed to parse target JSON")?;
    let mut builder = TargetBuilder::new(options);
    let mut errors = Vec::new();

    for (index, record) in records.iter().enumerate() {
        let record_index = index + 1;
        let source = record
            .source
            .clone()
            .unwrap_or_else(|| record.ip.to_string());
        let meta = TargetMeta {
            source: record.source.clone(),
            asn: record.asn,
            name: record.name.clone(),
            prefix: record.prefix.clone(),
        };
        if let Err(error) = builder.add_target(
            record.ip,
            record.port.unwrap_or(options.default_port),
            source,
            meta,
        ) {
            errors.push(format!(
                "record {record_index} target {}: {error}",
                record.ip
            ));
        }
    }

    if !errors.is_empty() {
        bail!("invalid JSON input:\n{}", errors.join("\n"));
    }

    Ok(builder.finish())
}

fn parse_json_inputs(input: &[u8], options: &ReadOptions) -> Result<Vec<TargetInput>> {
    let records: Vec<JsonTargetRecord> =
        serde_json::from_slice(input).context("failed to parse target JSON")?;

    Ok(records
        .iter()
        .map(|record| record_to_target_input(record, options.default_port))
        .collect())
}

#[cfg(test)]
fn parse_csv(input: &[u8], options: &ReadOptions) -> Result<Vec<Target>> {
    let mut reader = csv::Reader::from_reader(input);
    let mut builder = TargetBuilder::new(options);
    let mut errors = Vec::new();

    for (index, record) in reader.deserialize::<JsonTargetRecord>().enumerate() {
        let record_index = index + 1;
        match record {
            Ok(record) => {
                let source = record
                    .source
                    .clone()
                    .unwrap_or_else(|| record.ip.to_string());
                let meta = TargetMeta {
                    source: record.source.clone(),
                    asn: record.asn,
                    name: record.name.clone(),
                    prefix: record.prefix.clone(),
                };
                if let Err(error) = builder.add_target(
                    record.ip,
                    record.port.unwrap_or(options.default_port),
                    source,
                    meta,
                ) {
                    errors.push(format!(
                        "record {record_index} target {}: {error}",
                        record.ip
                    ));
                }
            }
            Err(error) => errors.push(format!("record {record_index}: {error}")),
        }
    }

    if !errors.is_empty() {
        bail!("invalid CSV input:\n{}", errors.join("\n"));
    }

    Ok(builder.finish())
}

fn parse_csv_inputs(input: &[u8], options: &ReadOptions) -> Result<Vec<TargetInput>> {
    let mut reader = csv::Reader::from_reader(input);
    let mut inputs = Vec::new();
    let mut errors = Vec::new();

    for (index, record) in reader.deserialize::<JsonTargetRecord>().enumerate() {
        let record_index = index + 1;
        match record {
            Ok(record) => inputs.push(record_to_target_input(&record, options.default_port)),
            Err(error) => errors.push(format!("record {record_index}: {error}")),
        }
    }

    if !errors.is_empty() {
        bail!("invalid CSV input:\n{}", errors.join("\n"));
    }

    Ok(inputs)
}

fn record_to_target_input(record: &JsonTargetRecord, default_port: u16) -> TargetInput {
    let port = record.port.unwrap_or(default_port);
    let source = record
        .source
        .clone()
        .unwrap_or_else(|| record.ip.to_string());

    TargetInput {
        value: target_value(record.ip, port, default_port),
        source: Some(source),
        asn: record.asn,
        name: record.name.clone(),
        prefix: record.prefix.clone(),
    }
}

fn target_value(ip: IpAddr, port: u16, default_port: u16) -> String {
    if port == default_port {
        ip.to_string()
    } else {
        SocketAddr::new(ip, port).to_string()
    }
}

fn validate_target_value(value: &str, default_port: u16) -> Result<()> {
    if value.contains('/') {
        value
            .parse::<IpNet>()
            .with_context(|| format!("invalid CIDR: {value}"))?;
    } else {
        parse_ip_or_socket(value, default_port)?;
    }

    Ok(())
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(value, _)| value).trim()
}

#[cfg(test)]
struct TargetBuilder<'a> {
    options: &'a ReadOptions,
    targets: Vec<Target>,
    seen: HashSet<(IpAddr, u16)>,
}

#[cfg(test)]
impl<'a> TargetBuilder<'a> {
    fn new(options: &'a ReadOptions) -> Self {
        Self {
            options,
            targets: Vec::new(),
            seen: HashSet::new(),
        }
    }

    fn add_value(&mut self, value: &str, meta: TargetMeta) -> Result<()> {
        if value.contains('/') {
            let net = value
                .parse::<IpNet>()
                .with_context(|| format!("invalid CIDR: {value}"))?;
            self.add_prefix(net, value, meta)
        } else {
            let (ip, port) = parse_ip_or_socket(value, self.options.default_port)?;
            self.add_target(ip, port, value.to_string(), meta)
        }
    }

    fn add_prefix(&mut self, net: IpNet, source: &str, meta: TargetMeta) -> Result<()> {
        let samples = match net {
            IpNet::V4(net) => sample_ipv4(net, self.options),
            IpNet::V6(net) => sample_ipv6(net, self.options),
        };

        for ip in samples {
            let mut meta = meta.clone();
            meta.prefix.get_or_insert_with(|| source.to_string());
            self.add_target(ip, self.options.default_port, source.to_string(), meta)?;
        }

        Ok(())
    }

    fn add_target(
        &mut self,
        ip: IpAddr,
        port: u16,
        source: String,
        meta: TargetMeta,
    ) -> Result<()> {
        if has_reached_target_limit(self.targets.len(), self.options.max_targets) {
            return Ok(());
        }

        if self.seen.insert((ip, port)) {
            self.targets.push(Target {
                ip,
                port,
                source: meta.source.unwrap_or(source),
                asn: meta.asn,
                name: meta.name,
                prefix: meta.prefix,
            });
        }

        Ok(())
    }

    fn finish(self) -> Vec<Target> {
        self.targets
    }
}

pub struct TargetBatchIter {
    inputs: std::vec::IntoIter<TargetInput>,
    options: ReadOptions,
    batch_size: usize,
    current: Option<ExpandedTargets>,
    seen: HashSet<(IpAddr, u16)>,
    produced: usize,
}

impl TargetBatchIter {
    fn new(inputs: Vec<TargetInput>, options: ReadOptions, batch_size: usize) -> Self {
        Self {
            inputs: inputs.into_iter(),
            options,
            batch_size: batch_size.max(1),
            current: None,
            seen: HashSet::new(),
            produced: 0,
        }
    }

    fn next_target(&mut self) -> Result<Option<Target>> {
        if has_reached_target_limit(self.produced, self.options.max_targets) {
            return Ok(None);
        }

        loop {
            if let Some(current) = &mut self.current
                && let Some(target) = current.next_target()
            {
                if self.seen.insert((target.ip, target.port)) {
                    self.produced += 1;
                    return Ok(Some(target));
                }
                continue;
            }

            let Some(input) = self.inputs.next() else {
                return Ok(None);
            };
            self.current = Some(ExpandedTargets::from_input(input, &self.options)?);
        }
    }
}

impl Iterator for TargetBatchIter {
    type Item = Result<Vec<Target>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batch = Vec::with_capacity(self.batch_size);

        while batch.len() < self.batch_size {
            match self.next_target() {
                Ok(Some(target)) => batch.push(target),
                Ok(None) => break,
                Err(error) => return Some(Err(error)),
            }
        }

        if batch.is_empty() {
            None
        } else {
            Some(Ok(batch))
        }
    }
}

struct ExpandedTargets {
    ips: ExpandedIps,
    port: u16,
    source: String,
    meta: TargetMeta,
}

impl ExpandedTargets {
    fn from_input(input: TargetInput, options: &ReadOptions) -> Result<Self> {
        let TargetInput {
            value,
            source,
            asn,
            name,
            prefix,
        } = input;
        let meta = TargetMeta {
            source,
            asn,
            name,
            prefix,
        };

        if value.contains('/') {
            let net = value
                .parse::<IpNet>()
                .with_context(|| format!("invalid CIDR: {value}"))?;
            let mut meta = meta;
            meta.prefix.get_or_insert_with(|| value.clone());
            return Ok(Self {
                ips: ExpandedIps::from_net(net, options),
                port: options.default_port,
                source: value,
                meta,
            });
        }

        let (ip, port) = parse_ip_or_socket(&value, options.default_port)?;
        Ok(Self {
            ips: ExpandedIps::single(ip),
            port,
            source: value,
            meta,
        })
    }

    fn next_target(&mut self) -> Option<Target> {
        let ip = self.ips.next()?;
        Some(Target {
            ip,
            port: self.port,
            source: self
                .meta
                .source
                .clone()
                .unwrap_or_else(|| self.source.clone()),
            asn: self.meta.asn,
            name: self.meta.name.clone(),
            prefix: self.meta.prefix.clone(),
        })
    }
}

enum ExpandedIps {
    Vec(std::vec::IntoIter<IpAddr>),
    V4All { next: u32, last: u32 },
    V6All { next: u128, last: u128 },
}

impl ExpandedIps {
    fn single(ip: IpAddr) -> Self {
        Self::Vec(vec![ip].into_iter())
    }

    fn from_net(net: IpNet, options: &ReadOptions) -> Self {
        match net {
            IpNet::V4(net) if options.all_hosts => {
                let first = u32::from(net.network());
                let last = u32::from(net.broadcast());
                let first_host = if net.prefix_len() <= 30 {
                    first.saturating_add(1)
                } else {
                    first
                };
                let last_host = if net.prefix_len() <= 30 {
                    last.saturating_sub(1)
                } else {
                    last
                };

                if first_host > last_host {
                    Self::Vec(Vec::new().into_iter())
                } else {
                    Self::V4All {
                        next: first_host,
                        last: last_host,
                    }
                }
            }
            IpNet::V6(net) if options.all_hosts && net.prefix_len() >= 127 => {
                let first = u128::from(net.network());
                let span = 1_u128 << (128 - net.prefix_len());
                Self::V6All {
                    next: first,
                    last: first + span - 1,
                }
            }
            IpNet::V4(net) => Self::Vec(sample_ipv4(net, options).into_iter()),
            IpNet::V6(net) => Self::Vec(sample_ipv6(net, options).into_iter()),
        }
    }

    fn next(&mut self) -> Option<IpAddr> {
        match self {
            Self::Vec(ips) => ips.next(),
            Self::V4All { next, last } => {
                if *next > *last {
                    None
                } else {
                    let ip = IpAddr::V4(Ipv4Addr::from(*next));
                    *next = next.saturating_add(1);
                    Some(ip)
                }
            }
            Self::V6All { next, last } => {
                if *next > *last {
                    None
                } else {
                    let ip = IpAddr::V6(Ipv6Addr::from(*next));
                    *next = next.saturating_add(1);
                    Some(ip)
                }
            }
        }
    }
}

fn parse_ip_or_socket(value: &str, default_port: u16) -> Result<(IpAddr, u16)> {
    if let Ok(socket) = SocketAddr::from_str(value) {
        return Ok((socket.ip(), socket.port()));
    }

    let ip = IpAddr::from_str(value)
        .with_context(|| format!("expected IP, IP:PORT, or CIDR, got {value}"))?;
    Ok((ip, default_port))
}

fn sample_ipv4(net: Ipv4Net, options: &ReadOptions) -> Vec<IpAddr> {
    let first = u32::from(net.network());
    let last = u32::from(net.broadcast());
    let first_host = if net.prefix_len() <= 30 {
        first.saturating_add(1)
    } else {
        first
    };
    let last_host = if net.prefix_len() <= 30 {
        last.saturating_sub(1)
    } else {
        last
    };

    if first_host > last_host {
        return Vec::new();
    }

    let span = u64::from(last_host - first_host) + 1;
    if options.all_hosts {
        let count = count_for_unbounded_hosts(span, options.max_targets);
        return (0..count)
            .map(|offset| IpAddr::V4(Ipv4Addr::from(first_host + offset as u32)))
            .collect();
    }

    let offset = proportional_offset(0, 1, u128::from(span)).min(u128::from(span - 1)) as u64;
    vec![IpAddr::V4(Ipv4Addr::from(first_host + offset as u32))]
}

fn sample_ipv6(net: Ipv6Net, options: &ReadOptions) -> Vec<IpAddr> {
    if net.prefix_len() == 128 {
        return vec![IpAddr::V6(net.addr())];
    }

    let base = u128::from(net.network());
    let host_bits = 128 - net.prefix_len();
    let span = if host_bits == 128 {
        u128::MAX
    } else {
        1_u128 << host_bits
    };
    if options.all_hosts && net.prefix_len() >= 127 {
        let count = count_for_unbounded_hosts_u128(span, options.max_targets);
        return (0..count)
            .map(|offset| IpAddr::V6(Ipv6Addr::from(base.saturating_add(offset))))
            .collect();
    }

    let offset = proportional_offset(0, 1, span).min(span - 1);
    vec![IpAddr::V6(Ipv6Addr::from(base.saturating_add(offset)))]
}

fn proportional_offset(index: usize, count: usize, span: u128) -> u128 {
    let numerator = index as u128 + 1;
    let denominator = count as u128 + 1;
    let whole = span / denominator;
    let remainder = span % denominator;

    numerator * whole + numerator * remainder / denominator
}

fn has_reached_target_limit(current: usize, max_targets: usize) -> bool {
    max_targets > 0 && current >= max_targets
}

fn count_for_unbounded_hosts(span: u64, max_targets: usize) -> u64 {
    let cap = if max_targets == 0 {
        usize::MAX as u64
    } else {
        max_targets as u64
    };
    span.min(cap)
}

fn count_for_unbounded_hosts_u128(span: u128, max_targets: usize) -> u128 {
    let cap = if max_targets == 0 {
        usize::MAX as u128
    } else {
        max_targets as u128
    };
    span.min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn options() -> ReadOptions {
        ReadOptions {
            default_port: 443,
            input_format: InputFormat::Auto,
            all_hosts: false,
            max_targets: 100,
        }
    }

    #[test]
    fn parses_ipv4_with_default_port() {
        let targets = parse_text(b"1.1.1.1\n", &options()).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].ip, IpAddr::from_str("1.1.1.1").unwrap());
        assert_eq!(targets[0].port, 443);
    }

    #[test]
    fn parses_ipv4_with_explicit_port() {
        let targets = parse_text(b"104.16.132.229:8443\n", &options()).unwrap();

        assert_eq!(targets[0].ip, IpAddr::from_str("104.16.132.229").unwrap());
        assert_eq!(targets[0].port, 8443);
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        let targets = parse_text(b"[2606:4700:4700::1111]:443\n", &options()).unwrap();

        assert_eq!(
            targets[0].ip,
            IpAddr::from_str("2606:4700:4700::1111").unwrap()
        );
        assert_eq!(targets[0].port, 443);
    }

    #[test]
    fn parses_cidr_sample() {
        let targets = parse_text(b"192.0.2.0/24\n", &options()).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].prefix, Some("192.0.2.0/24".to_string()));
    }

    #[test]
    fn parses_own_target_json_output() {
        let input = br#"[
            {
                "ip": "156.255.123.3",
                "port": 443,
                "source": "156.255.123.0/24",
                "asn": 13335,
                "name": null,
                "prefix": "156.255.123.0/24"
            }
        ]"#;

        let targets = parse_json(input, &options()).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].ip, IpAddr::from_str("156.255.123.3").unwrap());
        assert_eq!(targets[0].port, 443);
        assert_eq!(targets[0].asn, Some(13335));
        assert_eq!(targets[0].source, "156.255.123.0/24");
        assert_eq!(targets[0].prefix, Some("156.255.123.0/24".to_string()));
    }

    #[test]
    fn parses_own_target_csv_output() {
        let input = b"ip,port,source,asn,name,prefix\n156.255.123.3,443,156.255.123.0/24,13335,,156.255.123.0/24\n";

        let targets = parse_csv(input, &options()).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].ip, IpAddr::from_str("156.255.123.3").unwrap());
        assert_eq!(targets[0].port, 443);
        assert_eq!(targets[0].asn, Some(13335));
        assert_eq!(targets[0].source, "156.255.123.0/24");
        assert_eq!(targets[0].prefix, Some("156.255.123.0/24".to_string()));
    }

    #[test]
    fn auto_detects_target_csv_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            "ip,port,source,asn,name,prefix\n1.1.1.1,443,fixture,,,\n"
        )
        .unwrap();

        let targets = read_targets(file.path(), &options()).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].ip, IpAddr::from_str("1.1.1.1").unwrap());
        assert_eq!(targets[0].source, "fixture");
    }

    #[test]
    fn all_hosts_expands_small_ipv4_prefix() {
        let mut options = options();
        options.all_hosts = true;
        let targets = parse_text(b"192.0.2.0/30\n", &options).unwrap();

        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn all_hosts_expands_large_ipv4_prefix_until_max_targets() {
        let mut options = options();
        options.all_hosts = true;
        options.max_targets = 100;
        let targets = parse_text(b"192.0.0.0/22\n", &options).unwrap();

        assert_eq!(targets.len(), 100);
        assert_eq!(targets[0].ip, IpAddr::from_str("192.0.0.1").unwrap());
        assert_eq!(targets[99].ip, IpAddr::from_str("192.0.0.100").unwrap());
    }

    #[test]
    fn zero_max_targets_disables_target_cap() {
        let mut options = options();
        options.all_hosts = true;
        options.max_targets = 0;
        let targets = parse_text(b"192.0.2.0/30\n192.0.2.4/30\n", &options).unwrap();

        assert_eq!(targets.len(), 4);
    }

    #[test]
    fn deterministic_sample_stays_inside_small_ipv6_prefix() {
        let options = options();
        let targets = parse_text(b"2001:db8::/127\n", &options).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].ip, IpAddr::from_str("2001:db8::1").unwrap());
    }

    #[test]
    fn wide_ipv6_sample_does_not_overflow() {
        let options = options();
        let targets = parse_text(b"::/0\n", &options).unwrap();

        assert_eq!(targets.len(), 1);
        assert!(targets.iter().all(|target| target.ip.is_ipv6()));
    }

    #[test]
    fn all_hosts_expands_ipv6_point_to_point_prefix() {
        let mut options = options();
        options.all_hosts = true;
        let targets = parse_text(b"2001:db8::/127\n", &options).unwrap();

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].ip, IpAddr::from_str("2001:db8::").unwrap());
        assert_eq!(targets[1].ip, IpAddr::from_str("2001:db8::1").unwrap());
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let targets = parse_text(b"\n# comment\n1.0.0.1 # resolver\n", &options()).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].ip, IpAddr::from_str("1.0.0.1").unwrap());
    }

    #[test]
    fn reports_invalid_lines() {
        let error = parse_text(b"not-an-ip\n", &options())
            .unwrap_err()
            .to_string();

        assert!(error.contains("line 1"));
    }

    #[test]
    fn target_batch_iter_expands_large_prefix_without_global_cap() {
        let mut options = options();
        options.all_hosts = true;
        options.max_targets = 0;
        let inputs = vec![TargetInput {
            value: "10.0.0.0/8".to_string(),
            source: None,
            asn: Some(64500),
            name: Some("large".to_string()),
            prefix: None,
        }];
        let mut batches = target_batches_from_inputs(inputs, &options, 3).unwrap();

        let first = batches.next().unwrap().unwrap();
        let second = batches.next().unwrap().unwrap();

        assert_eq!(first.len(), 3);
        assert_eq!(second.len(), 3);
        assert_eq!(first[0].ip, IpAddr::from_str("10.0.0.1").unwrap());
        assert_eq!(second[2].ip, IpAddr::from_str("10.0.0.6").unwrap());
        assert_eq!(first[0].prefix, Some("10.0.0.0/8".to_string()));
        assert_eq!(first[0].asn, Some(64500));
    }

    #[test]
    fn target_batch_iter_dedupes_even_without_global_cap() {
        let mut options = options();
        options.max_targets = 0;
        let inputs = vec![
            TargetInput {
                value: "1.1.1.1".to_string(),
                source: Some("first".to_string()),
                asn: None,
                name: None,
                prefix: None,
            },
            TargetInput {
                value: "1.1.1.1".to_string(),
                source: Some("duplicate".to_string()),
                asn: None,
                name: None,
                prefix: None,
            },
            TargetInput {
                value: "1.1.1.2".to_string(),
                source: Some("second".to_string()),
                asn: None,
                name: None,
                prefix: None,
            },
        ];

        let batch = target_batches_from_inputs(inputs, &options, 10)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();

        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].source, "first");
        assert_eq!(batch[1].ip, IpAddr::from_str("1.1.1.2").unwrap());
    }

    #[test]
    fn reads_large_prefix_as_stream_input_without_expanding_hosts() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "10.0.0.0/8").unwrap();

        let inputs = read_target_inputs(file.path(), &options()).unwrap();

        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].value, "10.0.0.0/8");
    }

    #[test]
    fn converts_csv_records_to_target_inputs_without_losing_source() {
        let input = b"ip,port,source,asn,name,prefix\n2606:4700:4700::1111,8443,fixture,13335,Cloudflare,2606:4700::/32\n";

        let inputs = parse_csv_inputs(input, &options()).unwrap();

        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].value, "[2606:4700:4700::1111]:8443");
        assert_eq!(inputs[0].source, Some("fixture".to_string()));
        assert_eq!(inputs[0].asn, Some(13335));
    }
}
