use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

pub const DEFAULT_DOWNLOAD_BYTES: u64 = 20 * 1024;
pub const DEFAULT_SCAN_DOWNLOAD_URL: &str = "https://speed.cloudflare.com/__down?bytes=20480";

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about,
    after_help = "Use `discover`, `scan`, and `sing-box-urltest` to run backend workflows."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Discover candidate IP targets from ASN/BGP sources without probing them.
    Discover(Box<DiscoverArgs>),
    /// Scan candidate Cloudflare edge IPs.
    Scan(Box<ScanArgs>),
    /// Patch a sing-box CDN outbound with an IP and run a headless urltest.
    SingBoxUrltest(Box<SingBoxUrltestArgs>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum InputFormat {
    Auto,
    Text,
    Csv,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DiscoveryProviderArg {
    /// RIPEstat announced-prefixes API.
    Ripestat,
    /// bgp.tools table.jsonl export, cached locally.
    BgpTools,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
pub enum DiscoveryScopeArg {
    /// Prefixes originated by the selected ASN.
    Origin,
    /// Prefixes where the selected ASN appears in the AS_PATH but is not the origin.
    AsPath,
    /// Prefixes originated by the selected ASN plus AS_PATH transit/customer prefixes.
    OriginAndAsPath,
}

#[derive(Debug, Args, Clone)]
pub struct TargetExpansionArgs {
    /// Default port for targets that omit a port.
    #[arg(long, default_value_t = 443)]
    pub port: u16,

    /// Enumerate every IPv4 host from CIDR prefixes, capped by --max-targets. IPv6 remains sampled except /127 and /128.
    #[arg(long)]
    pub all_hosts: bool,

    /// Maximum number of targets produced by parsing or discovery. Use 0 for no cap.
    #[arg(long, default_value_t = 10000)]
    pub max_targets: usize,
}

#[derive(Debug, Args, Clone)]
pub struct DiscoveryArgsShared {
    /// ASN to discover. Accepts 13335 or AS13335. Can be repeated.
    #[arg(long)]
    pub asn: Vec<String>,

    /// ASN relationship scope used to discover prefixes.
    #[arg(long = "discovery-scope", value_enum, default_value_t = DiscoveryScopeArg::Origin)]
    pub discovery_scope: DiscoveryScopeArg,
}

#[derive(Debug, Args)]
pub struct DiscoverArgs {
    #[command(flatten)]
    pub discovery: DiscoveryArgsShared,

    #[command(flatten)]
    pub expansion: TargetExpansionArgs,

    /// Output path. When omitted, targets are written to stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// File with one IP, IP:PORT, CIDR, or supported JSON records. Can be repeated. Use "-" for stdin.
    #[arg(short, long)]
    pub input: Vec<PathBuf>,

    #[command(flatten)]
    pub discovery: DiscoveryArgsShared,

    /// Input format.
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    pub input_format: InputFormat,

    /// Output path. When omitted, results are written to stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Append to an existing output CSV and skip targets already present there.
    #[arg(long)]
    pub resume: bool,

    #[command(flatten)]
    pub expansion: TargetExpansionArgs,

    /// Maximum concurrent probes.
    #[arg(short = 'c', long, default_value_t = 16)]
    pub concurrency: usize,

    /// Global delay between request starts.
    #[arg(long, default_value_t = 250)]
    pub request_interval_ms: u64,

    /// Stop scanning after this many valid candidates are found. Applied between batches.
    #[arg(long)]
    pub max_valid: Option<usize>,

    /// Per-request timeout.
    #[arg(long, default_value_t = 2500)]
    pub timeout_ms: u64,

    /// Optional speed-test URL. Its hostname is resolved to the candidate IP.
    #[arg(long)]
    pub speed_url: Option<String>,

    /// Maximum seconds for each speed test. Zero disables speed tests.
    #[arg(long, default_value_t = 0)]
    pub speed_seconds: u64,

    /// URL used for minimum download validation. Its hostname is resolved to the candidate IP.
    #[arg(long, default_value = DEFAULT_SCAN_DOWNLOAD_URL)]
    pub download_url: Option<String>,

    /// Require this many bytes to be downloaded before a scan result is valid. Use 0 to disable.
    #[arg(long, default_value_t = DEFAULT_DOWNLOAD_BYTES)]
    pub min_download_bytes: u64,

    /// Timeout for minimum download validation.
    #[arg(long, default_value_t = 5000)]
    pub download_timeout_ms: u64,

    /// Optional hostname routed through the candidate IP before generic validation. When set, scan first requires direct HTTP to the IP to return one of --edge-direct-error-codes, then requires HTTPS to this hostname to avoid --edge-reject-error-codes.
    #[arg(long)]
    pub edge_hostname: Option<String>,

    /// Path requested on --edge-hostname. Defaults to "/".
    #[arg(long, default_value = "/")]
    pub edge_path: String,

    /// Cloudflare error codes accepted from direct HTTP access to the candidate IP.
    #[arg(long, value_delimiter = ',', default_value = "1003")]
    pub edge_direct_error_codes: Vec<u16>,

    /// Cloudflare error codes accepted from the HTTPS request to --edge-hostname even when the HTTP status is otherwise non-successful.
    #[arg(long, value_delimiter = ',')]
    pub edge_accept_error_codes: Vec<u16>,

    /// Cloudflare error codes that immediately reject the HTTPS request to --edge-hostname.
    #[arg(long, value_delimiter = ',', default_value = "1034")]
    pub edge_reject_error_codes: Vec<u16>,

    /// HTTP user agent.
    #[arg(long, default_value = "anycast-scout/0.1")]
    pub user_agent: String,
}

#[derive(Debug, Args)]
pub struct SingBoxUrltestArgs {
    /// Local sing-box JSON config path or https:// URL.
    #[arg(short, long)]
    pub config: String,

    /// Candidate CDN IP to put into the selected outbound's server field.
    #[arg(long)]
    pub candidate_ip: IpAddr,

    /// CDN outbound tag to copy and patch.
    #[arg(long, default_value = "🇩🇪 Germany CDN 1")]
    pub outbound_tag: String,

    /// Require this many bytes through sing-box before the candidate is considered OK. Use 0 to disable.
    #[arg(long, default_value_t = DEFAULT_DOWNLOAD_BYTES)]
    pub min_download_bytes: u64,

    /// sing-box executable path, or 'auto' to download the latest stable GitHub release.
    #[arg(long, default_value = "auto")]
    pub sing_box_bin: String,

    /// Output path. When omitted, JSON is written to stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}
