# Anycast Scout CLI

Rust CLI for discovering, probing, and ranking anycast edge IP candidates. It
is the backend used by the Anycast Scout desktop GUI and can also run as a
standalone command-line tool.

| Area | Details |
| --- | --- |
| Discovery | ASN/BGP prefix collection from RIPEstat and bgp.tools |
| Validation | HTTP/TLS probe, minimum download check, optional speed test |
| Outputs | CSV target and scan artifacts, JSON sing-box URLTest results |
| Releases | Native Linux, macOS, and Windows binaries from CI |

## Install

```bash
cargo build --release --locked
./target/release/anycast-scout --help
```

Optional local install:

```bash
mkdir -p "$HOME/.local/bin"
install -m 755 target/release/anycast-scout "$HOME/.local/bin/anycast-scout"
export PATH="$HOME/.local/bin:$PATH"
```

## Use

Discover Cloudflare-related candidate targets:

```bash
anycast-scout discover \
  --asn AS13335 \
  --asn AS209242 \
  --asn AS14789 \
  --asn AS395747 \
  --asn AS394536 \
  --discovery-scope origin-and-as-path \
  --all-hosts \
  --max-targets 0 \
  --output cf-edge-targets.csv
```

Scan and rank candidates:

```bash
anycast-scout scan \
  --input cf-edge-targets.csv \
  --input-format csv \
  --speed-url 'https://speed.cloudflare.com/__down?bytes=10000000' \
  --speed-seconds 3 \
  --download-url 'https://speed.cloudflare.com/__down?bytes=20480' \
  --min-download-bytes 20480 \
  --max-valid 100 \
  --output cf-edge-selected.csv
```

When a sing-box outbound hostname/path is known, `scan` can run a domain-aware
prefilter before URLTest confirmation: direct `HTTP` to the candidate IP must
return Cloudflare error `1003`, then `HTTPS` to the selected outbound
hostname/path through that same IP must avoid rejected Cloudflare errors such
as `1034`, before the usual minimum-download check runs.

Validation flow:
`discover targets -> direct HTTP to candidate IP -> expect Cloudflare 1003 -> HTTPS to outbound hostname/path through the same IP -> reject Cloudflare 1034 -> minimum download check -> optional speed test -> sing-box URLTest confirmation`

Run a sing-box URLTest with your own JSON config:

```bash
anycast-scout sing-box-urltest \
  --config /path/to/sing-box-config.json \
  --candidate-ip 1.1.1.1 \
  --outbound-tag 'Your outbound tag' \
  --min-download-bytes 20480
```

This repository does not ship sing-box credentials or ready-to-use sing-box
configs. Keep private configs outside version control; local `config.json`,
`.env*`, and sing-box-style JSON files are ignored by default.

## Tune

Discovery tuning is intentionally environment-based:

| Variable | Purpose |
| --- | --- |
| `ANYCAST_SCOUT_DISCOVERY_USER_AGENT` | HTTP user agent for discovery providers |
| `ANYCAST_SCOUT_DISCOVERY_REQUEST_INTERVAL_MS` | provider request spacing |
| `ANYCAST_SCOUT_RIPESTAT_MIN_PEERS_SEEING` | RIPEstat visibility threshold |
| `ANYCAST_SCOUT_BGP_TOOLS_MIN_HITS` | bgp.tools hit threshold |
| `ANYCAST_SCOUT_DISCOVERY_CACHE_DIR` | local discovery cache directory |
| `ANYCAST_SCOUT_BGP_TOOLS_CACHE_TTL_MINUTES` | bgp.tools cache TTL |
| `ANYCAST_SCOUT_REFRESH_DISCOVERY_CACHE` | force cache refresh when set |

## Verify

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

## Release

Release pipelines run verification, create the next semver release, publish
native archives, verify checksums, and trigger the GUI release pipeline with the
backend commit SHA when configured in CI.
