# Validation Resources and Limits

## Validation Model

Scan validation is a Cloudflare edge prefilter, not the final sing-box compatibility proof. It checks whether a candidate IP can serve Cloudflare-controlled hostnames with expected status/body markers and Cloudflare headers, then requires a small download before marking the scan result valid. Final compatibility for a Pingle CDN outbound is still verified with `sing-box-urltest`, which requires both the sing-box delay endpoint and a proxied download check.

When `scan` is given `--edge-hostname`, it uses a faster domain-aware prefilter instead of the generic Cloudflare resource pool. In that mode, the candidate IP must first return Cloudflare error `1003` on direct `HTTP`, then the selected hostname routed through that IP must avoid rejected Cloudflare error codes such as `1034`, before the download check runs.

Third-party API hosts are intentionally not part of the scanner resource pool. Their quotas and application behavior can change independently from Cloudflare edge reachability, so the scanner now keeps the built-in Cloudflare resource set fixed.

## Cloudflare Documentation Notes

- Cloudflare documents Error 1003 as direct IP access to a Cloudflare IP address.
- Cloudflare documents `https://<hostname>/cdn-cgi/trace` as a way to identify the Cloudflare data center serving a request.
- Cloudflare WARP docs use `https://www.cloudflare.com/cdn-cgi/trace` for connectivity verification.
- Cloudflare API limits are documented as 1,200 requests per five minutes per user/account token and 200 requests per second per IP. `anycast-scout` does not call the Cloudflare API for scanning, but the same conservative pacing model is used for public validation traffic.
- Cloudflare does not publish a specific public quota for the `cdn-cgi/trace`, `cp.cloudflare.com/generate_204`, or `speed.cloudflare.com/__down` validation URLs in the docs reviewed here. Treat them as shared public resources and keep scans paced.
- httpbin-style `/bytes/:n` endpoints are useful for final proxy-path compatibility because they return a caller-selected number of bytes. The built-in sing-box check defaults to `https://httpbin.org/bytes/20480`; scan validation defaults to Cloudflare's `speed.cloudflare.com` download endpoint because scan requests resolve the URL hostname directly to the candidate edge IP.

Sources:

- https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1003/
- https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/
- https://developers.cloudflare.com/warp-client/get-started/linux/
- https://developers.cloudflare.com/fundamentals/api/reference/limits/
## Built-In Cloudflare Preset

The built-in scanner preset currently includes:

| Name | URL | Expected result through a candidate Cloudflare IP |
| --- | --- | --- |
| `cloudflare-trace` | `https://cloudflare.com/cdn-cgi/trace` | `200`, Cloudflare headers, body contains `colo=` |
| `cloudflare-dns-trace` | `https://cloudflare-dns.com/cdn-cgi/trace` | `200`, Cloudflare headers, body contains `colo=` |
| `www-cloudflare-marker` | `https://www.cloudflare.com/cdn-cgi/trace` | `403`, Cloudflare headers |
| `cp-generate-204` | `https://cp.cloudflare.com/generate_204` | `204`, Cloudflare headers |
| `cp-root-204` | `https://cp.cloudflare.com/` | `204`, Cloudflare headers |
| `speed-marker` | `https://speed.cloudflare.com/__down?bytes=1000` | `403`, Cloudflare headers |

The `403` resources are still useful as edge markers: the scanner is not trying to fetch page content, it is verifying that the selected IP accepts the hostname/TLS route and returns a Cloudflare-controlled response.

After a marker resource succeeds, scan validation downloads at least `--min-download-bytes` bytes from `--download-url` before `valid=true`. Defaults:

- `--download-url https://speed.cloudflare.com/__down?bytes=20480`
- `--min-download-bytes 20480`
- `--download-timeout-ms 5000`

Set `--min-download-bytes 0` to restore marker-only scan validation.

The `sing-box-urltest` command performs the regular Clash API delay check and then downloads at least `--min-download-bytes` through a temporary local mixed inbound routed to the patched outbound. Its default download URL is `https://httpbin.org/bytes/20480`, which is deliberately not Cloudflare-specific because this stage tests the actual outbound path rather than direct host resolution to a candidate edge IP.

For each target, the scanner rotates the starting resource by hashing `IP:PORT`. This spreads the first validation request across the pool while keeping results reproducible. If the first resource does not validate, the scanner continues through the remaining resources in rotated order until one validates or the pool is exhausted.

## Local Validation Run

On 2026-04-23, each resource above was checked from this workspace by resolving its hostname to `104.16.132.229`. All resources returned the expected Cloudflare marker behavior.

## Pacing

The scanner starts requests through a single global limiter. Defaults:

- `--request-interval-ms 250`
- `--concurrency 16`
- speed checks are disabled unless explicitly requested

For large scans, lower concurrency does not reduce the global start rate by itself; `--request-interval-ms` is the main control. A practical polite baseline is `--request-interval-ms 500` or higher.
