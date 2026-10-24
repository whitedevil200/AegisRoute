# AegisRoute 3.2: Evidence and enterprise integrations

These features are optional. A normal AegisRoute trace does not create remote
measurements, open an agent listener, send OpenTelemetry data, or inject IOAM.

## Evidence, privacy, and release assurance

`--measurement-record FILE` emits the portable per-hop record used for replay
and evidence retention. `--privacy standard|strict` redacts the emitted report;
keep a non-redacted source record only in an access-controlled evidence store.
`--monitor-baseline N --store DB` summarizes recent observations with
P50/P95/P99 values and explicitly does not equate intermediate ICMP reply loss
with application packet loss.

`--alert-state FILE --alert-cooldown SECONDS` makes scheduled alerts
deterministically deduplicated. Do not share alert state between unrelated
environments. `aegisroute --sbom FILE` writes a CycloneDX 1.5 SBOM; publish it
alongside checksums and your organization’s signing/provenance evidence.

`--globalping` is a transparent distributed-measurement preview. Submission
requires `--approve-globalping`, and remains one bounded traceroute request.
`--hubble-flows` and `--integrity-observation` import operator-exported JSON
only: they never load eBPF, access a cluster, or send crafted mutation probes.

## Measurement profiles and confidence

`--profile fast|balanced|forensic|low-impact` applies a documented probe
budget. Use `custom` to preserve the individual probe settings. Reports expose
`measurement_confidence`, which describes observation completeness; it is not a
claim about service health or security.

## Control-plane timeline

`--bgp-events` fetches bounded historical control-plane evidence. Add
`--ris-live-seconds 30` to collect a short, optional real-time RIS Live sample.
RIS Live requires `pip install websockets`; failures are reported in the JSON
report and do not invalidate the data-plane measurement.

```bash
aegisroute example.com --bgp-events --ris-live-seconds 30 --format html -o report.html
```

The `evidence_timeline` is temporal correlation only. It must never be read as
proof that a BGP update caused a data-plane change.

## RIPE Atlas: preview before cost approval

This prints the exact request and does not spend credits:

```bash
aegisroute example.com --atlas-create --atlas-probes 5 --atlas-countries IN,US
```

Creation requires both an API key and explicit acknowledgement:

```bash
export AEGISROUTE_ATLAS_API_KEY='...'
aegisroute example.com --atlas-create --atlas-probes 5 --approve-atlas-cost
```

RIPE Atlas determines credits server-side. Review the preview and use a small,
authorized probe selection. Recurring measurements require `--atlas-interval`.

## Remote agent

The agent only serves an existing report; it never accepts measurement commands.
Use loopback behind a reverse proxy for simple deployments. For direct remote
use, provide a server certificate/key and a client CA to require mutual TLS.

```bash
export AEGISROUTE_AGENT_TOKEN='long-random-token'
export AEGISROUTE_AGENT_SIGNING_KEY='separate-long-random-secret'
aegisroute-agent --report /var/lib/aegisroute/latest.json \
  --listen 127.0.0.1 --allowed-cidr 203.0.113.0/24 --requests-per-minute 20
```

Signed responses carry `X-AegisRoute-Timestamp` and an HMAC-SHA256 signature.
Use `--require-nonce` to reject replayed report requests; the nonce is bound to
the signed response. Collectors should reject old timestamps and verify both
the nonce and signature.
For mTLS, add `--tls-cert`, `--tls-key`, and `--tls-ca`. Non-loopback binding
is rejected unless TLS is configured.

## Incident bundle, OTLP, and IOAM import

```bash
export AEGISROUTE_SIGNING_KEY='bundle-secret'
aegisroute example.com --bundle incident.zip --signing-key "$AEGISROUTE_SIGNING_KEY"
aegisroute example.com --otel-endpoint https://otel.example.net
aegisroute private.example --ioam-input operator-authorized-ioam.json
```

Bundles contain JSON, standalone HTML, SHA-256 manifest entries, and an optional
HMAC signature. OTLP uses compact, bounded-cardinality route attributes. IOAM is
strictly an operator-supplied JSON import; AegisRoute never injects IOAM packets
into a public network.
