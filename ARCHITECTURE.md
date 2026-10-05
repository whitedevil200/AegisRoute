# AegisRoute 3.0 architecture

AegisRoute separates packet measurement from interpretation. The native backend delegates classic probes to the operating system's `traceroute` or Windows `tracert`; the optional Scamper backend performs Paris-style flow-stable traces and genuine Multipath Detection Algorithm (MDA) discovery. Both are normalized into one `Trace → Hop → Responder` model.

The asynchronous enrichment stage classifies special-use addresses locally, then applies only requested public-data modules: PTR DNS, Team Cymru ASN/prefix, ipwho.is geography, RIPEstat RPKI/routing visibility, and PeeringDB IXP LAN matching. `--no-enrich` bypasses this stage completely.

The analysis stage calculates hop loss and latency distributions, detects multipath, possible loops, route divergence, latency changes, and incomplete paths, and attaches confidence, supporting evidence, and plausible alternative explanations. Findings are diagnostic hypotheses, not vulnerability claims.

The fusion graph merges responder nodes and transitions observed by every protocol or Atlas probe. JSON is the canonical lossless report; table and CSV are views, Prometheus is a latest-measurement export, and SQLite WAL storage retains reports plus indexed findings and route fingerprints.

RIPE Atlas import is read-only and fetches an existing public measurement. It neither creates measurements nor consumes credits. Each probe result becomes a distinct trace and participates in the same fusion graph.

## Trust boundaries

- Target input is resolved with the system resolver and passed to subprocesses as an argument array, never through a shell.
- External enrichment is opt-in by module; private and special-use addresses are not submitted to public enrichment APIs.
- Scamper is optional and must be installed separately. Selecting Paris or MDA fails clearly when it is absent; AegisRoute never labels a classic trace as MDA.
- SQLite parameters are bound, report files are atomically replaced, and active-probe limits are validated.
- Monitoring templates run as a dedicated unprivileged account with a read-only filesystem except for the Prometheus textfile directory.

## Data contracts

AegisRoute 3.0 adds four correlation stages after normalization: historical comparison against the newest SQLite report, optional RIPEstat BGP update correlation, service/TLS diagnostics, and multi-vantage fusion from files, HTTPS agents, or multiple Atlas measurements. Quality scoring records the limitations of the measurement rather than hiding them.

The remote agent is deliberately read-only: it serves an atomically updated report and never accepts a target or executes a probe from an HTTP request. Bearer authentication is available, it binds to loopback by default, and remote collection requires HTTPS. Deployment should terminate TLS in a reverse proxy.

Scamper Ally alias testing is only launched with `--alias-resolve`, is capped by `--alias-max-pairs`, and records `confirmed`, `rejected`, or `inconclusive`. Same-AS or same-TTL proximity only selects candidates; it is not itself alias evidence. External TNT output can be imported, but AegisRoute never claims to reveal hidden MPLS routers by observing no labels.

`aegisroute/v3` reports include settings, normalized traces, evidence-backed findings, `fusion_graph`, `quality`, MPLS analysis, and enabled correlation modules. Trace metadata records the real backend and strategy. Atlas imports use the same schema. SQLite is an implementation detail; integrations should consume JSON, HTML, or Prometheus output.
