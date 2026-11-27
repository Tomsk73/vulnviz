# vulnviz

Analyse and compare how Linux distributions remediate CVEs: fixes shipped per
month by severity, time from CVE publication to fix, how that time is
distributed, and what is still open. Data comes from the CVE Program's record
list (cve.org) and each distribution's OSV advisory feed. It runs as a
multi-service Kubernetes app backed by PostgreSQL.

```
                 ┌────────────────────────┐   ┌─────────────────────────────────┐
  cve.org  ─────▶│ ingest (Job / CronJob) │──▶│ PostgreSQL (StatefulSet)        │
  OSV feeds ────▶│  parse → COPY → merge  │   │  cves, advisories, fact_*, agg_*│
                 │  → rebuild fact tables │   └───────────────▲─────────────────┘
                 └────────────────────────┘                   │ SQL
                                                  ┌───────────┴──────────┐
  browser ──▶ web (nginx + React SPA) ──/api/──▶ │ api (Go, REST + cache)│
                                                  └──────────────────────┘
```

## What it shows

| View | Question it answers | Source tables |
|---|---|---|
| Hero ranking | Median (and p90) days to fix a CVE per distribution for the selected range and severity | `fact_fixes_cve` / `fact_fixes_pkg` |
| Fixes per month | How many CVEs (or package fixes) each distribution shipped, stacked by severity, as small multiples | `agg_monthly` or live |
| Time to remediate by month | Median / p25 / p75 / p90 / mean days to fix, one line per distribution | `agg_monthly` or live |
| How long fixes take | Share of fixes landing within 1 day, 1 week, 30 days, 90 days, 1 year, longer | live |
| Open CVEs right now | Unfixed CVEs per distribution by age and by severity | `fact_open` |
| CVEs published per month | The upstream volume everyone is working against, by severity | `agg_cves_monthly` |
| Browse CVEs | Which CVEs are behind a number: every CVE a distribution fixed or still lists, narrowed by days to fix or days open, severity, package or CVE ID. For example, the CVEs Debian took 90 days or more to fix, or the ones Ubuntu has had open for over a year | `fact_fixes_cve` / `fact_fixes_pkg`, `fact_open` |
| CVE lookup | One CVE: when each distribution fixed it, where it is still open | `cves`, facts |
| How each feed is read | The rule applied to each feed and the counts it produced | `distros`, `ingest_runs` |

Filters (date range, distributions, severity, release/ecosystem, CVE scope,
unit, month basis) live in the URL and scope every chart. Every chart has a
table view and tooltips; dark mode follows the OS.

Selecting a bar in "Fixes per month", "How long fixes take" or "Open CVEs
right now" opens the browser on the CVEs that bar counted, and the list always
totals to the bar. The browser's own state (status, distribution, severity,
days range, search, sort, page) is kept in the URL as `b_*` parameters, so a
list can be shared like any other view. It narrows the page-wide filters and
follows the same rules as the charts: fixed CVEs are scoped by the date range,
open CVEs are a snapshot the date range does not apply to, and only fixes with
a real fix date have a duration to filter on.

## Data sources

| Dataset | Source | Format | Size |
|---|---|---|---|
| CVE records | [cve.org downloads](https://www.cve.org/Downloads) → `CVEProject/cvelistV5` GitHub release `*_all_CVEs_at_midnight.zip.zip` | CVE Record Format 5.x | ~660 MB, ~425k records |
| Chainguard | OSV.dev bundle `Chainguard/all.zip` (bulk), [advisories.cgr.dev v3 index](https://advisories.cgr.dev/chainguard/v3/osv/all.json) plus per-ID documents (incremental) | OSV | 1.2 GB, ~1.37M advisories |
| Echo | OSV.dev bundle `Echo/all.zip` (bulk), [advisory.echohq.com index](https://advisory.echohq.com/osv/all.json) (incremental) | OSV | 7 MB, ~13k |
| Docker Hardened Images | OSV.dev bundle `Docker Hardened Images/all.zip` (mirrors `dhi/osv` in [docker-hardened-images/advisories](https://github.com/docker-hardened-images/advisories)) | OSV | 12 MB, ~4.5k |
| Red Hat | OSV.dev bundle `Red Hat/all.zip` (mirrors security.access.redhat.com/data/osv) | OSV | 28 MB, ~24k errata |
| Ubuntu | OSV.dev bundle `Ubuntu/all.zip` (mirrors canonical/ubuntu-security-notices OSV) | OSV | 815 MB, ~74k |
| Debian | OSV.dev bundle `Debian/all.zip` (DSA/DLA/DTSA plus tracker records) | OSV | 82 MB, ~74k |
| Alpine | OSV.dev bundle `Alpine/all.zip` (disabled by default, see notes) | OSV | 9 MB |

The direct `all.json` feeds from Chainguard and Echo are indexes of
`{id, modified}` pairs, not full records, so bulk loads use the OSV.dev zip
bundles and the direct feeds drive incremental refresh (only advisories whose
`modified` moved are re-fetched). Adding a distribution is a stanza in
`configs/sources.yaml`; any OSV.dev ecosystem works out of the box.

### How fix times are derived

Every distribution publishes OSV, but `published` does not mean the same thing
everywhere. The rules in `configs/sources.yaml` encode what was found by
inspecting the data (November 2026):

| Distribution | Fix time | Timed records | Why |
|---|---|---|---|
| Chainguard | per-component `latest_event_timestamp` where status is `fixed` | all CGA | Exact event time; `published` is when the advisory was opened. Wolfi duplicates of each advisory are dropped. |
| Red Hat | advisory `published` | errata whose published year matches the year in the ID | Errata up to 2023 were backfilled into the OSV feed in September 2024 with that date as `published`. |
| Ubuntu | advisory `published` | USN, LSN | UBUNTU-CVE tracker records carry the CVE's own date. |
| Debian | advisory `published` | DSA, DLA, DTSA | DEBIAN-CVE tracker records carry the CVE's own date. |
| Echo | advisory `published` | none | For over 90% of records `published` is within a day of the CVE's publication, so it marks when tracking began, not the fix. |
| Docker Hardened Images | advisory `published` | none | The feed began on 9 November 2026 and `published` is when a record entered it, a median of about 90 days after the CVE's publication for records that list a fix. Fixes carry no timestamp of their own. |
| Alpine | advisory `published` | none | secdb has no dates; OSV records carry the CVE's date. |

Untimed records still count towards "CVEs with a fix", release coverage, the
backlog and the by-CVE-month views; they are excluded wherever a duration is
computed. The per-distribution notes on the dashboard repeat this.

Other conventions:

- **Severity** is the CVE record's own CVSS rating: CNA 3.1, then 3.0, 4.0,
  then CISA ADP, then CVSS 2; else the distribution's stated severity (CVSS
  vector, Debian urgency, Ubuntu priority); else "unrated". Scores from
  vectors without a numeric score are computed (CVSS 3.x and 2.0).
- **A CVE counts as fixed** for a distribution the first time any advisory
  lists a `fixed` version for it. "CVEs" mode counts it once per distribution;
  "Package fixes" mode counts it once per package per release.
- **Time to remediate** is `first fix time − CVE datePublished` in days. It
  can be negative when the fix shipped before the CVE record was published.
- **CVE scope.** "CVEs published in range" (default) measures responsiveness
  to new CVEs. "Any CVE age" includes fixes for decade-old CVEs that land when a
  package is first added, which inflates medians (Chainguard January 2025 is
  a visible example).
- **Open CVEs** are (distribution, CVE, release, package) combinations with an
  advisory but no fixed version and no fix elsewhere for the same combination.
  Red Hat's OSV feed lists shipped errata only, so it has no backlog here.

## Repository layout

```
cmd/api            REST API server
cmd/ingest         ingestion CLI (cve | advisories | sync | aggregate | all | migrate)
internal/cve       CVE 5.x parsing            internal/osv      OSV parsing + distro rules
internal/cvss      CVSS scoring/buckets       internal/ingest   fetch, zip streaming, COPY loaders
internal/aggregate fact and roll-up rebuild    internal/api      handlers, queries, response cache
internal/db        connection + embedded SQL migrations
configs/sources.yaml   feeds and per-distro rules (copied into deploy/k8s/base for kustomize)
web/               Vite + React + TypeScript dashboard (hand-rolled SVG charts)
build/             Dockerfiles (Chainguard base images) and nginx.conf
deploy/compose.yaml    local stack;  deploy/k8s   kustomize base + kind/prod overlays
```

## Running locally

Prerequisites: Go 1.25+, Node 20+, Docker, and for the cluster path kind and kubectl.

```bash
make db-up                      # PostgreSQL on localhost:5433 (cgr.dev/chainguard/postgres)
make ingest-all                 # downloads ~3 GB of feeds, loads, aggregates (15-30 min)
make run-api                    # :8080
make run-web                    # :5173, proxies /api to :8080
```

To load from already-downloaded archives, point the config at local paths
(`bulk_url: /path/cves.zip.zip`, `bulk: {type: osv_zip, url: /path/all.zip}`)
and pass `-config`. Loading everything from local files takes about four
minutes on a laptop; the CVE list alone takes 15 seconds.

`ingest sync chainguard echo` performs an incremental refresh through the
index feeds; `ingest aggregate` rebuilds derived tables without fetching.

With Compose: `docker compose -f deploy/compose.yaml up --build`, then
`docker compose -f deploy/compose.yaml run --rm ingest all`; the UI is on
http://localhost:8000.

## Deploying to Kubernetes

```bash
make images                     # vulnviz-api:dev, vulnviz-ingest:dev, vulnviz-web:dev
make kind-up kind-load          # local cluster, port 30080 → localhost:8000
make kind-deploy                # applies deploy/k8s/overlays/kind
kubectl -n vulnviz logs -f job/vulnviz-ingest-bootstrap
```

The base kustomization creates:

- `vulnviz-db` StatefulSet (Chainguard PostgreSQL, 40 Gi PVC) and headless Service
- `vulnviz-api` Deployment (2 replicas, `/readyz` pings the database, applies migrations on start)
- `vulnviz-web` Deployment (nginx serving the SPA, proxying `/api/` to the API Service) and an Ingress
- `vulnviz-ingest-bootstrap` Job (full load) and two CronJobs: a daily full reload at 03:30 and a six-hourly incremental sync for feeds with an index
- a ConfigMap with `sources.yaml` and a Secret with the database credentials (replace the generated secret in your overlay)

All pods run as non-root with a read-only root filesystem and dropped
capabilities; the namespace enforces the `restricted` Pod Security Standard.
`deploy/k8s/overlays/prod` is the template for a real cluster: set the
registry, tags, ingress host and secret source.

Build arguments `GOPROXY`, `GONOSUMDB`, `GOFLAGS` and `NPM_CONFIG_REGISTRY` pass
through to the image builds so CI can point them at Chainguard Libraries or a
corporate proxy.

## API

All analytics endpoints share these query parameters: `distros` (comma list),
`from`/`to` (`YYYY-MM`, inclusive), `severity` (comma list of
critical|high|medium|low|none|unknown, or omit for each / `all` for a single
aggregate), `unit` (`cve`|`package`), `basis` (`fix_month`|`cve_month`),
`ecosystem` (exact release, or prefix with `*`), `scope` (`recent`|`all`).

| Endpoint | Returns |
|---|---|
| `GET /api/v1/distros` | distributions with rules, counts and last ingest |
| `GET /api/v1/fixes/monthly` | `{distro, month, severity, fixes}` |
| `GET /api/v1/mttr/monthly` | `{distro, month, severity, n, median, mean, p25, p75, p90}` |
| `GET /api/v1/mttr/summary` | the same without month, for the whole range |
| `GET /api/v1/mttr/distribution` | fix-time histogram buckets per distribution, each with its `min_days`/`max_days` |
| `GET /api/v1/backlog` | open CVEs per distribution × severity × age bucket, each with its `min_days`/`max_days` |
| `GET /api/v1/cves/monthly` | CVEs published per month by severity |
| `GET /api/v1/records` | one page of the CVEs behind the charts: `{rows, total, limit, offset}` |
| `GET /api/v1/ecosystems?distro=` | releases/ecosystems with fix counts |
| `GET /api/v1/cve/{id}` | CVE detail with per-distribution fixes and open packages |
| `GET /api/v1/status` | dataset counts and recent ingest runs |
| `GET /healthz`, `GET /readyz` | liveness, readiness |

`/api/v1/records` takes the shared parameters plus:

| Parameter | Meaning |
|---|---|
| `status` | `fixed` (default) or `open`. Open records ignore `from`/`to`, `basis` and `scope`, as the backlog does |
| `min_days`, `max_days` | days from the CVE's publication to the fix, or to now when open; `min_days` is inclusive, `max_days` exclusive. For fixed records this keeps only fixes with a real fix date |
| `undated` | `true` for CVEs with no publication date (the backlog's "no CVE date" bucket) |
| `month` | one `YYYY-MM` of the range, on the same `basis` as the charts; fixed records only |
| `q` | a CVE ID (exact once complete, a prefix before that) or part of a package name |
| `sort`, `order` | `days` (default), `published`, `fixed` or `severity`; `desc` (default) or `asc` |
| `limit`, `offset` | page size (default 50, at most 200) and start |

With `unit=cve` a row is one CVE for one distribution, with the number of
distinct packages behind it and the first three names; with `unit=package` a
row is one package in one release. The bucket bounds returned by
`/mttr/distribution` and `/backlog` can be passed straight back as
`min_days`/`max_days`, which is how the dashboard's bars open their lists.

Responses are cached in memory until the next successful ingest run.

## Design notes

- Series colour follows the distribution, never its position in the filter:
  Chainguard blue, Ubuntu orange, Debian aqua, Red Hat yellow, Echo magenta,
  Docker Hardened Images red.
  The order is the one validated for colour-vision-deficiency safety in both
  themes; severity uses a single-hue ordinal ramp so it never competes with
  distribution identity.
- Marks are thin (≤24 px bars, 2 px lines), neighbours are separated by a
  2 px surface gap rather than strokes, and every chart has a legend, a
  tooltip listing every series at the hovered X, and a table view.
- No dual axes anywhere; the schema's roll-ups make the default views cheap
  and the live fact queries keep filtered views under a second or two.

## Known limitations

- Severity for older CVEs is often "unrated" because cve.org records before
  2016 rarely carry CVSS and CISA's enrichment covers 2023 onwards. NVD could
  be added as a further severity source.
- Docker Hardened Images has no time-to-remediate figures because its feed
  carries no fix dates. Recording when a fix first appears in the feed (on
  each ingest, or from the history of its advisories repository) would date
  fixes from then on.
- Incremental sync does not detect deletions from an index; the daily full
  reload handles those.
- The CVE loader always takes the full nightly archive; the hourly delta
  archives are not applied.
