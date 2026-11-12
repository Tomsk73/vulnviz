-- Core reference data ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS distros (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    homepage    text,
    notes       text,
    sort_order  int  NOT NULL DEFAULT 0,
    rules       jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- CVE records (from cve.org / cvelistV5) --------------------------------------

CREATE TABLE IF NOT EXISTS cves (
    id            text PRIMARY KEY,
    state         text NOT NULL,
    published     timestamptz,
    reserved      timestamptz,
    updated       timestamptz,
    assigner      text,
    title         text,
    description   text,
    cwes          text[] NOT NULL DEFAULT '{}',
    cvss_score    numeric(3,1),
    cvss_version  text,
    cvss_vector   text,
    cvss_source   text,
    severity      text NOT NULL DEFAULT 'unknown',
    kev           boolean NOT NULL DEFAULT false,
    metrics       jsonb NOT NULL DEFAULT '[]'::jsonb,
    ingested_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS cves_published_idx ON cves (published);
CREATE INDEX IF NOT EXISTS cves_severity_published_idx ON cves (severity, published);

-- Advisories (OSV records) per distro ----------------------------------------

CREATE TABLE IF NOT EXISTS advisories (
    distro            text NOT NULL REFERENCES distros(id) ON DELETE CASCADE,
    id                text NOT NULL,
    kind              text NOT NULL,
    published         timestamptz,
    modified          timestamptz,
    withdrawn         timestamptz,
    summary           text,
    cvss_vector       text,
    cvss_score        numeric(3,1),
    severity          text,
    has_fix           boolean NOT NULL DEFAULT false,
    fix_time          timestamptz,
    fix_time_trusted  boolean NOT NULL DEFAULT false,
    ingested_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (distro, id)
);
CREATE INDEX IF NOT EXISTS advisories_distro_fix_time_idx ON advisories (distro, fix_time);
CREATE INDEX IF NOT EXISTS advisories_distro_modified_idx ON advisories (distro, modified);
CREATE INDEX IF NOT EXISTS advisories_kind_idx ON advisories (distro, kind);

CREATE TABLE IF NOT EXISTS advisory_cves (
    distro       text NOT NULL,
    advisory_id  text NOT NULL,
    cve_id       text NOT NULL,
    PRIMARY KEY (distro, advisory_id, cve_id),
    FOREIGN KEY (distro, advisory_id) REFERENCES advisories(distro, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS advisory_cves_cve_idx ON advisory_cves (cve_id);

CREATE TABLE IF NOT EXISTS advisory_packages (
    distro       text NOT NULL,
    advisory_id  text NOT NULL,
    ecosystem    text NOT NULL DEFAULT '',
    package      text NOT NULL DEFAULT '',
    introduced   text,
    fixed        text,
    fix_time     timestamptz,
    FOREIGN KEY (distro, advisory_id) REFERENCES advisories(distro, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS advisory_packages_adv_idx ON advisory_packages (distro, advisory_id);
CREATE INDEX IF NOT EXISTS advisory_packages_eco_idx ON advisory_packages (distro, ecosystem);

-- Ingest bookkeeping ----------------------------------------------------------

CREATE TABLE IF NOT EXISTS ingest_runs (
    id           bigserial PRIMARY KEY,
    source       text NOT NULL,          -- "cve" or a distro id
    mode         text NOT NULL,          -- full | incremental | aggregate
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    status       text NOT NULL DEFAULT 'running',
    records      bigint NOT NULL DEFAULT 0,
    detail       text
);
CREATE INDEX IF NOT EXISTS ingest_runs_source_idx ON ingest_runs (source, started_at DESC);

-- Derived fact tables (rebuilt by `ingest aggregate`) -------------------------

-- One row per (distro, cve, ecosystem, package): the earliest fix.
CREATE TABLE IF NOT EXISTS fact_fixes_pkg (
    distro            text NOT NULL,
    cve_id            text NOT NULL,
    ecosystem         text NOT NULL,
    package           text NOT NULL,
    advisory_id       text NOT NULL,
    kind              text NOT NULL,
    fix_time          timestamptz NOT NULL,
    fix_time_trusted  boolean NOT NULL,
    cve_published     timestamptz,
    severity          text NOT NULL,
    severity_source   text NOT NULL,     -- cve | distro | unknown
    cvss_score        numeric(3,1),
    ttr_days          numeric(10,3)
);
CREATE INDEX IF NOT EXISTS fact_fixes_pkg_distro_fix_idx ON fact_fixes_pkg (distro, fix_time);
CREATE INDEX IF NOT EXISTS fact_fixes_pkg_distro_eco_idx ON fact_fixes_pkg (distro, ecosystem, fix_time);
CREATE INDEX IF NOT EXISTS fact_fixes_pkg_cve_idx ON fact_fixes_pkg (cve_id);

-- One row per (distro, cve): the earliest trusted fix if any, else earliest fix.
CREATE TABLE IF NOT EXISTS fact_fixes_cve (
    distro            text NOT NULL,
    cve_id            text NOT NULL,
    advisory_id       text NOT NULL,
    kind              text NOT NULL,
    fix_time          timestamptz NOT NULL,
    fix_time_trusted  boolean NOT NULL,
    cve_published     timestamptz,
    severity          text NOT NULL,
    severity_source   text NOT NULL,
    cvss_score        numeric(3,1),
    ttr_days          numeric(10,3),
    packages          int NOT NULL,
    PRIMARY KEY (distro, cve_id)
);
CREATE INDEX IF NOT EXISTS fact_fixes_cve_distro_fix_idx ON fact_fixes_cve (distro, fix_time);
CREATE INDEX IF NOT EXISTS fact_fixes_cve_distro_pub_idx ON fact_fixes_cve (distro, cve_published);

-- Currently unfixed (distro, cve, ecosystem, package) combinations.
CREATE TABLE IF NOT EXISTS fact_open (
    distro            text NOT NULL,
    cve_id            text NOT NULL,
    ecosystem         text NOT NULL,
    package           text NOT NULL,
    advisory_id       text NOT NULL,
    kind              text NOT NULL,
    advisory_published timestamptz,
    cve_published     timestamptz,
    severity          text NOT NULL,
    cvss_score        numeric(3,1)
);
CREATE INDEX IF NOT EXISTS fact_open_distro_idx ON fact_open (distro, ecosystem);

-- Monthly roll-ups for the default (unfiltered) dashboard queries.
CREATE TABLE IF NOT EXISTS agg_monthly (
    distro      text NOT NULL,
    unit        text NOT NULL,            -- cve | package
    basis       text NOT NULL,            -- fix_month | cve_month
    month       date NOT NULL,
    severity    text NOT NULL,
    trusted     boolean NOT NULL,
    fixes       bigint NOT NULL,
    ttr_median  numeric(10,2),
    ttr_mean    numeric(10,2),
    ttr_p25     numeric(10,2),
    ttr_p75     numeric(10,2),
    ttr_p90     numeric(10,2),
    PRIMARY KEY (distro, unit, basis, month, severity, trusted)
);

CREATE TABLE IF NOT EXISTS agg_cves_monthly (
    month     date NOT NULL,
    severity  text NOT NULL,
    cves      bigint NOT NULL,
    PRIMARY KEY (month, severity)
);
