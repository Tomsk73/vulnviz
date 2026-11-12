-- Supports the "CVEs published in range" scope on the package-level facts.
CREATE INDEX IF NOT EXISTS fact_fixes_pkg_distro_pub_idx ON fact_fixes_pkg (distro, cve_published);
CREATE INDEX IF NOT EXISTS fact_open_cve_idx ON fact_open (cve_id);
