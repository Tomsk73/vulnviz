import { DistroInfo, Status, useGet } from '../api'
import { distroColor } from '../palette'
import { date, dateTime, int } from '../format'

export function NotesSection({ distros }: { distros: DistroInfo[] }) {
  const { data: status } = useGet<Status>('/api/v1/status', {})
  return (
    <section className="section" aria-labelledby="notes-h">
      <div className="section-head"><div><h2 id="notes-h">How each feed is read</h2>
        <p>Every distribution publishes OSV advisories, but they do not all record the same moment. These rules decide which records can be timed.</p></div></div>
      <div className="notes">
        {distros.map(d => (
          <div className="note" key={d.id}>
            <h3><i style={{ ['--c' as string]: distroColor(d.id) }} />{d.name}{d.homepage && <a href={d.homepage} style={{ fontWeight: 400, fontSize: 13, color: 'var(--ink-3)' }}>feed</a>}</h3>
            <p>{d.notes}</p>
            <dl>
              <dt>Advisories</dt><dd>{int(d.advisories)}</dd>
              <dt>CVEs with a fix</dt><dd>{int(d.fixed_cves)}{d.trusted_fixed_cves !== d.fixed_cves && <span style={{ color: 'var(--ink-3)' }}> ({int(d.trusted_fixed_cves)} with a usable fix time)</span>}</dd>
              <dt>Open CVEs</dt><dd>{int(d.open_cves)}</dd>
              <dt>Timed fixes from</dt><dd>{date(d.first_trusted_fix)}</dd>
              <dt>Fix time basis</dt><dd>{d.rules.fix_time_basis === 'component_event' ? 'per-component fixed event' : 'advisory published time'}{d.rules.trusted_kinds?.length ? `, ${d.rules.trusted_kinds.filter(k => k !== '__none__').join(', ') || 'no'} records timed` : ''}</dd>
              <dt>Last refresh</dt><dd>{dateTime(d.last_ingest)}{d.last_ingest_ok === false && <span className="error"> (failed)</span>}</dd>
            </dl>
          </div>
        ))}
      </div>
      {status && (
        <p className="status-line">
          CVE list: {int(status.cves)} published records from cve.org, last loaded {dateTime(status.last_cve_load)}. Derived tables rebuilt {dateTime(status.last_rebuild)}.
          Severity is the CNA's CVSS 3.1 rating when present, then CVSS 3.0, 4.0, CISA ADP, then the distribution's own rating; CVEs with none are shown as unrated.
          A CVE counts as fixed for a distribution the first time any advisory lists a fixed version for it; a CVE fixed in several releases or packages counts once in CVE mode and once per package per release in package mode.
        </p>
      )}
    </section>
  )
}
