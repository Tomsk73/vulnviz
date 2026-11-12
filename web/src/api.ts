import { useEffect, useRef, useState } from 'react'

export interface DistroInfo {
  id: string; name: string; homepage: string | null; notes: string | null
  rules: { fix_time_basis?: string; trusted_kinds?: string[]; max_id_year_gap?: number; ecosystem_prefix?: string }
  advisories: number; fixed_cves: number; trusted_fixed_cves: number; open_cves: number
  first_trusted_fix: string | null; last_fix: string | null; last_ingest: string | null; last_ingest_ok: boolean | null
}
export interface MonthlyFix { distro: string; month: string; severity: string; fixes: number }
export interface MTTRPoint { distro: string; month?: string; severity: string; n: number; median: number | null; mean: number | null; p25: number | null; p75: number | null; p90: number | null }
export interface Bucket { distro: string; bucket: string; order: number; n: number }
export interface OpenRow { distro: string; severity: string; age: string; order: number; n: number }
export interface CVEMonth { month: string; severity: string; cves: number }
export interface Ecosystem { ecosystem: string; fixes: number }
export interface CVEDetail {
  id: string; state: string; published: string | null; title: string | null; description: string | null
  severity: string; cvss_score: number | null; cvss_vector: string | null; cvss_source: string | null; kev: boolean; cwes: string[]
  metrics: { source: string; version: string; score: number; severity: string; vector?: string }[]
  fixes: { distro: string; ecosystem: string; package: string; advisory_id: string; fix_time: string; fix_time_trusted: boolean; ttr_days: number | null }[]
  open: { distro: string; ecosystem: string; package: string; advisory_id: string }[]
}
export interface Status {
  cves: number; cve_first_published: string | null; cve_last_published: string | null
  last_cve_load: string | null; last_rebuild: string | null
  runs: { id: number; source: string; mode: string; started_at: string; finished_at: string | null; status: string; records: number; detail: string | null }[]
}

export interface Envelope<T> { data: T; data_as_of?: string }

export async function get<T>(path: string, params?: Record<string, string | undefined>): Promise<Envelope<T>> {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params ?? {})) if (v) q.set(k, v)
  const url = q.toString() ? `${path}?${q}` : path
  const res = await fetch(url, { headers: { Accept: 'application/json' } })
  if (!res.ok) {
    let msg = res.statusText
    try { msg = (await res.json()).error ?? msg } catch { /* ignore */ }
    throw new Error(msg)
  }
  return res.json()
}

export interface Loaded<T> { data: T | null; loading: boolean; error: string | null; asOf?: string }

/** Fetches whenever the key changes, keeping the previous data visible while loading. */
export function useGet<T>(path: string, params: Record<string, string | undefined>, enabled = true): Loaded<T> {
  const key = path + JSON.stringify(params) + enabled
  const [state, setState] = useState<Loaded<T>>({ data: null, loading: enabled, error: null })
  const latest = useRef(key)
  useEffect(() => {
    latest.current = key
    if (!enabled) { setState(s => ({ ...s, loading: false })); return }
    setState(s => ({ ...s, loading: true, error: null }))
    get<T>(path, params).then(env => {
      if (latest.current !== key) return
      setState({ data: env.data, loading: false, error: null, asOf: env.data_as_of })
    }).catch(err => {
      if (latest.current !== key) return
      setState(s => ({ ...s, loading: false, error: err.message || 'request failed' }))
    })
  }, [key]) // eslint-disable-line react-hooks/exhaustive-deps
  return state
}
