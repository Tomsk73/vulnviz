import { useCallback, useEffect, useState } from 'react'

export type SortKey = 'days' | 'published' | 'fixed' | 'severity'

/** State of the record browser. It narrows the page-wide filters and never widens them. */
export interface Browse {
  status: 'fixed' | 'open'
  distro: string           // '' = every selected distribution
  severity: string         // 'all' or one severity
  min: string              // days, inclusive; '' = no lower bound
  max: string              // days, exclusive; '' = no upper bound
  undated: boolean         // only CVEs that have no publication date
  month: string            // one 'YYYY-MM' of the range, '' = the whole range (fixed only)
  q: string                // CVE ID or package name
  sort: SortKey
  dir: 'asc' | 'desc'
  page: number
}

export const browseDefaults: Browse = {
  status: 'fixed', distro: '', severity: 'all', min: '', max: '', undated: false, month: '', q: '', sort: 'days', dir: 'desc', page: 0,
}

/** What a chart hands over when one of its marks is selected. */
export type Drill = (to: Partial<Browse>) => void

/** The browser's days filter for a chart bucket, whose bounds the API states with the counts. */
export function bucketRange(r: { min_days: number | null; max_days: number | null; undated?: boolean }): Partial<Browse> {
  return { min: r.min_days == null ? '' : String(r.min_days), max: r.max_days == null ? '' : String(r.max_days), undated: !!r.undated }
}

const key: Record<keyof Browse, string> = {
  status: 'b_status', distro: 'b_distro', severity: 'b_severity', min: 'b_min', max: 'b_max', undated: 'b_undated',
  month: 'b_month', q: 'b_q', sort: 'b_sort', dir: 'b_dir', page: 'b_page',
}

function read(): Browse {
  const q = new URLSearchParams(location.search)
  const oneOf = <T extends string>(k: keyof Browse, allowed: readonly T[], fallback: T): T => {
    const v = q.get(key[k])
    return allowed.includes(v as T) ? (v as T) : fallback
  }
  const number = (k: keyof Browse) => {
    const v = q.get(key[k]) ?? ''
    return v !== '' && isFinite(Number(v)) ? v : ''
  }
  const month = q.get(key.month) ?? ''
  return {
    status: oneOf('status', ['fixed', 'open'] as const, 'fixed'),
    distro: q.get(key.distro) ?? '',
    severity: q.get(key.severity) ?? 'all',
    min: number('min'), max: number('max'),
    undated: q.get(key.undated) === '1',
    month: /^\d{4}-\d{2}$/.test(month) ? month : '',
    q: q.get(key.q) ?? '',
    sort: oneOf('sort', ['days', 'published', 'fixed', 'severity'] as const, 'days'),
    dir: oneOf('dir', ['asc', 'desc'] as const, 'desc'),
    page: Math.max(0, Math.floor(Number(q.get(key.page))) || 0),
  }
}

function write(b: Browse) {
  // Only this hook's keys are touched; the page-wide filters own the rest.
  const q = new URLSearchParams(location.search)
  for (const k of Object.values(key)) q.delete(k)
  for (const k of Object.keys(key) as (keyof Browse)[]) {
    if (b[k] === browseDefaults[k]) continue
    q.set(key[k], typeof b[k] === 'boolean' ? '1' : String(b[k]))
  }
  const qs = q.toString()
  if (qs !== location.search.replace(/^\?/, '')) history.replaceState(null, '', qs ? `?${qs}` : location.pathname)
}

export function isDefaultBrowse(b: Browse): boolean {
  return (Object.keys(browseDefaults) as (keyof Browse)[]).every(k => b[k] === browseDefaults[k])
}

/** The browser's state lives in the URL next to the filters, so a list can be shared and restored. */
export function useBrowse(): { b: Browse; set: (patch: Partial<Browse>) => void; replace: (next: Partial<Browse>) => void } {
  const [b, setB] = useState<Browse>(read)
  useEffect(() => {
    const onPop = () => setB(read())
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])
  useEffect(() => write(b), [b])
  // Any change of selection starts again from the first page.
  const set = useCallback((patch: Partial<Browse>) => setB(prev => ({ ...prev, page: 0, ...patch })), [])
  const replace = useCallback((next: Partial<Browse>) => setB({ ...browseDefaults, ...next }), [])
  return { b, set, replace }
}
