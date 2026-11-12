import { useCallback, useEffect, useMemo, useState } from 'react'
import { thisMonth, ymAdd } from './format'

export interface Filters {
  from: string; to: string
  distros: string[]        // empty = all enabled
  severity: string         // 'all' or one severity
  unit: 'cve' | 'package'
  basis: 'fix_month' | 'cve_month'
  ecosystem: string        // '' = every release; '<distro>|<ecosystem>' otherwise
  scope: 'recent' | 'all'  // recent = only CVEs published inside the range
}

export const presets = [
  { id: '12m', label: 'Last 12 months', months: 12 },
  { id: '24m', label: 'Last 24 months', months: 24 },
  { id: '36m', label: 'Last 3 years', months: 36 },
  { id: '60m', label: 'Last 5 years', months: 60 },
]

function read(): Filters {
  const q = new URLSearchParams(location.search)
  const now = thisMonth()
  return {
    from: q.get('from') ?? ymAdd(now, -23),
    to: q.get('to') ?? now,
    distros: (q.get('distros') ?? '').split(',').filter(Boolean),
    severity: q.get('severity') ?? 'all',
    unit: (q.get('unit') as Filters['unit']) ?? 'cve',
    basis: (q.get('basis') as Filters['basis']) ?? 'fix_month',
    ecosystem: q.get('ecosystem') ?? '',
    scope: (q.get('scope') as Filters['scope']) ?? 'recent',
  }
}

/** Filters live in the URL so a view can be shared and restored. */
export function useFilters(): [Filters, (patch: Partial<Filters>) => void] {
  const [f, setF] = useState<Filters>(read)
  useEffect(() => {
    const onPop = () => setF(read())
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])
  const update = useCallback((patch: Partial<Filters>) => {
    setF(prev => {
      const next = { ...prev, ...patch }
      const q = new URLSearchParams()
      q.set('from', next.from); q.set('to', next.to)
      if (next.distros.length) q.set('distros', next.distros.join(','))
      if (next.severity !== 'all') q.set('severity', next.severity)
      if (next.unit !== 'cve') q.set('unit', next.unit)
      if (next.basis !== 'fix_month') q.set('basis', next.basis)
      if (next.ecosystem) q.set('ecosystem', next.ecosystem)
      if (next.scope !== 'recent') q.set('scope', next.scope)
      history.replaceState(null, '', `?${q}`)
      return next
    })
  }, [])
  return [f, update]
}

/** Query parameters shared by every analytics request. */
export function apiParams(f: Filters, enabledDistros: string[]): Record<string, string | undefined> {
  const distros = f.distros.length ? f.distros : enabledDistros
  const [ecoDistro, eco] = f.ecosystem.includes('|') ? f.ecosystem.split('|', 2) : ['', '']
  return {
    from: f.from, to: f.to,
    distros: eco ? ecoDistro : distros.join(','),
    severity: f.severity === 'all' ? undefined : f.severity,
    unit: f.unit, basis: f.basis,
    ecosystem: eco || undefined,
    scope: f.scope,
  }
}

export function useSelectedDistros(f: Filters, all: string[]): string[] {
  return useMemo(() => {
    if (f.ecosystem.includes('|')) return [f.ecosystem.split('|')[0]]
    return f.distros.length ? all.filter(d => f.distros.includes(d)) : all
  }, [f.distros, f.ecosystem, all])
}
