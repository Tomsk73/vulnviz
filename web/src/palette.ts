// Series colour follows the entity, never its position in the current filter.
// Slots are the validated categorical order (see README, "Design notes").
export const distroSlot: Record<string, number> = {
  chainguard: 1, ubuntu: 2, debian: 3, redhat: 4, echo: 5, alpine: 6, wolfi: 7,
}
let nextSlot = 8
export function distroColor(id: string): string {
  let slot = distroSlot[id]
  if (!slot) { slot = Math.min(nextSlot++, 8); distroSlot[id] = slot }
  return `var(--s${slot})`
}

export const severities = ['critical', 'high', 'medium', 'low', 'none', 'unknown'] as const
export type Severity = typeof severities[number]
export const severityLabel: Record<string, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None', unknown: 'Unrated', all: 'All severities',
}
export function severityColor(s: string): string { return `var(--sev-${s})` }
