export function hex(value: number): string { return `0x${value.toString(16).toUpperCase()}` }
export function bytes(value: number): string { return `${value.toLocaleString()} B` }
export function display(value: string | number | boolean | null): string {
  if (value === null) return '—'
  if (typeof value === 'number') return Number.isInteger(value) ? `${value.toLocaleString()} (${hex(value)})` : value.toFixed(4)
  return String(value)
}
export function fieldName(path: string): string { return path.split('.').at(-1)!.replaceAll('_', ' ') }
