import type { ReportCommandAdapter } from '../types/reports'

/** Local-only admission. An API adapter can replace this without changing UI event handlers. */
export const acceptLocalReportCommand: ReportCommandAdapter = async () => ({ ok: true })
