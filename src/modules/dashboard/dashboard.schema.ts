// backend/src/modules/dashboard/dashboard.schema.ts
// ==================================================================
// Zero Plus - Dashboard Validation Schemas
// ------------------------------------------------------------------
// موديول قراءة فقط — كل الـ endpoints = GET
// مفيش body؛ التحقق على Query فقط
//
// Routes (prefix: /dashboard):
//   GET /overview      ?range=&serverId=
//   GET /timeline      ?range=&serverId=
//   GET /top           ?by=&range=&limit=&serverId=
//   GET /servers
//   GET /threat-map    ?range=
//
// الأدوار (في الـ routes): OWNER | ADMIN | ANALYST  (مش VIEWER)
// organizationId من JWT فقط
// ==================================================================

import { z } from 'zod'

// ==================================================================
// 1) ثوابت الفترات والتجميع
// ==================================================================

/** الفترات الزمنية المسموحة للداشبورد */
export const DASHBOARD_RANGES = ['1h', '24h', '7d', '30d'] as const
export type DashboardRange = (typeof DASHBOARD_RANGES)[number]

/**
 * إعدادات كل range:
 * - ms: طول الفترة بالميلي ثانية
 * - interval: وحدة التجميع للـ timeline (PostgreSQL date_trunc)
 * - expectedPoints: عدد النقاط التقريبي (للتوثيق والفرونت)
 */
export const RANGE_CONFIG = {
  '1h': {
    ms: 60 * 60 * 1000,
    interval: '5 minutes' as const,
    truncUnit: 'minute' as const, // هنقرّب لـ 5 دقايق في الـ SQL
    bucketMinutes: 5,
    expectedPoints: 12,
    label: 'آخر ساعة',
  },
  '24h': {
    ms: 24 * 60 * 60 * 1000,
    interval: '1 hour' as const,
    truncUnit: 'hour' as const,
    bucketMinutes: 60,
    expectedPoints: 24,
    label: 'آخر 24 ساعة',
  },
  '7d': {
    ms: 7 * 24 * 60 * 60 * 1000,
    interval: '1 day' as const,
    truncUnit: 'day' as const,
    bucketMinutes: 24 * 60,
    expectedPoints: 7,
    label: 'آخر 7 أيام',
  },
  '30d': {
    ms: 30 * 24 * 60 * 60 * 1000,
    interval: '1 day' as const,
    truncUnit: 'day' as const,
    bucketMinutes: 24 * 60,
    expectedPoints: 30,
    label: 'آخر 30 يوم',
  },
} as const satisfies Record<
  DashboardRange,
  {
    ms: number
    interval: string
    truncUnit: 'minute' | 'hour' | 'day'
    bucketMinutes: number
    expectedPoints: number
    label: string
  }
>

/** أبعاد الـ Top */
export const TOP_BY_OPTIONS = [
  'ip',
  'path',
  'country',
  'asn',
  'ipType',
  'stage',
] as const
export type TopBy = (typeof TOP_BY_OPTIONS)[number]

export const TOP_LIMIT_DEFAULT = 10
export const TOP_LIMIT_MAX = 50

// ==================================================================
// 2) Helpers للـ Query
// ==================================================================

const queryInt = (fallback: number, min: number, max: number) =>
  z
    .string()
    .optional()
    .default(String(fallback))
    .transform((value) => Number(value))
    .pipe(
      z
        .number({ message: 'القيمة يجب أن تكون رقمًا' })
        .int('القيمة يجب أن تكون رقمًا صحيحًا')
        .min(min, `الحد الأدنى ${min}`)
        .max(max, `الحد الأقصى ${max}`),
    )

const optionalUuid = z
  .string()
  .uuid('serverId غير صالح')
  .optional()

const rangeField = z
  .enum(DASHBOARD_RANGES, {
    message: `range يجب أن يكون واحدًا من: ${DASHBOARD_RANGES.join(', ')}`,
  })
  .default('24h')

// ==================================================================
// 3) Query Schemas
// ==================================================================

/** GET /dashboard/overview */
export const overviewQuerySchema = z
  .object({
    range: rangeField,
    serverId: optionalUuid,
  })
  .strict()

/** GET /dashboard/timeline */
export const timelineQuerySchema = z
  .object({
    range: rangeField,
    serverId: optionalUuid,
  })
  .strict()

/** GET /dashboard/top */
export const topQuerySchema = z
  .object({
    by: z.enum(TOP_BY_OPTIONS, {
      message: `by يجب أن يكون واحدًا من: ${TOP_BY_OPTIONS.join(', ')}`,
    }),
    range: rangeField,
    limit: queryInt(TOP_LIMIT_DEFAULT, 1, TOP_LIMIT_MAX),
    serverId: optionalUuid,
  })
  .strict()

/** GET /dashboard/servers — مفيش query */
export const serversSummaryQuerySchema = z.object({}).strict()

/** GET /dashboard/threat-map */
export const threatMapQuerySchema = z
  .object({
    range: rangeField,
  })
  .strict()

// ==================================================================
// 4) أنواع الردود (Contract للفرونت + الـ Service)
// ==================================================================

export type ThreatLevel = 'low' | 'medium' | 'high' | 'critical'

export interface DashboardTrafficStats {
  total: number
  allowed: number
  blocked: number
  challenged: number
  rateLimited: number
  monitored: number
}

export interface DashboardRiskStats {
  avgScore: number
  surgeDetected: boolean
  surgeCount: number
}

export interface DashboardChallengeStats {
  total: number
  passed: number
  failed: number
}

export interface DashboardServersStatusCount {
  ONLINE: number
  DEGRADED: number
  OFFLINE: number
  PENDING: number
  MAINTENANCE: number
}

export interface DashboardReputationStats {
  activeBans: number
  permanentBans: number
  criticalEntries: number
  newBansInRange: number
}

export interface OverviewResult {
  range: DashboardRange
  rangeLabel: string
  periodStart: string
  periodEnd: string
  traffic: DashboardTrafficStats
  risk: DashboardRiskStats
  challenges: DashboardChallengeStats
  servers: DashboardServersStatusCount
  reputation: DashboardReputationStats
  unreadNotifications: number
  /** لو اتعمل فلتر بسيرفر */
  serverId: string | null
  generatedAt: string
}

export interface TimelinePoint {
  time: string
  total: number
  blocked: number
  challenged: number
  rateLimited: number
  allowed: number
  monitored: number
  avgRiskScore: number
}

export interface TimelineResult {
  range: DashboardRange
  interval: string
  periodStart: string
  periodEnd: string
  serverId: string | null
  points: TimelinePoint[]
  generatedAt: string
}

export interface TopItem {
  /** القيمة المُجمَّعة (ip / path / country code / asn / ipType / stage) */
  value: string
  /** تسمية إضافية (مثل asOrg للـ ASN أو اسم الدولة لاحقًا) */
  label?: string | null
  total: number
  blocked: number
  challenged: number
  rateLimited?: number
  allowed?: number
  avgRiskScore: number
  maxRiskScore?: number
}

export interface TopResult {
  by: TopBy
  range: DashboardRange
  limit: number
  serverId: string | null
  items: TopItem[]
  generatedAt: string
}

export interface ServerSummaryItem {
  id: string
  domain: string
  status: string
  mode: string
  dnsVerified: boolean
  gatewayReachable: boolean
  originReachable: boolean
  avgResponseTimeMs: number | null
  currentLoadPercent: number | null
  maxRequestsPerSecond: number | null
  safeRequestsPerSecond: number | null
  p95ResponseTimeMs: number | null
  probeRecommendation: string | null
  probeConfidence: string | null
  lastProbeAt: string | null
  eventsLastHour: number
  blockedLastHour: number
  lastHealthCheckAt: string | null
  lastEventAt: string | null
}

export interface ServersSummaryResult {
  servers: ServerSummaryItem[]
  totals: {
    count: number
    online: number
    degraded: number
    offline: number
    pending: number
    maintenance: number
  }
  generatedAt: string
}

export interface ThreatMapCountry {
  code: string
  total: number
  blocked: number
  challenged: number
  /** blocked / total */
  blockRate: number
  threatLevel: ThreatLevel
}

export interface ThreatMapResult {
  range: DashboardRange
  periodStart: string
  periodEnd: string
  countries: ThreatMapCountry[]
  unknownCountryTotal: number
  generatedAt: string
}

// ==================================================================
// 5) Helpers تُستخدم من الـ Service
// ==================================================================

/**
 * يحسب بداية الفترة من range بالنسبة لـ now
 */
export function periodFromRange(
  range: DashboardRange,
  now: Date = new Date(),
): { periodStart: Date; periodEnd: Date; config: (typeof RANGE_CONFIG)[DashboardRange] } {
  const config = RANGE_CONFIG[range]
  const periodEnd = now
  const periodStart = new Date(now.getTime() - config.ms)
  return { periodStart, periodEnd, config }
}

/**
 * مستوى التهديد من نسبة الحظر
 */
export function computeThreatLevel(blockRate: number): ThreatLevel {
  if (blockRate >= 0.85) return 'critical'
  if (blockRate >= 0.6) return 'high'
  if (blockRate >= 0.3) return 'medium'
  return 'low'
}

// ==================================================================
// 6) Types مستخرجة من Zod
// ==================================================================

export type OverviewQuery = z.infer<typeof overviewQuerySchema>
export type TimelineQuery = z.infer<typeof timelineQuerySchema>
export type TopQuery = z.infer<typeof topQuerySchema>
export type ThreatMapQuery = z.infer<typeof threatMapQuerySchema>