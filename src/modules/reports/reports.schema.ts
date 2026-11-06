// backend/src/modules/reports/reports.schema.ts
// ==================================================================
// Zero Plus - Reports Validation Schemas
// ------------------------------------------------------------------
// مصدر الحقيقة لـ Report module (متوافق مع model Report في Prisma)
//
// Dashboard (JWT) → prefix: /reports
//   POST   /              إنشاء تقرير (type + فترة + server اختياري)
//   GET    /              قائمة + فلاتر + pagination
//   GET    /:id           تفاصيل تقرير واحد
//   DELETE /:id           حذف (OWNER / ADMIN)
//   POST   /chat          محادثة مع Gemini (context اختياري)
//
// قواعد:
//   1) organizationId من JWT فقط
//   2) periodEnd > periodStart
//   3) مدة الفترة محدودة (ما يتبعتش شهور كاملة دفعة واحدة)
//   4) chat: تاريخ رسائل محدود + طول رسالة محدود
// ==================================================================

import { z } from 'zod'
import type { ReportStatus, ReportType } from '@prisma/client'

// ==================================================================
// 1) Enums (متطابقة مع Prisma)
// ==================================================================

export const REPORT_TYPES = [
  'PERIODIC',
  'INCIDENT',
  'ON_DEMAND',
] as const satisfies readonly ReportType[]

export const REPORT_STATUSES = [
  'PENDING',
  'GENERATING',
  'READY',
  'FAILED',
] as const satisfies readonly ReportStatus[]

// ==================================================================
// 2) حدود وثوابت
// ==================================================================

/** أقصى مدة لفترة التقرير (أيام) — لتقليل حجم البيانات والـ tokens */
export const MAX_REPORT_PERIOD_DAYS = 31

/** أقصى أيام للرجوع للماضي */
export const MAX_LOOKBACK_DAYS = 365

/** حدود الـ Chat */
export const CHAT_MAX_MESSAGE_LENGTH = 4_000
export const CHAT_MAX_HISTORY_MESSAGES = 40
export const CHAT_MAX_HISTORY_CHARS = 48_000

// ==================================================================
// 3) Helpers للـ Query / Dates
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
        .min(min, `القيمة يجب ألا تقل عن ${min}`)
        .max(max, `القيمة يجب ألا تزيد عن ${max}`),
    )

const isoDateTime = z
  .string({ message: 'التاريخ مطلوب' })
  .datetime({
    message: 'التاريخ يجب أن يكون ISO 8601 UTC وينتهي بـ Z (مثال: 2026-10-01T00:00:00.000Z)',
  })
  .transform((s) => new Date(s))

const optionalIsoDateTime = z
  .string()
  .datetime({
    message: 'التاريخ يجب أن يكون ISO 8601 UTC وينتهي بـ Z',
  })
  .optional()
  .transform((s) => (s === undefined ? undefined : new Date(s)))

const uuidField = (label: string) =>
  z
    .string({ message: `${label} مطلوب` })
    .uuid(`${label} غير صالح`)

/**
 * يتحقق من:
 * - periodEnd > periodStart
 * - المدة ≤ MAX_REPORT_PERIOD_DAYS
 * - periodStart مش أقدم من MAX_LOOKBACK_DAYS
 */
function refinePeriod(
  data: { periodStart: Date; periodEnd: Date },
  ctx: z.RefinementCtx,
) {
  const start = data.periodStart.getTime()
  const end = data.periodEnd.getTime()

  if (Number.isNaN(start) || Number.isNaN(end)) {
    ctx.addIssue({
      code: 'custom',
      message: 'تاريخ غير صالح',
      path: ['periodStart'],
    })
    return
  }

  if (end <= start) {
    ctx.addIssue({
      code: 'custom',
      message: 'periodEnd يجب أن يكون بعد periodStart',
      path: ['periodEnd'],
    })
  }

  const durationMs = end - start
  const maxMs = MAX_REPORT_PERIOD_DAYS * 24 * 60 * 60 * 1000
  if (durationMs > maxMs) {
    ctx.addIssue({
      code: 'custom',
      message: `مدة الفترة لا تتجاوز ${MAX_REPORT_PERIOD_DAYS} يومًا`,
      path: ['periodEnd'],
    })
  }

  const oldest = Date.now() - MAX_LOOKBACK_DAYS * 24 * 60 * 60 * 1000
  if (start < oldest) {
    ctx.addIssue({
      code: 'custom',
      message: `لا يمكن الرجوع أكتر من ${MAX_LOOKBACK_DAYS} يومًا للخلف`,
      path: ['periodStart'],
    })
  }
}

// ==================================================================
// 4) إنشاء تقرير  POST /reports
// ==================================================================

export const createReportSchema = z
  .object({
    type: z.enum(REPORT_TYPES, {
      message: 'type يجب أن يكون PERIODIC أو INCIDENT أو ON_DEMAND',
    }),

    /** null/undefined = كل سيرفرات الشركة */
    serverId: z
      .string()
      .uuid('serverId غير صالح')
      .optional()
      .nullable(),

    periodStart: isoDateTime,
    periodEnd: isoDateTime,

    /** لو مش موجود، الـ Service بيولّد عنوان تلقائي */
    title: z
      .string()
      .trim()
      .min(3, 'العنوان قصير جدًا')
      .max(200, 'العنوان طويل جدًا')
      .optional(),

    /** لربط تقرير INCIDENT بحدث معيّن (اختياري) */
    securityEventId: z
      .string()
      .uuid('securityEventId غير صالح')
      .optional()
      .nullable(),
  })
  .strict()
  .superRefine(refinePeriod)

// ==================================================================
// 5) قائمة التقارير  GET /reports
// ==================================================================

export const listReportsQuerySchema = z.object({
  page: queryInt(1, 1, 100_000),
  limit: queryInt(20, 1, 100),

  status: z.enum(REPORT_STATUSES).optional(),
  type: z.enum(REPORT_TYPES).optional(),

  serverId: z.string().uuid('serverId غير صالح').optional(),

  /** فلتر على createdAt للتقرير نفسه */
  startDate: optionalIsoDateTime,
  endDate: optionalIsoDateTime,

  sortBy: z
    .enum(['createdAt', 'updatedAt', 'periodStart', 'status', 'type'])
    .default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
})

// ==================================================================
// 6) معرف تقرير  GET|DELETE /reports/:id
// ==================================================================

export const reportIdParamsSchema = z.object({
  id: uuidField('معرف التقرير'),
})

// ==================================================================
// 7) Chat  POST /reports/chat
// ==================================================================

const chatRoleSchema = z.enum(['user', 'assistant', 'system'], {
  message: 'role يجب أن يكون user أو assistant أو system',
})

const chatMessageSchema = z
  .object({
    role: chatRoleSchema,
    content: z
      .string({ message: 'محتوى الرسالة مطلوب' })
      .trim()
      .min(1, 'الرسالة فارغة')
      .max(CHAT_MAX_MESSAGE_LENGTH, `الرسالة أطول من ${CHAT_MAX_MESSAGE_LENGTH} حرف`),
  })
  .strict()

export const chatSchema = z
  .object({
    /** الرسالة الجديدة من المستخدم */
    message: z
      .string({ message: 'الرسالة مطلوبة' })
      .trim()
      .min(1, 'الرسالة فارغة')
      .max(CHAT_MAX_MESSAGE_LENGTH, `الرسالة أطول من ${CHAT_MAX_MESSAGE_LENGTH} حرف`),

    /**
     * تاريخ المحادثة السابق (من غير الرسالة الحالية)
     * الـ Service بيضيف message في الآخر كـ role=user
     */
    messages: z
      .array(chatMessageSchema)
      .max(
        CHAT_MAX_HISTORY_MESSAGES,
        `عدد رسائل التاريخ لا يتجاوز ${CHAT_MAX_HISTORY_MESSAGES}`,
      )
      .default([]),

    /**
     * لو true: الـ Service يجمع إحصائيات سريعة عن الشركة
     * (عدد أحداث، محظورين، حالة سيرفرات) ويحطها system context
     * — من غير IPs كاملة حساسة أو أسرار
     */
    includeContext: z.boolean().default(true),

    /** اختياري: حصر السياق على سيرفر واحد */
    serverId: z.string().uuid('serverId غير صالح').optional().nullable(),
  })
  .strict()
  .superRefine((data, ctx) => {
    const historyChars = data.messages.reduce(
      (sum, m) => sum + m.content.length,
      0,
    )
    if (historyChars > CHAT_MAX_HISTORY_CHARS) {
      ctx.addIssue({
        code: 'custom',
        message: `حجم تاريخ المحادثة كبير جدًا (حد ${CHAT_MAX_HISTORY_CHARS} حرف)`,
        path: ['messages'],
      })
    }
  })

// ==================================================================
// 8) أنواع مساعدة للـ Service / Gemini (مش Validation)
// ==================================================================

/**
 * شكل البيانات المُصفّاة اللي بتتبعت لـ Gemini
 * — مفيش originIp / secrets / PII مستخدمين / passkeys
 */
export interface ReportEventForAi {
  decision: string
  riskScore: number
  path: string
  method: string
  countryCode: string | null
  ipType: string | null
  decidedAtStage: string | null
  surgeDetected: boolean
  pathSensitive: boolean
  isChallenged: boolean
  challengeType: string | null
  challengePassed: boolean | null
  reasonSummary: string | null
  /** domain مش UUID */
  serverName: string
  /** IP الزائر — اختياري إخفاء آخر octet قبل التصدير الخارجي */
  ipAddress: string
  createdAt: string
}

export interface ReportReputationForAi {
  ipAddress: string
  score: number
  banStatus: string
  bannedUntil: string | null
  failedChecksCount: number
  jsFailCount: number
  advancedFailCount: number
  isKnownBotnet: boolean
  ipType: string | null
  countryCode: string | null
  totalRequests: number
}

export interface ReportChallengeForAi {
  challengeType: string
  passed: boolean
  durationMs: number | null
  failureReason: string | null
  serverName: string | null
  createdAt: string
}

export interface ReportSimulationForAi {
  pattern: string
  status: string
  targetRps: number
  totalSent: number
  totalAllowed: number
  totalRateLimited: number
  totalChallenged: number
  totalBlocked: number
  serverName: string
  startedAt: string
  stoppedAt: string | null
}

export interface ReportServerSummaryForAi {
  domain: string
  status: string
  mode: string
  dnsVerified: boolean
  originReachable: boolean
  gatewayReachable: boolean
  maxRequestsPerSecond: number | null
  safeRequestsPerSecond: number | null
  probeRecommendation: string | null
  // ❌ مفيش originIp / originPort / verificationToken
}

export interface CollectedReportData {
  periodStart: string
  periodEnd: string
  organizationName: string
  servers: ReportServerSummaryForAi[]
  events: ReportEventForAi[]
  reputations: ReportReputationForAi[]
  challenges: ReportChallengeForAi[]
  simulations: ReportSimulationForAi[]
  stats: {
    totalEventsSampled: number
    blockedCount: number
    challengedCount: number
    rateLimitedSampled: number
    allowSurgeCount: number
    highRiskReputations: number
    failedChallenges: number
  }
}

// ==================================================================
// 9) Types المُستخرجة من Zod
// ==================================================================

export type CreateReportInput = z.infer<typeof createReportSchema>
export type ListReportsQuery = z.infer<typeof listReportsQuerySchema>
export type ReportIdParams = z.infer<typeof reportIdParamsSchema>
export type ChatInput = z.infer<typeof chatSchema>
export type ChatMessage = z.infer<typeof chatMessageSchema>