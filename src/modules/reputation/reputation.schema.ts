// backend/src/modules/reputation/reputation.schema.ts
// ==================================================================
// Zero Plus - Reputation Schemas (متطابق مع model ReputationEntry / ChallengeLog)
// ------------------------------------------------------------------
// الفكرة: الـ Gateway ما بيقولش "زوّد السمعة 1". هو بيبعت أدلة (Signals)
// بتوصف اللي حصل (نوعه وخطورته ومدى تأكده وكام مرة)، والباك هو اللي
// بيحسب النقاط، فالضرر الكبير والمتكرر بيرفع السمعة أكتر، والإشارة الضعيفة
// بترفعها شوية، والسلوك النضيف بيخفضها.
//
// Dashboard (JWT)  → prefix: /reputation
//   GET   /                        قائمة + فلاتر
//   GET   /stats                   ملخص (حسب الحظر وحسب التصنيف اللوني)
//   GET   /:id                     تفاصيل
//   GET   /:id/challenges          سجل الاختبارات (ChallengeLog)
//   POST  /:id/ban                 حظر يدوي          (OWNER, ADMIN, ANALYST)
//   POST  /:id/unban               رفع الحظر         (OWNER, ADMIN, ANALYST)
//   POST  /:id/allowlist           جهاز موثوق        (OWNER, ADMIN, ANALYST)
//   POST  /:id/reset               تصفير السمعة      (OWNER, ADMIN, ANALYST)
//
// Gateway (X-Gateway-Key) → prefix: /internal/gateway
//   GET  /reputation/lookup        الاستعلام قبل القرار (L0 + L3)
//   POST /reputation/apply         تسجيل أدلة تقرير واحد
//   POST /reputation/apply-batch   دفعة تقارير
//   GET  /reputation/bans          مزامنة الحظر (للـ Redis)
//
// قواعد ثابتة:
//   1) organizationId في الـ Dashboard من JWT فقط
//   2) الـ Gateway ما يقدرش يحدد درجة السمعة ولا يفرض حظر: الباك بيحسب
//      ويطبق قواعد Policy الشركة (autoBanAfterFails / temporaryBanMinutes / permanentBanScore)
//   3) ReputationEntry بيتنشئ Lazy: فقط لما يوصل دليل سلبي أو اختبار،
//      الزائر النضيف ما بيتخزنش
//   4) متوافق مع Zod v3 و v4
// ==================================================================

import { isIP } from 'node:net'
import { z } from 'zod'
import type { BanStatus, ChallengeType, IpType } from '@prisma/client'

// ==================================================================
// 1) Enums (متطابقة مع Prisma، والـ build بيكسر لو اختلفت)
// ==================================================================

export const BAN_STATUSES = [
  'NONE',
  'TEMPORARY',
  'PERMANENT',
] as const satisfies readonly BanStatus[]

export const IP_TYPES = [
  'RESIDENTIAL',
  'MOBILE',
  'DATACENTER',
  'VPN_PROXY',
  'TOR',
  'UNKNOWN',
] as const satisfies readonly IpType[]

export const CHALLENGE_TYPES = [
  'JS_SILENT',
  'TLS_FINGERPRINT',
  'RATE_LIMIT_SOFT',
  'CAPTCHA_FALLBACK',
] as const satisfies readonly ChallengeType[]

/** خطورة الدليل (الضرر المحتمل) */
export const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const
export type Severity = (typeof SEVERITIES)[number]

// ==================================================================
// 2) كتالوج الأدلة (Signals): قلب منطق "السمعة الذكية"
// ------------------------------------------------------------------
// baseWeight:  نقاط على مقياس السمعة (1-10). سالب = سلوك كويس.
// countsAsFailedCheck: بيزوّد failedChecksCount (اللي بيشغّل autoBanAfterFails)
// dedupeWindowSec: نفس الدليل من نفس السجل خلال المدة دي بيتحسب مرة واحدة
//                  (يحمي من الفيضان ومن إعادة إرسال الـ Gateway)
// fromGateway: false = الباك بيولّده بنفسه (من block الـ challenge)
//
// ملاحظة: BLOCKED_BY_POLICY مش موجود عمدًا، لأن الحظر نتيجة للـ Risk،
// ولو رفع السمعة هيحصل حلقة مفرغة (يتحظر ← سمعته ترتفع ← يتحظر أكتر).
// ==================================================================

export interface SignalDefinition {
  category: 'CHALLENGE' | 'NETWORK' | 'BEHAVIOR' | 'FINGERPRINT' | 'AI' | 'THREAT_INTEL'
  baseWeight: number
  countsAsFailedCheck: boolean
  dedupeWindowSec: number
  fromGateway: boolean
  label: string
}

export const SIGNAL_CATALOG = {
  // ---- مولّدة من الباك (من block الـ challenge) ----
  CHALLENGE_FAILED: {
    category: 'CHALLENGE', baseWeight: 2, countsAsFailedCheck: true,
    dedupeWindowSec: 0, fromGateway: false, label: 'فشل اختبار التحقق',
  },
  CHALLENGE_PASSED: {
    category: 'CHALLENGE', baseWeight: -1, countsAsFailedCheck: false,
    dedupeWindowSec: 60, fromGateway: false, label: 'نجح في اختبار التحقق',
  },

  // ---- الاختبار الصامت ----
  CHALLENGE_TOO_FAST: {
    category: 'CHALLENGE', baseWeight: 2, countsAsFailedCheck: false,
    dedupeWindowSec: 300, fromGateway: true, label: 'حل الاختبار بسرعة غير بشرية',
  },

  // ---- الشبكة ----
  DATACENTER_IP: {
    category: 'NETWORK', baseWeight: 1, countsAsFailedCheck: false,
    dedupeWindowSec: 3600, fromGateway: true, label: 'عنوان من مركز بيانات',
  },
  VPN_PROXY_IP: {
    category: 'NETWORK', baseWeight: 1, countsAsFailedCheck: false,
    dedupeWindowSec: 3600, fromGateway: true, label: 'عنوان VPN أو Proxy',
  },
  TOR_EXIT_NODE: {
    category: 'NETWORK', baseWeight: 2, countsAsFailedCheck: false,
    dedupeWindowSec: 3600, fromGateway: true, label: 'عقدة خروج Tor',
  },

  // ---- السلوك ----
  BOT_USER_AGENT: {
    category: 'BEHAVIOR', baseWeight: 2, countsAsFailedCheck: false,
    dedupeWindowSec: 600, fromGateway: true, label: 'User-Agent خاص بروبوت',
  },
  MISSING_BROWSER_HEADERS: {
    category: 'BEHAVIOR', baseWeight: 1, countsAsFailedCheck: false,
    dedupeWindowSec: 600, fromGateway: true, label: 'ترويسات متصفح ناقصة',
  },
  RATE_LIMIT_EXCEEDED: {
    category: 'BEHAVIOR', baseWeight: 1, countsAsFailedCheck: false,
    dedupeWindowSec: 60, fromGateway: true, label: 'تجاوز حد الطلبات الناعم',
  },
  HARD_LIMIT_EXCEEDED: {
    category: 'BEHAVIOR', baseWeight: 3, countsAsFailedCheck: false,
    dedupeWindowSec: 60, fromGateway: true, label: 'تجاوز الحد الأقصى للطلبات',
  },
  BRUTE_FORCE_PATTERN: {
    category: 'BEHAVIOR', baseWeight: 3, countsAsFailedCheck: false,
    dedupeWindowSec: 300, fromGateway: true, label: 'نمط تخمين كلمات المرور',
  },
  PATH_SCANNING: {
    category: 'BEHAVIOR', baseWeight: 3, countsAsFailedCheck: false,
    dedupeWindowSec: 300, fromGateway: true, label: 'فحص مسارات حساسة (/.env, /wp-admin ...)',
  },

  // ---- البصمات ----
  TLS_FINGERPRINT_BAD: {
    category: 'FINGERPRINT', baseWeight: 3, countsAsFailedCheck: true,
    dedupeWindowSec: 3600, fromGateway: true, label: 'بصمة TLS معروفة بالأدوات الآلية',
  },
  TLS_FINGERPRINT_MISMATCH: {
    category: 'FINGERPRINT', baseWeight: 3, countsAsFailedCheck: true,
    dedupeWindowSec: 3600, fromGateway: true, label: 'بصمة TLS لا تطابق المتصفح المعلن',
  },
  FINGERPRINT_ROTATION: {
    category: 'FINGERPRINT', baseWeight: 3, countsAsFailedCheck: false,
    dedupeWindowSec: 600, fromGateway: true, label: 'نفس العنوان بعدة بصمات أجهزة مختلفة',
  },
  IP_ROTATION: {
    category: 'FINGERPRINT', baseWeight: 3, countsAsFailedCheck: false,
    dedupeWindowSec: 600, fromGateway: true, label: 'نفس البصمة من عناوين كثيرة',
  },

  // ---- الذكاء الاصطناعي ----
  AI_ANOMALY: {
    category: 'AI', baseWeight: 3, countsAsFailedCheck: false,
    dedupeWindowSec: 120, fromGateway: true, label: 'شذوذ سلوكي من الـ AI',
  },

  // ---- معلومات تهديد معروفة ----
  KNOWN_BOTNET: {
    category: 'THREAT_INTEL', baseWeight: 5, countsAsFailedCheck: false,
    dedupeWindowSec: 3600, fromGateway: true, label: 'مصدر معروف ببوت نت',
  },
} as const satisfies Record<string, SignalDefinition>

export type SignalType = keyof typeof SIGNAL_CATALOG

export type GatewaySignalType = {
  [K in SignalType]: (typeof SIGNAL_CATALOG)[K]['fromGateway'] extends true ? K : never
}[SignalType]

/** الأنواع اللي الـ Gateway مسموح له يبعتها */
export const GATEWAY_SIGNAL_TYPES = (
  Object.keys(SIGNAL_CATALOG) as SignalType[]
).filter((type) => SIGNAL_CATALOG[type].fromGateway) as [
  GatewaySignalType,
  ...GatewaySignalType[],
]

// ==================================================================
// 3) ضبط التقييم (ثابت في الكود، مش في الـ Policy)
// ==================================================================

export const REPUTATION_TUNING = {
  /** أقصى زيادة في تقرير واحد: يمنع قفزة من 1 لـ 10 بإشارة واحدة */
  MAX_POINTS_PER_REPORT: 5,
  /** أقصى نزول في تقرير واحد */
  MIN_POINTS_PER_REPORT: -2,
  /** كل X ساعة من غير أدلة سلبية = تخفيض (بيحسبها الـ Service عند أول استعلام) */
  DECAY_AFTER_HOURS: 24,
  DECAY_STEP: 1,
  MAX_SIGNALS_PER_REPORT: 20,
  MAX_REPORTS_PER_BATCH: 200,
} as const

/** مضاعف الخطورة */
export const SEVERITY_MULTIPLIER: Record<Severity, number> = {
  LOW: 0.5,
  MEDIUM: 1,
  HIGH: 1.5,
  CRITICAL: 2,
}

const clamp01 = (value: number) => Math.min(1, Math.max(0, value))
const round2 = (value: number) => Math.round(value * 100) / 100

/**
 * تكرار الحدث في نفس التقرير (مثلًا 40 محاولة فحص) بيكبّر الضرر بالـ log
 * مش بشكل خطي: 1→×1 ، 4→×1.5 ، 16→×2 (أقصى حد ×2)
 */
export function repeatFactor(count: number): number {
  return Math.min(2, 1 + 0.25 * Math.log2(Math.max(1, count)))
}

/**
 * مضاعف "المعتدي المتكرر": بيطبقه الـ Service حسب failedChecksCount الحالي،
 * فمن فشل قبل كده بيتعاقب أسرع.
 */
export function repeatOffenderFactor(failedChecksCount: number): number {
  if (failedChecksCount >= 5) return 1.5
  if (failedChecksCount >= 3) return 1.25
  return 1
}

export interface SignalInput {
  type: SignalType
  severity?: Severity
  /** مدى التأكد من الدليل (0-1) */
  confidence?: number
  /** كام مرة حصل في التقرير ده */
  count?: number
  /** لـ AI_ANOMALY فقط */
  anomalyScore?: number
}

/**
 * نقاط دليل واحد (دالة صرفة، من غير DB):
 *   النقاط = الوزن الأساسي × مضاعف الخطورة × التأكد × عامل التكرار
 *   AI_ANOMALY: التأكد = confidence × anomalyScore
 *   الإشارات السالبة (سلوك كويس) ما بتتكبّرش بالخطورة ولا التكرار
 */
export function computeSignalPoints(input: SignalInput): number {
  const weight = SIGNAL_CATALOG[input.type].baseWeight

  if (weight < 0) return weight

  let confidence = clamp01(input.confidence ?? 1)

  if (input.type === 'AI_ANOMALY') {
    confidence *= clamp01(input.anomalyScore ?? 0)
  }

  const severity = SEVERITY_MULTIPLIER[input.severity ?? 'MEDIUM']

  return round2(weight * severity * confidence * repeatFactor(input.count ?? 1))
}

/**
 * مجموع أدلة تقرير (بعد الـ dedupe اللي الـ Service بيعمله) ← عدد صحيح للسمعة.
 * التقريب مرة واحدة على المجموع، فالإشارات الخفيفة بتتجمع داخل نفس التقرير.
 */
export function pointsFromSignals(signals: SignalInput[]): {
  raw: number
  applied: number
} {
  const raw = round2(signals.reduce((sum, s) => sum + computeSignalPoints(s), 0))

  const capped = Math.min(
    REPUTATION_TUNING.MAX_POINTS_PER_REPORT,
    Math.max(REPUTATION_TUNING.MIN_POINTS_PER_REPORT, raw),
  )

  return { raw, applied: Math.round(capped) }
}

// ==================================================================
// 4) التصنيف اللوني للسمعة (صفحة /reputation) ونقاط الـ Risk
// ==================================================================

export type ScoreBand = 'CLEAN' | 'LOW' | 'ELEVATED' | 'HIGH' | 'CRITICAL'

export function getScoreBand(score: number): ScoreBand {
  if (score <= 1) return 'CLEAN'
  if (score <= 3) return 'LOW'
  if (score <= 6) return 'ELEVATED'
  if (score <= 8) return 'HIGH'
  return 'CRITICAL'
}

/** نقاط تضاف على الـ Risk Score (0-100) من سمعة الجهاز (اقتراح قابل للضبط) */
export const REPUTATION_RISK_POINTS: Record<ScoreBand, number> = {
  CLEAN: 0,
  LOW: 3,
  ELEVATED: 10,
  HIGH: 20,
  CRITICAL: 30,
}

export function reputationRiskPoints(score: number): number {
  return REPUTATION_RISK_POINTS[getScoreBand(score)]
}

/** حالة الحظر الفعلية (الحظر المؤقت المنتهي = NONE) من غير ما الـ Gateway يعيد المنطق */
export function resolveEffectiveBan(
  banStatus: BanStatus,
  bannedUntil: Date | null,
  now: Date = new Date(),
): {
  banStatusEffective: BanStatus
  isCurrentlyBanned: boolean
  minutesLeftOnBan: number | null
} {
  if (banStatus === 'PERMANENT') {
    return {
      banStatusEffective: 'PERMANENT',
      isCurrentlyBanned: true,
      minutesLeftOnBan: null,
    }
  }

  if (
    banStatus === 'TEMPORARY' &&
    bannedUntil !== null &&
    bannedUntil.getTime() > now.getTime()
  ) {
    return {
      banStatusEffective: 'TEMPORARY',
      isCurrentlyBanned: true,
      minutesLeftOnBan: Math.ceil((bannedUntil.getTime() - now.getTime()) / 60_000),
    }
  }

  return {
    banStatusEffective: 'NONE',
    isCurrentlyBanned: false,
    minutesLeftOnBan: null,
  }
}

// ==================================================================
// 5) عنوان الـ IP (توحيد الشكل مهم لأن الـ unique على org + ip)
// ==================================================================

/**
 * - IPv4-mapped (::ffff:1.2.3.4) ← 1.2.3.4
 * - IPv6 بيتحول لصيغته المختصرة القياسية (2001:db8:0:0::1 ← 2001:db8::1)
 * - بيشيل [] و zone id
 * مسموح بالعناوين الخاصة (زوار التطوير ممكن يكونوا 127.0.0.1)
 */
export function normalizeIp(raw: string): string | null {
  let value = raw.trim().toLowerCase()

  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1)

  value = value.replace(/%.*$/, '')

  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(value)
  if (mapped?.[1]) value = mapped[1]

  const version = isIP(value)

  if (version === 4) return value

  if (version === 6) {
    try {
      return new URL(`http://[${value}]`).hostname.slice(1, -1)
    } catch {
      return null
    }
  }

  return null
}

const ipAddressField = z
  .string({ message: 'عنوان IP مطلوب' })
  .max(60, 'عنوان IP طويل جدًا')
  .transform((raw, ctx) => {
    const ip = normalizeIp(raw)

    if (!ip) {
      ctx.addIssue({ code: 'custom', message: 'صيغة عنوان IP غير صالحة' })
      return z.NEVER
    }

    return ip
  })

// ==================================================================
// 6) حقول مشتركة
// ==================================================================

const uuidField = (label: string) =>
  z.string({ message: `${label} مطلوب` }).uuid(`${label} غير صالح`)

// DeviceFP / JA3 (md5 hex) / JA4 (t13d1516h2_xxxx_xxxx)
const fingerprintField = z
  .string()
  .trim()
  .min(4, 'البصمة قصيرة جدًا')
  .max(512, 'البصمة طويلة جدًا')
  .regex(/^[A-Za-z0-9._:=+/\-]+$/, 'البصمة تحتوي على رموز غير مسموحة')

const countryCodeField = z
  .string()
  .trim()
  .regex(/^[A-Za-z]{2}$/, 'كود الدولة يجب أن يكون حرفين')
  .transform((value) => value.toUpperCase())

const reasonField = z.string().trim().min(3, 'السبب قصير جدًا').max(300, 'السبب طويل جدًا')

const queryBoolean = z
  .enum(['true', 'false'], { message: 'القيمة يجب أن تكون true أو false' })
  .optional()
  .transform((value) => (value === undefined ? undefined : value === 'true'))

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

const optionalQueryInt = (min: number, max: number) =>
  z
    .string()
    .optional()
    .transform((value) => (value === undefined ? undefined : Number(value)))
    .pipe(
      z
        .number({ message: 'القيمة يجب أن تكون رقمًا' })
        .int('القيمة يجب أن تكون رقمًا صحيحًا')
        .min(min, `القيمة يجب ألا تقل عن ${min}`)
        .max(max, `القيمة يجب ألا تزيد عن ${max}`)
        .optional(),
    )

const isoUtcDate = (label: string) =>
  z.string().datetime({ message: `${label} يجب أن يكون تاريخ ISO بصيغة UTC (ينتهي بـ Z)` })

// ==================================================================
// 7) Dashboard: القائمة   GET /reputation
// ==================================================================

export const listReputationQuerySchema = z
  .object({
    page: queryInt(1, 1, 100_000),
    limit: queryInt(20, 1, 100),

    banStatus: z.enum(BAN_STATUSES).optional(),
    ipType: z.enum(IP_TYPES).optional(),
    countryCode: countryCodeField.optional(),
    asn: optionalQueryInt(1, 4_294_967_295),

    minScore: optionalQueryInt(1, 10),
    maxScore: optionalQueryInt(1, 10),

    isAllowlisted: queryBoolean,
    isManualBan: queryBoolean,
    isKnownBotnet: queryBoolean,

    // بحث جزئي في الـ IP أو بصمة الجهاز
    search: z.string().trim().min(1).max(64).optional(),

    lastSeenAfter: isoUtcDate('lastSeenAfter').optional(),
    lastSeenBefore: isoUtcDate('lastSeenBefore').optional(),

    sortBy: z
      .enum([
        'score',
        'lastSeenAt',
        'firstSeenAt',
        'failedChecksCount',
        'totalRequests',
        'bannedUntil',
        'createdAt',
      ])
      .default('lastSeenAt'),
    sortOrder: z.enum(['asc', 'desc']).default('desc'),
  })
  .refine(
    (d) => d.minScore === undefined || d.maxScore === undefined || d.minScore <= d.maxScore,
    { message: 'minScore يجب أن يكون أقل من أو يساوي maxScore', path: ['minScore'] },
  )
  .refine(
    (d) =>
      d.lastSeenAfter === undefined ||
      d.lastSeenBefore === undefined ||
      new Date(d.lastSeenAfter) <= new Date(d.lastSeenBefore),
    { message: 'lastSeenAfter يجب أن يكون قبل lastSeenBefore', path: ['lastSeenAfter'] },
  )

export const reputationIdParamsSchema = z.object({
  id: uuidField('معرف سجل السمعة'),
})

// GET /reputation/:id/challenges
export const reputationChallengesQuerySchema = z.object({
  page: queryInt(1, 1, 100_000),
  limit: queryInt(20, 1, 100),
  passed: queryBoolean,
})

// ==================================================================
// 8) Dashboard: إجراءات يدوية (بتتسجل Notification + بتبقى isManualBan)
// ==================================================================

// POST /reputation/:id/ban
export const manualBanBodySchema = z
  .object({
    type: z.enum(['TEMPORARY', 'PERMANENT'], {
      message: 'type يجب أن يكون TEMPORARY أو PERMANENT',
    }),
    // الحد الأقصى 30 يوم للمؤقت، وللأطول استخدم PERMANENT
    minutes: z.number().int().min(1).max(43_200).optional(),
    reason: reasonField,
  })
  .strict()
  .superRefine((data, ctx) => {
    if (data.type === 'TEMPORARY' && data.minutes === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['minutes'],
        message: 'minutes مطلوب مع الحظر المؤقت',
      })
    }

    if (data.type === 'PERMANENT' && data.minutes !== undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['minutes'],
        message: 'minutes غير مسموح مع الحظر الدائم',
      })
    }
  })

// POST /reputation/:id/unban
export const unbanBodySchema = z
  .object({
    reason: reasonField.optional(),
    // true: يرجّع السمعة لـ 1 ويصفّر الفشل مع رفع الحظر
    resetScore: z.boolean().default(false),
  })
  .strict()

// POST /reputation/:id/allowlist   (التفعيل بيرفع الحظر الحالي)
export const allowlistBodySchema = z
  .object({
    enabled: z.boolean({ message: 'enabled يجب أن يكون true أو false' }),
    reason: reasonField.optional(),
  })
  .strict()

// POST /reputation/:id/reset
export const resetReputationBodySchema = z
  .object({
    confirm: z.literal(true, { message: 'confirm: true مطلوب' }),
    reason: reasonField.optional(),
  })
  .strict()

// ==================================================================
// 9) Gateway: الاستعلام   GET /internal/gateway/reputation/lookup
// ------------------------------------------------------------------
// الـ Service بيدوّر بالـ IP الأول، ولو مفيش بيدوّر بالبصمة (جهاز غيّر الـ IP)
// ورد الـ lookup فيه matchedBy عشان الـ Gateway يعرف اتطابق بإيه.
// ==================================================================

export const lookupReputationQuerySchema = z.object({
  organizationId: uuidField('معرف المؤسسة'),
  ipAddress: ipAddressField,
  deviceFingerprint: fingerprintField.optional(),
  ja3Fingerprint: fingerprintField.optional(),
  ja4Fingerprint: fingerprintField.optional(),
})

// ==================================================================
// 10) Gateway: تسجيل الأدلة   POST /internal/gateway/reputation/apply
// ------------------------------------------------------------------
// - الـ Gateway يبعت الأدلة، والـ Service يحسب النقاط ويطبّق Policy الشركة
// - تقرير من غير أدلة سلبية ولا اختبار لزائر ملوش سجل = لا شيء (Lazy)
// - idempotencyKey: لو الـ Gateway أعاد الإرسال بنفس المفتاح ما يتحسبش مرتين
// ==================================================================

const signalSchema = z
  .object({
    type: z.enum(GATEWAY_SIGNAL_TYPES, { message: 'نوع الدليل غير معروف' }),
    severity: z.enum(SEVERITIES).default('MEDIUM'),
    confidence: z.number().min(0).max(1).default(1),
    count: z.number().int().min(1).max(100_000).default(1),
    // لـ AI_ANOMALY فقط (0-1)
    anomalyScore: z.number().min(0).max(1).optional(),
    // سبب مختصر بيظهر في الـ Dashboard
    note: z.string().trim().max(200).optional(),
  })
  .strict()
  .superRefine((signal, ctx) => {
    if (signal.type === 'AI_ANOMALY' && signal.anomalyScore === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['anomalyScore'],
        message: 'anomalyScore مطلوب مع AI_ANOMALY',
      })
    }

    if (signal.type !== 'AI_ANOMALY' && signal.anomalyScore !== undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['anomalyScore'],
        message: 'anomalyScore مسموح مع AI_ANOMALY فقط',
      })
    }
  })

// نتيجة اختبار تحقق (بتتحفظ في ChallengeLog، والـ Service بيولّد منها
// CHALLENGE_PASSED / CHALLENGE_FAILED بنفسه، فالـ Gateway ما يبعتهمش)
const challengeSchema = z
  .object({
    type: z.enum(CHALLENGE_TYPES),
    passed: z.boolean(),
    durationMs: z.number().int().min(0).max(600_000).optional(),
    failureReason: z.string().trim().max(200).optional(),
  })
  .strict()

export const applyReputationBodySchema = z
  .object({
    organizationId: uuidField('معرف المؤسسة'),
    serverId: uuidField('معرف السيرفر').optional(),

    ipAddress: ipAddressField,
    deviceFingerprint: fingerprintField.optional(),
    ja3Fingerprint: fingerprintField.optional(),
    ja4Fingerprint: fingerprintField.optional(),

    signals: z.array(signalSchema).max(REPUTATION_TUNING.MAX_SIGNALS_PER_REPORT).default([]),
    challenge: challengeSchema.optional(),

    // عدد الطلبات اللي اتشافت من المصدر ده من آخر تقرير
    requestCount: z.number().int().min(0).max(1_000_000).default(0),

    idempotencyKey: z.string().trim().min(1).max(128).optional(),

    // معلومات إضافية الـ Gateway عارفها
    countryCode: countryCodeField.optional(),
    asn: z.number().int().min(1).max(4_294_967_295).optional(),
    asOrg: z.string().trim().max(255).optional(),
    ipType: z.enum(IP_TYPES).optional(),
    lastPath: z.string().trim().max(2048).optional(),
    lastUserAgent: z.string().trim().max(512).optional(),
    avgRequestRate: z.number().min(0).max(10_000_000).optional(),
  })
  .strict()
  .refine((d) => d.signals.length > 0 || d.challenge !== undefined || d.requestCount > 0, {
    message: 'يجب إرسال أدلة أو نتيجة اختبار أو عدد طلبات',
    path: ['signals'],
  })

// POST /internal/gateway/reputation/apply-batch
export const applyReputationBatchBodySchema = z
  .object({
    reports: z
      .array(applyReputationBodySchema)
      .min(1, 'يجب إرسال تقرير واحد على الأقل')
      .max(REPUTATION_TUNING.MAX_REPORTS_PER_BATCH),
  })
  .strict()

// ==================================================================
// 11) Gateway: مزامنة الحظر   GET /internal/gateway/reputation/bans
// ------------------------------------------------------------------
// أول تشغيل (من غير updatedSince): الحظر الساري فقط، بصفحات.
// بعد كده (updatedSince = آخر serverTime): كل سجل اتغير، حتى لو بقى
// banStatus=NONE، عشان الـ Gateway يشيله من الـ Redis.
// ==================================================================

export const gatewayBansQuerySchema = z.object({
  limit: queryInt(500, 1, 1000),
  cursor: z.string().uuid('cursor غير صالح').optional(),
  updatedSince: isoUtcDate('updatedSince').optional(),
  organizationId: uuidField('معرف المؤسسة').optional(),
})

// ==================================================================
// 12) أشكال الردود (بيبنيها الـ Service، والتواريخ ISO strings)
// ==================================================================

export interface ReputationEntryPublic {
  id: string
  organizationId: string
  ipAddress: string
  deviceFingerprint: string | null
  ja3Fingerprint: string | null
  ja4Fingerprint: string | null
  countryCode: string | null
  asn: number | null
  asOrg: string | null
  ipType: IpType
  score: number
  scoreBand: ScoreBand
  banStatus: BanStatus
  bannedUntil: string | null
  bannedAt: string | null
  banReason: string | null
  isManualBan: boolean
  isAllowlisted: boolean
  failedChecksCount: number
  successfulChecks: number
  totalRequests: number
  lastFailedAt: string | null
  lastPath: string | null
  lastUserAgent: string | null
  avgRequestRate: number | null
  isKnownBotnet: boolean
  firstSeenAt: string
  lastSeenAt: string
  createdAt: string
  updatedAt: string
}

export type ReputationMatchedBy = 'IP' | 'DEVICE_FINGERPRINT' | 'JA3' | 'JA4'

export interface LookupReputationResult {
  found: boolean
  matchedBy: ReputationMatchedBy | null
  entry: ReputationEntryPublic | null
  /** القيم الجاهزة للـ Risk Engine (لو مفيش سجل: score=1 ومفيش حظر) */
  effective: {
    score: number
    scoreBand: ScoreBand
    banStatus: BanStatus
    isCurrentlyBanned: boolean
    bannedUntil: string | null
    minutesLeftOnBan: number | null
    isAllowlisted: boolean
    isManualBan: boolean
    isKnownBotnet: boolean
    failedChecksCount: number
    reputationRiskPoints: number
  }
}

export interface AppliedSignalResult {
  type: SignalType
  points: number
  /** اتجاهل لأنه اتسجل قبل كده خلال dedupeWindowSec */
  deduped: boolean
}

export interface ApplyReputationResult {
  /** false = ما اتعملش أي تغيير (زائر نضيف من غير سجل، أو تقرير مكرر) */
  applied: boolean
  entry: ReputationEntryPublic | null
  change: {
    scoreBefore: number
    scoreAfter: number
    pointsRaw: number
    pointsApplied: number
    decayApplied: number
    failedChecksBefore: number
    failedChecksAfter: number
    banStatusBefore: BanStatus
    banStatusAfter: BanStatus
    newlyBanned: boolean
    banType: 'TEMPORARY' | 'PERMANENT' | null
    signals: AppliedSignalResult[]
  } | null
}

export interface ApplyReputationBatchResult {
  results: Array<
    | { index: number; ok: true; result: ApplyReputationResult }
    | { index: number; ok: false; code: string; message: string }
  >
  summary: { total: number; succeeded: number; failed: number; newlyBanned: number }
}

export interface ReputationStatsResult {
  total: number
  byBanStatus: Record<BanStatus, number>
  byBand: Record<ScoreBand, number>
  allowlisted: number
  knownBotnets: number
}

export interface GatewayBanItem {
  id: string
  organizationId: string
  ipAddress: string
  deviceFingerprint: string | null
  ja3Fingerprint: string | null
  ja4Fingerprint: string | null
  banStatus: BanStatus
  bannedUntil: string | null
  isAllowlisted: boolean
  updatedAt: string
}

export interface GatewayBansListResult {
  bans: GatewayBanItem[]
  nextCursor: string | null
  serverTime: string
}

// ==================================================================
// 13) Types
// ==================================================================

export type ListReputationQuery = z.infer<typeof listReputationQuerySchema>
export type ReputationIdParams = z.infer<typeof reputationIdParamsSchema>
export type ReputationChallengesQuery = z.infer<typeof reputationChallengesQuerySchema>
export type ManualBanInput = z.infer<typeof manualBanBodySchema>
export type UnbanInput = z.infer<typeof unbanBodySchema>
export type AllowlistInput = z.infer<typeof allowlistBodySchema>
export type ResetReputationInput = z.infer<typeof resetReputationBodySchema>
export type LookupReputationQuery = z.infer<typeof lookupReputationQuerySchema>
export type ApplyReputationInput = z.infer<typeof applyReputationBodySchema>
export type ApplyReputationBatchInput = z.infer<typeof applyReputationBatchBodySchema>
export type GatewayBansQuery = z.infer<typeof gatewayBansQuerySchema>