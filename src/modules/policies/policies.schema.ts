// backend/src/modules/policies/policies.schema.ts
// ==================================================================
// Zero Plus - Policies Validation Schemas
// ------------------------------------------------------------------
// مصدر الحقيقة الوحيد لحقول الـ Policy (متطابق مع model Policy في schema.prisma)
//
// Dashboard (JWT):
//   GET   /api/policies/me
//   PATCH /api/policies/me
//   POST  /api/policies/me/reset
//   GET   /api/policies/defaults
//
// Gateway (X-Gateway-Key):
//   GET /internal/gateway/policies/resolve?host=example.com   (الأساسي)
//   GET /internal/gateway/policies/by-server/:serverId
//   GET /internal/gateway/policies/by-org/:organizationId
// ==================================================================

import { z } from 'zod'
import type { ServerMode, ServerStatus } from '@prisma/client'

// ==================================================================
// 1) قائمة الحقول القابلة للتعديل (نفس أسماء Prisma بالحرف)
// ==================================================================

export const POLICY_EDITABLE_FIELDS = [
  // حدود الـ Risk Score
  'allowMaxScore',
  'rateLimitMaxScore',
  'challengeMaxScore',

  // الاختبار الأساسي (JS Challenge)
  'enableJsChallenge',
  'challengeAllVisitors',
  'passTokenTtlMinutes',

  // Rate Limit الناعم
  'rateLimitRequests',
  'rateLimitWindowSec',

  // الحد الأقصى الصارم (تحدده الشركة)
  'maxRequestsPerIp',
  'maxRequestsWindowSec',
  'banOnMaxRequests',
  'maxServerRps',
  'capacityWarnPercent',

  // الحظر التلقائي
  'autoBanAfterFails',
  'temporaryBanMinutes',
  'permanentBanScore',

  // ميزات
  'enableAiAnomaly',
] as const

export type PolicyFieldKey = (typeof POLICY_EDITABLE_FIELDS)[number]

// ==================================================================
// 2) القيم الافتراضية
// لازم تطابق @default في schema.prisma
// بتُستخدم في: GET /defaults و POST /reset فقط
// (إنشاء Policy جديدة بيعتمد على @default في قاعدة البيانات مباشرة)
// ==================================================================

export const POLICY_DEFAULTS = {
  allowMaxScore: 30,
  rateLimitMaxScore: 60,
  challengeMaxScore: 80,

  enableJsChallenge: true,
  challengeAllVisitors: true,
  passTokenTtlMinutes: 60,

  rateLimitRequests: 30,
  rateLimitWindowSec: 60,

  maxRequestsPerIp: 300,
  maxRequestsWindowSec: 60,
  banOnMaxRequests: true,
  maxServerRps: null,
  capacityWarnPercent: 80,

  autoBanAfterFails: 2,
  temporaryBanMinutes: 120,
  permanentBanScore: 9,

  enableAiAnomaly: true,
} as const satisfies Record<PolicyFieldKey, number | boolean | null>

// ==================================================================
// 3) تعريف كل حقل مرة واحدة (المدى + رسالة الخطأ)
// ==================================================================

const policyFieldsShape = {
  // ---- حدود الـ Risk Score (0-100) ----
  // challengeMaxScore أقصاها 99 عشان منطقة الـ BLOCK ما تختفيش
  allowMaxScore: z
    .number()
    .int('allowMaxScore يجب أن يكون رقمًا صحيحًا')
    .min(0, 'allowMaxScore لا يقل عن 0')
    .max(99, 'allowMaxScore لا يزيد عن 99'),

  rateLimitMaxScore: z
    .number()
    .int('rateLimitMaxScore يجب أن يكون رقمًا صحيحًا')
    .min(0, 'rateLimitMaxScore لا يقل عن 0')
    .max(99, 'rateLimitMaxScore لا يزيد عن 99'),

  challengeMaxScore: z
    .number()
    .int('challengeMaxScore يجب أن يكون رقمًا صحيحًا')
    .min(0, 'challengeMaxScore لا يقل عن 0')
    .max(99, 'challengeMaxScore لا يزيد عن 99 (فوقه BLOCK)'),

  // ---- الاختبار الأساسي ----
  enableJsChallenge: z.boolean(),
  challengeAllVisitors: z.boolean(),

  passTokenTtlMinutes: z
    .number()
    .int('passTokenTtlMinutes يجب أن يكون رقمًا صحيحًا')
    .min(1, 'passTokenTtlMinutes لا يقل عن دقيقة')
    .max(1440, 'passTokenTtlMinutes لا يزيد عن 1440 (يوم)'),

  // ---- Rate Limit الناعم ----
  rateLimitRequests: z
    .number()
    .int('rateLimitRequests يجب أن يكون رقمًا صحيحًا')
    .min(1, 'rateLimitRequests لا يقل عن 1')
    .max(100_000, 'rateLimitRequests لا يزيد عن 100000'),

  rateLimitWindowSec: z
    .number()
    .int('rateLimitWindowSec يجب أن يكون رقمًا صحيحًا')
    .min(1, 'rateLimitWindowSec لا يقل عن ثانية')
    .max(3600, 'rateLimitWindowSec لا يزيد عن 3600 (ساعة)'),

  // ---- الحد الأقصى الصارم ----
  maxRequestsPerIp: z
    .number()
    .int('maxRequestsPerIp يجب أن يكون رقمًا صحيحًا')
    .min(1, 'maxRequestsPerIp لا يقل عن 1')
    .max(1_000_000, 'maxRequestsPerIp لا يزيد عن 1000000'),

  maxRequestsWindowSec: z
    .number()
    .int('maxRequestsWindowSec يجب أن يكون رقمًا صحيحًا')
    .min(1, 'maxRequestsWindowSec لا يقل عن ثانية')
    .max(3600, 'maxRequestsWindowSec لا يزيد عن 3600 (ساعة)'),

  banOnMaxRequests: z.boolean(),

  // null = ما فيش سقف من الشركة، والـ Gateway ياخد Server.maxRequestsPerSecond
  maxServerRps: z
    .number()
    .int('maxServerRps يجب أن يكون رقمًا صحيحًا')
    .min(1, 'maxServerRps لا يقل عن 1')
    .max(1_000_000, 'maxServerRps لا يزيد عن 1000000')
    .nullable(),

  capacityWarnPercent: z
    .number()
    .int('capacityWarnPercent يجب أن يكون رقمًا صحيحًا')
    .min(1, 'capacityWarnPercent لا يقل عن 1')
    .max(100, 'capacityWarnPercent لا يزيد عن 100'),

  // ---- الحظر التلقائي ----
  autoBanAfterFails: z
    .number()
    .int('autoBanAfterFails يجب أن يكون رقمًا صحيحًا')
    .min(1, 'autoBanAfterFails لا يقل عن 1')
    .max(20, 'autoBanAfterFails لا يزيد عن 20'),

  temporaryBanMinutes: z
    .number()
    .int('temporaryBanMinutes يجب أن يكون رقمًا صحيحًا')
    .min(1, 'temporaryBanMinutes لا يقل عن دقيقة')
    .max(10_080, 'temporaryBanMinutes لا يزيد عن 10080 (أسبوع)'),

  // السمعة من 1 إلى 10 (ReputationEntry.score)
  permanentBanScore: z
    .number()
    .int('permanentBanScore يجب أن يكون رقمًا صحيحًا')
    .min(1, 'permanentBanScore لا يقل عن 1')
    .max(10, 'permanentBanScore لا يزيد عن 10'),

  // ---- ميزات ----
  enableAiAnomaly: z.boolean(),
} satisfies Record<PolicyFieldKey, z.ZodTypeAny>

const fullPolicyObject = z.object(policyFieldsShape)

/** كل قيم الـ Policy (كلها موجودة) */
export type PolicyValues = z.infer<typeof fullPolicyObject>

// ==================================================================
// 4) قواعد الترابط بين الحقول
// نفس الدالة بتُستخدم في مكانين:
//   - هنا (Zod) على الحقول المبعوتة فقط (قاعدة بتتفحص لو الطرفين موجودين)
//   - في الـ Service على القيم بعد الدمج مع الحالية (الفحص الكامل)
// ==================================================================

export interface PolicyViolation {
  path: PolicyFieldKey
  message: string
}

export function findPolicyViolations(
  v: { [K in keyof PolicyValues]?: PolicyValues[K] | undefined },
): PolicyViolation[] {
  const violations: PolicyViolation[] = []

  const {
    allowMaxScore: allow,
    rateLimitMaxScore: rate,
    challengeMaxScore: challenge,
  } = v

  // الترتيب: allow ≤ rateLimit ≤ challenge
  if (allow !== undefined && rate !== undefined && allow > rate) {
    violations.push({
      path: 'allowMaxScore',
      message: 'allowMaxScore يجب أن يكون أقل من أو يساوي rateLimitMaxScore',
    })
  }

  if (rate !== undefined && challenge !== undefined && rate > challenge) {
    violations.push({
      path: 'rateLimitMaxScore',
      message: 'rateLimitMaxScore يجب أن يكون أقل من أو يساوي challengeMaxScore',
    })
  }

  if (allow !== undefined && challenge !== undefined && allow > challenge) {
    violations.push({
      path: 'allowMaxScore',
      message: 'allowMaxScore يجب أن يكون أقل من أو يساوي challengeMaxScore',
    })
  }

  // الحد الصارم (طلب/ثانية) لازم يكون أكبر من أو يساوي الحد الناعم
  // وإلا الـ Rate Limit الناعم عمره ما هيتطبق قبل الحظر
  if (
    v.rateLimitRequests !== undefined &&
    v.rateLimitWindowSec !== undefined &&
    v.maxRequestsPerIp !== undefined &&
    v.maxRequestsWindowSec !== undefined
  ) {
    const softRps = v.rateLimitRequests / v.rateLimitWindowSec
    const hardRps = v.maxRequestsPerIp / v.maxRequestsWindowSec

    if (hardRps < softRps) {
      violations.push({
        path: 'maxRequestsPerIp',
        message:
          'الحد الأقصى للطلبات (maxRequestsPerIp / maxRequestsWindowSec) يجب ألا يقل عن حد الـ Rate Limit (rateLimitRequests / rateLimitWindowSec)',
      })
    }
  }

  return violations
}

// ==================================================================
// 5) PATCH /api/policies/me
// ==================================================================

export const updatePolicySchema = z
  .object(policyFieldsShape)
  .partial()
  // حقل غير معروف = 400 (بدل ما يتشال بصمت ويبان إن التعديل نجح)
  .strict()
  .refine((data) => Object.keys(data).length > 0, {
    message: 'يجب إرسال حقل واحد على الأقل للتعديل',
  })
  .superRefine((data, ctx) => {
    for (const violation of findPolicyViolations(data)) {
      ctx.addIssue({
        code: 'custom',
        path: [violation.path],
        message: violation.message,
      })
    }
  })

export type UpdatePolicyInput = z.infer<typeof updatePolicySchema>

// ==================================================================
// 6) POST /api/policies/me/reset
// body: { "confirm": true }                        → رجوع كل الإعدادات للافتراضي
// body: { "confirm": true, "fields": ["..."] }     → رجوع حقول محددة فقط
// ==================================================================

export const resetPolicySchema = z
  .object({
    confirm: z.literal(true),
    fields: z
      .array(z.enum(POLICY_EDITABLE_FIELDS))
      .min(1, 'اختر حقلًا واحدًا على الأقل أو احذف fields')
      .max(POLICY_EDITABLE_FIELDS.length)
      .optional(),
  })
  .strict()

export type ResetPolicyInput = z.infer<typeof resetPolicySchema>

// ==================================================================
// 7) Gateway: تحديد الشركة والسيرفر
// ------------------------------------------------------------------
// الـ Gateway بيستقبل طلب زائر على Host معين، فبيسأل الباك:
//   GET /internal/gateway/policies/resolve?host=shop.example.com
// والباك يرجّع: أنهي سيرفر + أنهي شركة + الـ Policy بتاعتها
// ==================================================================

const HOST_REGEX =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/

/**
 * توحيد شكل الـ Host:
 * - lowercase
 * - إزالة البورت (shop.com:8080 → shop.com)
 * - إزالة النقطة الأخيرة (shop.com. → shop.com)
 *
 * لازم يطابق طريقة تخزين Server.domain (lowercase + trim)
 */
export function normalizeHost(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/:\d+$/, '')
    .replace(/\.$/, '')
}

export const hostSchema = z
  .string()
  .trim()
  .min(1, 'host مطلوب')
  .max(260)
  .transform(normalizeHost)
  .pipe(
    z
      .string()
      .min(1, 'host غير صالح')
      .max(253, 'host طويل جدًا')
      .regex(HOST_REGEX, 'host غير صالح'),
  )

// GET /internal/gateway/policies/resolve?host=...
export const gatewayResolveQuerySchema = z.object({
  host: hostSchema,
})

// GET /internal/gateway/policies/by-server/:serverId
export const gatewayPolicyByServerParamsSchema = z.object({
  serverId: z.string().uuid('serverId غير صالح'),
})

// GET /internal/gateway/policies/by-org/:organizationId
export const gatewayPolicyByOrgParamsSchema = z.object({
  organizationId: z.string().uuid('organizationId غير صالح'),
})

export type GatewayResolveQuery = z.infer<typeof gatewayResolveQuerySchema>
export type GatewayPolicyByServerParams = z.infer<
  typeof gatewayPolicyByServerParamsSchema
>
export type GatewayPolicyByOrgParams = z.infer<
  typeof gatewayPolicyByOrgParamsSchema
>

// ==================================================================
// 8) شكل الرد اللي الـ Gateway بياخده (يتبني في الـ Service)
// ==================================================================

/** الـ Policy اللي الـ Gateway بيستخدمها (من غير id ولا timestamps) */
export type GatewayPolicyPayload = PolicyValues & {
  organizationId: string
}

export interface GatewayResolveResult {
  // ---- تحديد الهوية ----
  organizationId: string

  server: {
    id: string
    domain: string
    originIp: string
    originPort: number
    status: ServerStatus
    mode: ServerMode // PROTECT | MONITOR_ONLY
    maxRequestsPerSecond: number | null
  }

  // ---- القواعد ----
  policy: GatewayPolicyPayload

  /**
   * السقف الفعلي للسيرفر كله (طلب/ثانية):
   * policy.maxServerRps لو الشركة حددته، وإلا server.maxRequestsPerSecond
   * null = مفيش سقف
   */
  effectiveMaxServerRps: number | null

  /**
   * نسخة الـ Policy = Policy.updatedAt (ISO)
   * الـ Gateway يقارنها ويعمل refresh للـ cache لما تتغير
   */
  policyVersion: string
}