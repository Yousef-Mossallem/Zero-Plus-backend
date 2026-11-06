// backend/src/modules/servers/servers.schema.ts
// ==================================================================
// Zero Plus - Servers Validation Schemas
// ------------------------------------------------------------------
// مصدر الحقيقة لكل ما يخص السيرفرات المحمية، ومتطابق مع model Server
// في schema.prisma (originIp / originPort / sslEnabled / mode ...).
//
// Dashboard (JWT)  → prefix: /servers
//   POST   /                       إنشاء سيرفر (+ تعليمات DNS)
//   GET    /                       قائمة السيرفرات
//   GET    /:id                    تفاصيل سيرفر
//   PATCH  /:id                    تعديل
//   DELETE /:id?confirmDomain=     حذف (بتأكيد اسم الدومين)
//   GET    /:id/dns                تعليمات الـ DNS
//   POST   /:id/verify             فحص الـ DNS (ملكية / توجيه / الاتنين)
//   POST   /:id/maintenance        تشغيل/إيقاف وضع الصيانة
//
// Gateway (X-Gateway-Key) → prefix: /internal/gateway
//   GET  /servers                  مزامنة كل السيرفرات (cursor + updatedSince)
//   GET  /servers/resolve?host=    سيرفر واحد من الـ Host
//   POST /servers/:id/health       الـ Gateway يبلّغ بحالة السيرفر (+ نتائج Probe)
//
// ملاحظة: متوافق مع Zod v3 و v4 (من غير required_error).
// ==================================================================

import { isIP } from 'node:net'
import { domainToASCII } from 'node:url'
import { z } from 'zod'
import type { ServerMode, ServerStatus } from '@prisma/client'

// ==================================================================
// 1) Enums (متطابقة مع Prisma، والـ TypeScript هيكسر الـ build لو اختلفت)
// ==================================================================

export const SERVER_MODES = [
  'PROTECT',
  'MONITOR_ONLY',
] as const satisfies readonly ServerMode[]

export const SERVER_STATUSES = [
  'PENDING',
  'ONLINE',
  'DEGRADED',
  'OFFLINE',
  'MAINTENANCE',
] as const satisfies readonly ServerStatus[]

// ==================================================================
// 2) الدومين
// ==================================================================

export type DomainCheck =
  | { ok: true; value: string }
  | { ok: false; message: string }

const fail = (message: string): DomainCheck => ({ ok: false, message })

const LABEL_REGEX = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
const TLD_REGEX = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/

// نطاقات داخلية/محجوزة ما ينفعش تتحمي
const RESERVED_DOMAIN = 'localhost'
const RESERVED_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.lan',
  '.home.arpa',
  '.invalid',
  '.onion',
] as const

/**
 * نطاقات المنصة نفسها (مثلًا zeroplus.app) عشان شركة ما تسجلهاش.
 * في .env:  PLATFORM_DOMAINS=zeroplus.app,zeroplus.com
 */
function getPlatformDomains(): string[] {
  return (process.env.PLATFORM_DOMAINS ?? '')
    .split(',')
    .map((d) => d.trim().toLowerCase().replace(/\.$/, ''))
    .filter(Boolean)
}

/**
 * توحيد الدومين + التحقق منه (للإنشاء والتعديل).
 */
export function normalizeDomain(raw: string): DomainCheck {
  let value = raw.trim().toLowerCase()

  if (!value) return fail('النطاق مطلوب')

  if (/^[a-z][a-z0-9+.-]*:\/\//.test(value)) {
    return fail('اكتب اسم النطاق فقط بدون http:// أو https://')
  }

  if (/[\s/?#@\\]/.test(value)) {
    return fail('اكتب اسم النطاق فقط (بدون مسار أو مسافات أو رموز إضافية)')
  }

  if (value.startsWith('*.')) {
    return fail(
      'نطاقات wildcard (*.example.com) غير مدعومة، أضف كل نطاق فرعي على حدة',
    )
  }

  if (value.includes(':')) {
    return fail('لا تكتب رقم المنفذ مع النطاق، استخدم حقل originPort')
  }

  value = value.replace(/\.$/, '')

  const ascii = domainToASCII(value)

  if (!ascii) return fail('صيغة النطاق غير صحيحة')

  if (isIP(ascii)) return fail('النطاق لا يمكن أن يكون عنوان IP')

  if (ascii.length > 253) return fail('النطاق طويل جدًا')

  const labels = ascii.split('.')

  if (labels.length < 2) {
    return fail('النطاق يجب أن يحتوي على امتداد (مثال: shop.example.com)')
  }

  if (!labels.every((label) => LABEL_REGEX.test(label))) {
    return fail(
      'صيغة النطاق غير صحيحة (حروف وأرقام وشرطة فقط، والشرطة لا تكون أول أو آخر الجزء)',
    )
  }

  if (!TLD_REGEX.test(labels[labels.length - 1]!)) {
    return fail('امتداد النطاق غير صحيح')
  }

  if (
    ascii === RESERVED_DOMAIN ||
    RESERVED_SUFFIXES.some((suffix) => ascii.endsWith(suffix))
  ) {
    return fail('هذا النطاق داخلي أو محجوز ولا يمكن حمايته')
  }

  if (getPlatformDomains().some((d) => ascii === d || ascii.endsWith(`.${d}`))) {
    return fail('هذا النطاق تابع للمنصة ولا يمكن تسجيله')
  }

  return { ok: true, value: ascii }
}

/**
 * توحيد الـ Host القادم من الـ Gateway أو من تأكيد الحذف.
 */
export function normalizeHostHeader(raw: string): string | null {
  const host = raw
    .trim()
    .toLowerCase()
    .replace(/:\d{1,5}$/, '')
    .replace(/\.$/, '')

  if (!host) return null

  const ascii = domainToASCII(host)

  if (!ascii || ascii.length > 253) return null

  if (!ascii.split('.').every((label) => LABEL_REGEX.test(label))) return null

  return ascii
}

// ==================================================================
// 3) عنوان الـ Origin (IPv4 فقط في الـ MVP)
// ==================================================================

export type IpClass = 'PUBLIC' | 'PRIVATE' | 'FORBIDDEN'

export function classifyIPv4(ip: string): IpClass {
  const [a, b] = ip.split('.').map(Number) as [number, number]

  if (a === 0) return 'FORBIDDEN'
  if (a >= 224) return 'FORBIDDEN'
  if (a === 169 && b === 254) return 'FORBIDDEN'

  if (a === 127) return 'PRIVATE'
  if (a === 10) return 'PRIVATE'
  if (a === 172 && b >= 16 && b <= 31) return 'PRIVATE'
  if (a === 192 && b === 168) return 'PRIVATE'
  if (a === 100 && b >= 64 && b <= 127) return 'PRIVATE'

  return 'PUBLIC'
}

export function allowPrivateOrigins(): boolean {
  const flag = process.env.ALLOW_PRIVATE_ORIGINS

  if (flag === 'true') return true
  if (flag === 'false') return false

  return process.env.NODE_ENV !== 'production'
}

export type OriginIpCheck =
  | { ok: true; value: string }
  | { ok: false; message: string }

export function validateOriginIp(raw: string): OriginIpCheck {
  const value = raw.trim()

  if (!value) return { ok: false, message: 'عنوان IP مطلوب' }

  const version = isIP(value)

  if (version === 6) {
    return { ok: false, message: 'IPv6 غير مدعوم حاليًا، استخدم عنوان IPv4' }
  }

  if (version !== 4) {
    return { ok: false, message: 'صيغة عنوان IP غير صحيحة' }
  }

  const ipClass = classifyIPv4(value)

  if (ipClass === 'FORBIDDEN') {
    return {
      ok: false,
      message:
        'هذا العنوان محجوز ولا يمكن استخدامه (عنوان خاص بالنظام أو الشبكة أو Cloud Metadata)',
    }
  }

  if (ipClass === 'PRIVATE' && !allowPrivateOrigins()) {
    return {
      ok: false,
      message:
        'يجب أن يكون الـ Origin عنوان IP عامًا (العناوين الداخلية غير مسموحة)',
    }
  }

  return { ok: true, value }
}

// ==================================================================
// 4) المنفذ
// ==================================================================

const BLOCKED_ORIGIN_PORTS: ReadonlySet<number> = new Set([
  22, 23, 25, 110, 143, 465, 587, 993, 995, 1433, 3306, 5432, 6379, 9200,
  11211, 27017,
])

// ==================================================================
// 5) تعريف الحقول (مرة واحدة)
// ==================================================================

const domainField = z
  .string({ message: 'النطاق مطلوب' })
  .max(300, 'النطاق طويل جدًا')
  .transform((raw, ctx) => {
    const result = normalizeDomain(raw)

    if (!result.ok) {
      ctx.addIssue({ code: 'custom', message: result.message })
      return z.NEVER
    }

    return result.value
  })

const originIpField = z
  .string({ message: 'عنوان IP مطلوب' })
  .max(45, 'صيغة عنوان IP غير صحيحة')
  .transform((raw, ctx) => {
    const result = validateOriginIp(raw)

    if (!result.ok) {
      ctx.addIssue({ code: 'custom', message: result.message })
      return z.NEVER
    }

    return result.value
  })

const originPortField = z
  .number({ message: 'المنفذ يجب أن يكون رقمًا' })
  .int('المنفذ يجب أن يكون رقمًا صحيحًا')
  .min(1, 'المنفذ يجب أن يكون بين 1 و 65535')
  .max(65535, 'المنفذ يجب أن يكون بين 1 و 65535')
  .refine((port) => !BLOCKED_ORIGIN_PORTS.has(port), {
    message: 'هذا المنفذ مخصص لخدمة غير ويب ولا يمكن استخدامه كـ Origin',
  })

const sslEnabledField = z.boolean({
  message: 'sslEnabled يجب أن يكون true أو false',
})

const modeField = z.enum(SERVER_MODES, {
  message: 'mode يجب أن يكون PROTECT أو MONITOR_ONLY',
})

// ==================================================================
// 6) إنشاء سيرفر  (POST /servers)
// ==================================================================

export const createServerSchema = z
  .object({
    domain: domainField,
    originIp: originIpField,
    originPort: originPortField.default(443),
    sslEnabled: sslEnabledField.optional(),
    mode: modeField.optional(),
  })
  .strict()
  .transform((data) => ({
    ...data,
    sslEnabled: data.sslEnabled ?? data.originPort !== 80,
  }))

// ==================================================================
// 7) تعديل سيرفر  (PATCH /servers/:id)
// ==================================================================

export const updateServerSchema = z
  .object({
    domain: domainField,
    originIp: originIpField,
    originPort: originPortField,
    sslEnabled: sslEnabledField,
    mode: modeField,
  })
  .partial()
  .strict()
  .refine((data) => Object.values(data).some((value) => value !== undefined), {
    message: 'يجب إرسال حقل واحد على الأقل للتعديل',
  })

// ==================================================================
// 8) Params / Query / Actions للـ Dashboard
// ==================================================================

export const serverIdParamsSchema = z.object({
  id: z.string({ message: 'معرف السيرفر مطلوب' }).uuid('معرف السيرفر غير صالح'),
})

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

export const listServersQuerySchema = z.object({
  page: queryInt(1, 1, 100_000),
  limit: queryInt(20, 1, 100),

  status: z.enum(SERVER_STATUSES).optional(),
  mode: z.enum(SERVER_MODES).optional(),
  dnsVerified: queryBoolean,

  search: z.string().trim().min(1).max(100).optional(),

  sortBy: z
    .enum(['createdAt', 'updatedAt', 'domain', 'status'])
    .default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
})

export const VERIFY_STEPS = ['ownership', 'routing', 'all'] as const

export const verifyServerSchema = z
  .object({
    step: z.enum(VERIFY_STEPS).default('all'),
  })
  .strict()

export const maintenanceSchema = z
  .object({
    enabled: z.boolean({ message: 'enabled يجب أن يكون true أو false' }),
  })
  .strict()

export const hostSchema = z
  .string({ message: 'host مطلوب' })
  .trim()
  .min(1, 'host مطلوب')
  .max(300, 'host طويل جدًا')
  .transform((raw, ctx) => {
    const host = normalizeHostHeader(raw)

    if (!host) {
      ctx.addIssue({ code: 'custom', message: 'host غير صالح' })
      return z.NEVER
    }

    return host
  })

export const deleteServerQuerySchema = z.object({
  confirmDomain: hostSchema,
})

// ==================================================================
// 9) الـ Gateway
// ==================================================================

export const gatewayServersQuerySchema = z.object({
  limit: queryInt(500, 1, 1000),
  cursor: z.string().uuid('cursor غير صالح').optional(),
  updatedSince: z
    .string()
    .datetime({
      message: 'updatedSince يجب أن يكون تاريخ ISO بصيغة UTC (ينتهي بـ Z)',
    })
    .optional(),
})

export const gatewayServerResolveQuerySchema = z.object({
  host: hostSchema,
})

// ---- POST /internal/gateway/servers/:id/health ----
// يدعم تقارير الصحة العادية + نتائج Origin Probe الكاملة

const probeStepSchema = z.object({
  connections: z.number().int().min(1).max(2000),
  rps: z.number().int().min(0),
  p99Ms: z.number().int().min(0),
  errorRate: z.number().min(0).max(100),
})

export const gatewayHealthReportSchema = z
  .object({
    originReachable: z.boolean().optional(),
    gatewayReachable: z.boolean().optional(),
    avgResponseTimeMs: z.number().int().min(0).max(600_000).optional(),
    p95ResponseTimeMs: z.number().int().min(0).max(600_000).optional(),
    loadLatencyP99Ms: z.number().int().min(0).max(600_000).optional(),
    currentLoadPercent: z.number().min(0).max(100).optional(),
    maxRequestsPerSecond: z.number().int().min(0).optional(),
    safeRequestsPerSecond: z.number().int().min(0).optional(),
    probeErrorRate: z.number().min(0).max(100).optional(),
    probeConfidence: z.enum(['high', 'medium', 'low']).optional(),
    probeRecommendation: z
      .enum(['excellent', 'good', 'fair', 'poor', 'down'])
      .optional(),
    probeDetails: z
      .object({
        steps: z.array(probeStepSchema).max(20),
        runs: z.array(z.object({ rps: z.number().int().min(0) })).max(10),
        saturated: z.boolean().optional(),
        redirected: z.boolean().optional(),
      })
      .optional(),
    lastError: z.string().trim().max(500).optional(),
  })
  .strict()
  .refine(
    (d) =>
      Object.entries(d).some(
        ([k, v]) => k !== 'lastError' && v !== undefined,
      ),
    { message: 'يجب إرسال قيمة صحة واحدة على الأقل' },
  )

// ==================================================================
// 10) إعدادات وتعليمات الـ DNS
// ==================================================================

export const DNS_TXT_LABEL = '_zeroplus-verify'
export const DNS_TXT_VALUE_PREFIX = 'zeroplus-verify='
export const DNS_RECOMMENDED_TTL = 300

export interface DnsConfig {
  cnameTarget: string | null
  gatewayIps: string[]
}

export function readDnsConfig(env: NodeJS.ProcessEnv = process.env): DnsConfig {
  const cnameTarget =
    env.GATEWAY_CNAME_TARGET?.trim().toLowerCase().replace(/\.$/, '') || null

  const gatewayIps = (env.GATEWAY_PUBLIC_IPS ?? '')
    .split(',')
    .map((ip) => ip.trim())
    .filter((ip) => isIP(ip) === 4)

  return { cnameTarget, gatewayIps }
}

export const dnsTxtRecordName = (domain: string) => `${DNS_TXT_LABEL}.${domain}`
export const dnsTxtRecordValue = (token: string) =>
  `${DNS_TXT_VALUE_PREFIX}${token}`

export interface DnsRecordInstruction {
  purpose: 'OWNERSHIP' | 'ROUTING'
  type: 'TXT' | 'CNAME' | 'A'
  name: string
  value: string
  ttl: number
  note?: string
}

export interface DnsInstructions {
  domain: string
  ownership: DnsRecordInstruction
  routing: DnsRecordInstruction[]
  steps: string[]
  warnings: string[]
}

export function buildDnsInstructions(
  server: { domain: string; verificationToken: string },
  config: DnsConfig,
): DnsInstructions {
  const { domain, verificationToken } = server

  const ownership: DnsRecordInstruction = {
    purpose: 'OWNERSHIP',
    type: 'TXT',
    name: dnsTxtRecordName(domain),
    value: dnsTxtRecordValue(verificationToken),
    ttl: DNS_RECOMMENDED_TTL,
    note: 'يثبت إنك مالك الدومين. لا تحذفه بعد التحقق.',
  }

  const routing: DnsRecordInstruction[] = []

  if (config.cnameTarget) {
    routing.push({
      purpose: 'ROUTING',
      type: 'CNAME',
      name: domain,
      value: config.cnameTarget,
      ttl: DNS_RECOMMENDED_TTL,
      note: 'للنطاقات الفرعية (shop.example.com). لا يصلح مع النطاق الرئيسي.',
    })
  }

  for (const ip of config.gatewayIps) {
    routing.push({
      purpose: 'ROUTING',
      type: 'A',
      name: domain,
      value: ip,
      ttl: DNS_RECOMMENDED_TTL,
      note: 'يصلح للنطاق الرئيسي (example.com) والفرعي.',
    })
  }

  const warnings: string[] = [
    'Delete any old A/CNAME record for this domain before adding the routing record, otherwise traffic will keep going straight to the origin server without protection.',
    'After activation, lock down the origin server to the Gateway addresses only (Firewall). If the attacker knows the origin IP, they will attack it directly and bypass the protection.',
  ]

  if (routing.length === 0) {
    warnings.unshift(
      'إعدادات توجيه الـ Gateway (GATEWAY_CNAME_TARGET / GATEWAY_PUBLIC_IPS) غير مضبوطة في السيرفر.',
    )
  }
  return {
    domain,
    ownership,
    routing,
    steps: [
      'Add a TXT record to verify domain ownership in your DNS panel.',
      'Click "Verify" (step: ownership) after the record has propagated (it may take a few minutes).',
      'Point the domain to the Gateway using a CNAME or A record (only one of them).',
      'Click "Verify" (step: routing). If it succeeds, traffic will start flowing through the protection.',
      'Start with MONITOR_ONLY mode to observe decisions, then switch to PROTECT.',
    ],
    warnings,
  }
}

// ==================================================================
// 11) أشكال الردود (يبنيها الـ Service)
// ==================================================================

export interface DnsCheckResult {
  verified: boolean
  expected: string[]
  found: string[]
  checkedAt: string
  message: string
}

export interface DnsVerificationResult {
  ownership?: DnsCheckResult
  routing?: DnsCheckResult
  server: {
    id: string
    status: ServerStatus
    dnsVerified: boolean
    gatewayReachable: boolean
  }
}

/** السيرفر بالشكل اللي الـ Gateway بيستخدمه */
export interface GatewayServerPayload {
  id: string
  domain: string
  organizationId: string
  originIp: string
  originPort: number
  sslEnabled: boolean
  status: ServerStatus
  mode: ServerMode
  dnsVerified: boolean
  gatewayReachable: boolean
  originReachable: boolean
  maxRequestsPerSecond: number | null
  /** رقم التسعير الآمن من آخر Probe */
  safeRequestsPerSecond: number | null
  updatedAt: string
}

export interface GatewayServersListResult {
  servers: GatewayServerPayload[]
  nextCursor: string | null
  serverTime: string
}

// ==================================================================
// 12) Types
// ==================================================================

export type CreateServerInput = z.infer<typeof createServerSchema>
export type UpdateServerInput = z.infer<typeof updateServerSchema>
export type ServerIdParams = z.infer<typeof serverIdParamsSchema>
export type ListServersQuery = z.infer<typeof listServersQuerySchema>
export type VerifyServerInput = z.infer<typeof verifyServerSchema>
export type MaintenanceInput = z.infer<typeof maintenanceSchema>
export type DeleteServerQuery = z.infer<typeof deleteServerQuerySchema>
export type GatewayServersQuery = z.infer<typeof gatewayServersQuerySchema>
export type GatewayServerResolveQuery = z.infer<
  typeof gatewayServerResolveQuerySchema
>
export type GatewayHealthReport = z.infer<typeof gatewayHealthReportSchema>