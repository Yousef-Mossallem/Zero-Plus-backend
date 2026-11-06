// ==================================================================
// Zero Plus - Simulations Module — Zod Validation Schemas
// ------------------------------------------------------------------
// كل مدخلات Simulation Lab تتتحقق هنا قبل الـ Service / Worker
// متوافق مع:
//   - Prisma: SimulationPattern / SimulationStatus / SimulationIntensity
//   - Frontend: POST /simulations + options المتقدمة
//   - Gateway: token + personas + AI المؤقت
// ==================================================================

import { z } from 'zod'

// ------------------------------------------------------------------
// Helper: يقبل الحروف الصغيرة والكبيرة (الفرونت بيبعت lowercase)
// بيحوّل النص لحروف كبيرة قبل التحقق من الـ enum
// ------------------------------------------------------------------

const upperEnum = <T extends z.ZodTypeAny>(schema: T) =>
  z.preprocess(
    (v) => (typeof v === 'string' ? v.trim().toUpperCase() : v),
    schema,
  )

// ------------------------------------------------------------------
// Enums (نفس أسماء Prisma — String enum في Zod)
// ------------------------------------------------------------------

export const simulationPatternSchema = upperEnum(
  z.enum([
    'REALISTIC_MIX',
    'LEGIT_ONLY',
    'LOGIN_FOCUS',
    'RATE_STRESS',
    'BOT_WAVE',
    'BAN_RECOVERY',
    'FULL_PIPELINE',
    'CUSTOM',
    // توافق قديم
    'NORMAL',
    'SUSPICIOUS_BURST',
    'REPEATED_REQUESTS',
    'UNUSUAL_BEHAVIOR',
    'KNOWN_TEST_SOURCE',
  ]),
)

export const simulationStatusSchema = z.enum([
  'PENDING',
  'RUNNING',
  'STOPPED',
  'COMPLETED',
  'FAILED',
])

export const simulationIntensitySchema = upperEnum(
  z.enum(['LOW', 'MEDIUM', 'HIGH']),
)

export const simulationPersonaSchema = z.enum([
  'legit_ok',
  'legit_sensitive',
  'rate_soft',
  'rate_hard',
  'bot_ua',
  'fail_js',
  'pass_js',
  'bad_ip',
])

export const simulationAiModeSchema = z.enum(['auto', 'fixed', 'off'])

// ------------------------------------------------------------------
// حدود تشغيل آمنة (الـ Service يقدر يضيّق حسب plan لاحقًا)
// ------------------------------------------------------------------

export const SIM_LIMITS = {
  durationSecMin: 30,
  durationSecMax: 900,
  targetRpsMin: 1,
  targetRpsMax: 200,
  maxRpsMin: 1,
  maxRpsMax: 300,
  ipPoolMin: 1,
  ipPoolMax: 500,
  pathMaxLen: 256,
  pathsMaxCount: 30,
  weightMax: 1000,
} as const

// ------------------------------------------------------------------
// أوزان الشخصيات — أرقام ≥ 0؛ المجموع يُتحقق في superRefine
// ------------------------------------------------------------------

export const personaWeightsSchema = z
  .object({
    legit_ok: z.number().min(0).max(SIM_LIMITS.weightMax).optional(),
    legit_sensitive: z.number().min(0).max(SIM_LIMITS.weightMax).optional(),
    rate_soft: z.number().min(0).max(SIM_LIMITS.weightMax).optional(),
    rate_hard: z.number().min(0).max(SIM_LIMITS.weightMax).optional(),
    bot_ua: z.number().min(0).max(SIM_LIMITS.weightMax).optional(),
    fail_js: z.number().min(0).max(SIM_LIMITS.weightMax).optional(),
    pass_js: z.number().min(0).max(SIM_LIMITS.weightMax).optional(),
    bad_ip: z.number().min(0).max(SIM_LIMITS.weightMax).optional(),
  })
  .strict()

// ------------------------------------------------------------------
// options المتقدمة (كلها اختيارية — الديفولت في الـ Service حسب pattern)
// ------------------------------------------------------------------

const pathItemSchema = z
  .string()
  .min(1)
  .max(SIM_LIMITS.pathMaxLen)
  .refine((p) => p.startsWith('/'), {
    message: 'Each path must start with /',
  })

export const simulationOptionsSchema = z
  .object({
    personaWeights: personaWeightsSchema.optional(),

    ipPoolLegit: z
      .number()
      .int()
      .min(SIM_LIMITS.ipPoolMin)
      .max(SIM_LIMITS.ipPoolMax)
      .optional(),

    ipPoolAttack: z
      .number()
      .int()
      .min(SIM_LIMITS.ipPoolMin)
      .max(SIM_LIMITS.ipPoolMax)
      .optional(),

    enableJaHeaders: z.boolean().optional(),

    aiMode: simulationAiModeSchema.optional(),

    /** يُستخدم فقط إذا aiMode === 'fixed' */
    aiFixedScore: z.number().min(0).max(1).optional(),

    paths: z.array(pathItemSchema).max(SIM_LIMITS.pathsMaxCount).optional(),

    /** لإعادة نفس التوزيع العشوائي */
    seed: z.number().int().min(0).max(2_147_483_647).nullable().optional(),
  })
  .strict()
  .superRefine((opts, ctx) => {
    if (opts.aiMode === 'fixed' && opts.aiFixedScore === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'aiFixedScore is required when aiMode is fixed',
        path: ['aiFixedScore'],
      })
    }
  })

// ------------------------------------------------------------------
// 1) إنشاء Run — POST /simulations
// ------------------------------------------------------------------

export const createSimulationSchema = z
  .object({
    serverId: z.string().uuid('Invalid serverId'),

    pattern: simulationPatternSchema.default('REALISTIC_MIX'),

    durationSec: z
      .number()
      .int()
      .min(SIM_LIMITS.durationSecMin, `Minimum duration is ${SIM_LIMITS.durationSecMin}s`)
      .max(SIM_LIMITS.durationSecMax, `Maximum duration is ${SIM_LIMITS.durationSecMax}s`)
      .default(120),

    targetRps: z
      .number()
      .int()
      .min(SIM_LIMITS.targetRpsMin)
      .max(SIM_LIMITS.targetRpsMax)
      .default(15),

    maxRps: z
      .number()
      .int()
      .min(SIM_LIMITS.maxRpsMin)
      .max(SIM_LIMITS.maxRpsMax)
      .default(40),

    intensity: simulationIntensitySchema.default('MEDIUM'),

    options: simulationOptionsSchema.optional(),
  })
  .strict()
  .superRefine((data, ctx) => {
    if (data.maxRps < data.targetRps) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'maxRps must be greater than or equal to targetRps',
        path: ['maxRps'],
      })
    }

    // CUSTOM: لازم أوزان وبمجموع > 0
    if (data.pattern === 'CUSTOM') {
      const weights = data.options?.personaWeights
      if (!weights) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'options.personaWeights is required when pattern is CUSTOM',
          path: ['options', 'personaWeights'],
        })
        return
      }
      const sum = Object.values(weights).reduce<number>(
        (acc, v) => acc + (typeof v === 'number' ? v : 0),
        0,
      )
      if (sum <= 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Sum of personaWeights must be greater than 0',
          path: ['options', 'personaWeights'],
        })
      }
    }

    // لو اتبعت أوزان في أي نمط — المجموع > 0
    if (data.options?.personaWeights) {
      const sum = Object.values(data.options.personaWeights).reduce<number>(
        (acc, v) => acc + (typeof v === 'number' ? v : 0),
        0,
      )
      if (sum <= 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Sum of personaWeights must be greater than 0',
          path: ['options', 'personaWeights'],
        })
      }
    }
  })

// ------------------------------------------------------------------
// 2) قائمة Runs — GET /simulations
// ------------------------------------------------------------------

export const listSimulationsQuerySchema = z
  .object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    status: simulationStatusSchema.optional(),
    serverId: z.string().uuid().optional(),
    pattern: simulationPatternSchema.optional(),
  })
  .strict()

// ------------------------------------------------------------------
// 3) تفاصيل Run — params
// ------------------------------------------------------------------

export const simulationIdParamsSchema = z
  .object({
    id: z.string().uuid('Invalid simulation run id'),
  })
  .strict()

// ------------------------------------------------------------------
// 4) أحداث Run — GET /simulations/:id/events
// ------------------------------------------------------------------

export const simulationEventsQuerySchema = z
  .object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(50),
    decision: z
      .enum(['ALLOW', 'MONITOR', 'RATE_LIMIT', 'CHALLENGE', 'BLOCK'])
      .optional(),
  })
  .strict()

// ------------------------------------------------------------------
// 5) Stop — لا body؛ params فقط (schema صريح للتوثيق)
// ------------------------------------------------------------------

export const stopSimulationSchema = z.object({}).strict()

// ------------------------------------------------------------------
// أنواع TypeScript
// ------------------------------------------------------------------

export type SimulationPattern = z.infer<typeof simulationPatternSchema>
export type SimulationStatus = z.infer<typeof simulationStatusSchema>
export type SimulationIntensity = z.infer<typeof simulationIntensitySchema>
export type SimulationPersona = z.infer<typeof simulationPersonaSchema>
export type SimulationAiMode = z.infer<typeof simulationAiModeSchema>
export type PersonaWeights = z.infer<typeof personaWeightsSchema>
export type SimulationOptions = z.infer<typeof simulationOptionsSchema>
export type CreateSimulationInput = z.infer<typeof createSimulationSchema>
export type ListSimulationsQuery = z.infer<typeof listSimulationsQuerySchema>
export type SimulationIdParams = z.infer<typeof simulationIdParamsSchema>
export type SimulationEventsQuery = z.infer<typeof simulationEventsQuerySchema>

// ------------------------------------------------------------------
// ديفولتات أوزان حسب النمط (للاستخدام في Service — مش Zod parse)
// ------------------------------------------------------------------

export const DEFAULT_PERSONA_WEIGHTS: Record<
  Exclude<SimulationPattern, 'CUSTOM'>,
  Required<PersonaWeights>
> = {
  REALISTIC_MIX: {
    legit_ok: 45,
    legit_sensitive: 15,
    rate_soft: 10,
    rate_hard: 5,
    bot_ua: 8,
    fail_js: 7,
    pass_js: 5,
    bad_ip: 5,
  },
  LEGIT_ONLY: {
    legit_ok: 80,
    legit_sensitive: 20,
    rate_soft: 0,
    rate_hard: 0,
    bot_ua: 0,
    fail_js: 0,
    pass_js: 0,
    bad_ip: 0,
  },
  LOGIN_FOCUS: {
    legit_ok: 20,
    legit_sensitive: 50,
    rate_soft: 10,
    rate_hard: 0,
    bot_ua: 5,
    fail_js: 5,
    pass_js: 10,
    bad_ip: 0,
  },
  RATE_STRESS: {
    legit_ok: 15,
    legit_sensitive: 5,
    rate_soft: 40,
    rate_hard: 30,
    bot_ua: 5,
    fail_js: 0,
    pass_js: 0,
    bad_ip: 5,
  },
  BOT_WAVE: {
    legit_ok: 10,
    legit_sensitive: 5,
    rate_soft: 10,
    rate_hard: 10,
    bot_ua: 30,
    fail_js: 25,
    pass_js: 0,
    bad_ip: 10,
  },
  BAN_RECOVERY: {
    legit_ok: 25,
    legit_sensitive: 5,
    rate_soft: 10,
    rate_hard: 25,
    bot_ua: 10,
    fail_js: 15,
    pass_js: 5,
    bad_ip: 5,
  },
  FULL_PIPELINE: {
    legit_ok: 20,
    legit_sensitive: 15,
    rate_soft: 15,
    rate_hard: 10,
    bot_ua: 10,
    fail_js: 10,
    pass_js: 10,
    bad_ip: 10,
  },
  NORMAL: {
    legit_ok: 70,
    legit_sensitive: 20,
    rate_soft: 5,
    rate_hard: 0,
    bot_ua: 0,
    fail_js: 0,
    pass_js: 5,
    bad_ip: 0,
  },
  SUSPICIOUS_BURST: {
    legit_ok: 20,
    legit_sensitive: 10,
    rate_soft: 20,
    rate_hard: 20,
    bot_ua: 15,
    fail_js: 10,
    pass_js: 0,
    bad_ip: 5,
  },
  REPEATED_REQUESTS: {
    legit_ok: 30,
    legit_sensitive: 10,
    rate_soft: 30,
    rate_hard: 20,
    bot_ua: 5,
    fail_js: 0,
    pass_js: 5,
    bad_ip: 0,
  },
  UNUSUAL_BEHAVIOR: {
    legit_ok: 25,
    legit_sensitive: 15,
    rate_soft: 10,
    rate_hard: 5,
    bot_ua: 20,
    fail_js: 15,
    pass_js: 0,
    bad_ip: 10,
  },
  KNOWN_TEST_SOURCE: {
    legit_ok: 40,
    legit_sensitive: 20,
    rate_soft: 10,
    rate_hard: 0,
    bot_ua: 0,
    fail_js: 0,
    pass_js: 30,
    bad_ip: 0,
  },
}

export function resolvePersonaWeights(
  pattern: SimulationPattern,
  options?: SimulationOptions,
): Required<PersonaWeights> {
  if (pattern === 'CUSTOM') {
    const w = options?.personaWeights ?? {}
    return {
      legit_ok: w.legit_ok ?? 0,
      legit_sensitive: w.legit_sensitive ?? 0,
      rate_soft: w.rate_soft ?? 0,
      rate_hard: w.rate_hard ?? 0,
      bot_ua: w.bot_ua ?? 0,
      fail_js: w.fail_js ?? 0,
      pass_js: w.pass_js ?? 0,
      bad_ip: w.bad_ip ?? 0,
    }
  }
  const base = DEFAULT_PERSONA_WEIGHTS[pattern]
  if (!options?.personaWeights) return { ...base }
  return {
    legit_ok: options.personaWeights.legit_ok ?? base.legit_ok,
    legit_sensitive:
      options.personaWeights.legit_sensitive ?? base.legit_sensitive,
    rate_soft: options.personaWeights.rate_soft ?? base.rate_soft,
    rate_hard: options.personaWeights.rate_hard ?? base.rate_hard,
    bot_ua: options.personaWeights.bot_ua ?? base.bot_ua,
    fail_js: options.personaWeights.fail_js ?? base.fail_js,
    pass_js: options.personaWeights.pass_js ?? base.pass_js,
    bad_ip: options.personaWeights.bad_ip ?? base.bad_ip,
  }
}