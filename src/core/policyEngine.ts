// backend/src/core/policy.engine.ts
// ==================================================================
// Zero Plus - Policy Engine (pure)
// ------------------------------------------------------------------
// الدوسيه: Signals → Detection → AI → Risk Engine → Policy → Decision
// الملف ده هو خانة "Policy": ياخد Risk Score وسياق الطلب، ويرجّع
// قرار كامل (إيه اللي يعمله الـ Gateway بالظبط + ليه).
//
// نقي 100%: مفيش Fastify ولا Prisma ولا DB ولا Redis، والوقت بييجي كمدخل.
// يعني ينفع يتنسخ للـ gateway/ (خدمة منفصلة) وينفع يتختبر من غير أي حاجة،
// وينفع الـ Simulation Lab يشغّله على أنماط مولّدة.
//
// ترتيب الفحص (أول واحد بيحسم):
//   1) السيرفر: دومين مش متحقق منه ← 404 | صيانة ← 503
//   2) جهاز موثوق (allowlist) ← يعدي
//   3) حظر ساري (مؤقت/دائم)   ← BLOCK
//   4) الحد الصارم للـ IP      ← BLOCK (أو 429 حسب banOnMaxRequests)
//   5) ضغط على السيرفر كله     ← 503 للمشكوك فيهم (والنضيف بتصريح يعدي)
//   6) فشل اختبار متقدم        ← BLOCK
//   7) اختبار JS الأساسي (لكل الزوار أو للمشبوهين بس) ← CHALLENGE
//   8) نطاقات الـ Risk: ALLOW / MONITOR|RATE_LIMIT / CHALLENGE|STRICT / BLOCK
//
// قواعد ذكية:
//   - الـ AI وحده ما يحظرش (الدوسيه 7.1): لو الـ AI هو السبب الوحيد
//     لتجاوز حد الحظر ← CHALLENGE بدل BLOCK
//   - فشل اختبار JS ما بيحظرش على طول: بيتصعّد للاختبار المتقدم (أو تحديد صارم)
//   - التصريح (pass token) ما بيحمي من الضغط العالي ولا الخطورة العالية
//     (البوت ممكن يحل الاختبار مرة ويغرق بعدها)
//   - الـ enableAiAnomaly=false بيستبعد مكوّن الـ AI من الـ Risk فعلًا
//   - MONITOR_ONLY: بيحسب القرار ويسجله من غير ما ينفذه
//
// الأرقام والـ enums لازم تفضل مطابقة لـ schema.prisma (Decision, DetectionStage,
// ChallengeType, BanStatus, ServerMode, ServerStatus) وحقول model Policy.
// ==================================================================

// ==================================================================
// Types
// ==================================================================

export type Decision = 'ALLOW' | 'MONITOR' | 'RATE_LIMIT' | 'CHALLENGE' | 'BLOCK'

export type DetectionStage =
  | 'BAN_LIST'
  | 'PASS_TOKEN'
  | 'IP_LOOKUP'
  | 'JS_CHALLENGE'
  | 'HISTORY_MATCH'
  | 'DEEP_COMPARISON'
  | 'TLS_FINGERPRINT'
  | 'AI_ANOMALY'
  | 'HARD_LIMIT'
  | 'POLICY'

export type ChallengeType =
  | 'JS_SILENT'
  | 'TLS_FINGERPRINT'
  | 'RATE_LIMIT_SOFT'
  | 'CAPTCHA_FALLBACK'

export type BanStatus = 'NONE' | 'TEMPORARY' | 'PERMANENT'
export type ServerMode = 'PROTECT' | 'MONITOR_ONLY'
export type ServerStatus =
  | 'PENDING'
  | 'ONLINE'
  | 'DEGRADED'
  | 'OFFLINE'
  | 'MAINTENANCE'

/**
 * اللي الـ Gateway ينفذه فعلًا:
 *   PASS         مرّر الطلب للـ Origin
 *   THROTTLE     ارفض بـ 429 (+ Retry-After)
 *   CHALLENGE    اعرض/نفّذ الاختبار المحدد في result.challenge
 *   BLOCK        ارفض بـ 403
 *   UNAVAILABLE  ارفض بـ 503 (صيانة أو ضغط على السيرفر)
 *   NOT_FOUND    404: الدومين مش متحقق منه، ما تمررش ترافيك
 */
export type GatewayAction =
  | 'PASS'
  | 'THROTTLE'
  | 'CHALLENGE'
  | 'BLOCK'
  | 'UNAVAILABLE'
  | 'NOT_FOUND'

/** حقول model Policy (من غير id/timestamps) */
export interface PolicyValues {
  allowMaxScore: number
  rateLimitMaxScore: number
  challengeMaxScore: number
  enableJsChallenge: boolean
  challengeAllVisitors: boolean
  passTokenTtlMinutes: number
  rateLimitRequests: number
  rateLimitWindowSec: number
  maxRequestsPerIp: number
  maxRequestsWindowSec: number
  banOnMaxRequests: boolean
  maxServerRps: number | null
  capacityWarnPercent: number
  autoBanAfterFails: number
  temporaryBanMinutes: number
  permanentBanScore: number
  enableAiAnomaly: boolean
}

/** مكوّن في الـ Risk (الـ Risk Engine بيبعتهم عشان نعرف مين السبب) */
export interface RiskComponent {
  /** نفس DetectionStage: IP_LOOKUP / HISTORY_MATCH / DEEP_COMPARISON / TLS_FINGERPRINT / AI_ANOMALY ... */
  stage: DetectionStage
  label: string
  points: number
}

export interface RiskInput {
  /** 0-100. لو components موجودة بتتحسب منها بدل الرقم ده */
  score: number
  components?: RiskComponent[]
  /** لو مفيش components: نقاط الـ AI جوه الـ score (لقاعدة "الـ AI وحده ما يحظرش") */
  aiPoints?: number
}

export interface PolicyEngineInput {
  policy: PolicyValues
  server: {
    mode: ServerMode
    status: ServerStatus
    dnsVerified: boolean
    maxRequestsPerSecond: number | null
  }
  risk: RiskInput
  visitor: {
    hasValidPassToken: boolean
    isAllowlisted?: boolean
    ban?: {
      status: BanStatus
      bannedUntil?: Date | string | null
    }
  }
  /** العدادات شاملة الطلب الحالي (من Redis) */
  rate: {
    /** طلبات الـ IP في نافذة rateLimitWindowSec */
    ipSoftCount: number
    /** طلبات الـ IP في نافذة maxRequestsWindowSec (الافتراضي = ipSoftCount) */
    ipHardCount?: number
    /** طلبات السيرفر كله في الثانية الحالية */
    serverRps?: number
  }
  /** نتايج اختبارات اتعملت للزائر ده في الجلسة */
  challenge?: {
    results: Array<{ type: ChallengeType; passed: boolean }>
  }
  /** من الـ AI Service (لو شغال) */
  ai?: { anomalyScore: number; confidence: number }
  /** إمكانيات الـ Gateway الفعلية */
  capabilities?: { tlsFingerprint?: boolean; captcha?: boolean }
  request?: {
    /** false لطلبات API/XHR/الصور (مفيش صفحة اختبار تتعرض) */
    canServeChallenge?: boolean
  }
  now?: Date
}

export interface RateLimitDecision {
  kind: 'SOFT' | 'STRICT' | 'HARD' | 'SERVER'
  scope: 'IP' | 'SERVER'
  limit: number
  windowSec: number
  count: number
  remaining: number
  exceeded: boolean
  retryAfterSec: number
}

export interface ChallengeDecision {
  level: 'BASELINE' | 'ADVANCED'
  type: ChallengeType
  /** true = لازم صفحة تتعرض للزائر، false = فحص صامت (زي بصمة TLS) */
  requiresPage: boolean
}

/** أدلة تتبعت لـ POST /internal/gateway/reputation/apply (متطابقة مع signalSchema) */
export interface ReputationSignalSuggestion {
  type: 'RATE_LIMIT_EXCEEDED' | 'HARD_LIMIT_EXCEEDED' | 'AI_ANOMALY'
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  confidence: number
  count: number
  anomalyScore?: number
  note?: string
}

export interface TraceStep {
  step: string
  outcome: string
  note: string
}

export interface PolicyEngineResult {
  /** الحكم (ممكن يكون مختلف عن اللي اتنفذ لو MONITOR_ONLY) */
  decision: Decision
  /** اللي يتسجل في SecurityEvent.decision (MONITOR لو السيرفر MONITOR_ONLY) */
  eventDecision: Decision
  action: GatewayAction
  httpStatus: number
  /** false = السيرفر MONITOR_ONLY والقرار اتسجل بس */
  enforced: boolean
  /** false لحالات السيرفر (صيانة / دومين مش متحقق): ما تتسجلش كحدث أمني */
  shouldLogEvent: boolean
  riskScore: number
  /** SecurityEvent.decidedAtStage */
  decidedAtStage: DetectionStage
  reasonCode: string
  /** SecurityEvent.reasonSummary */
  reasonSummary: string
  /** SecurityEvent.reasonDetails (مختصر، من غير trace) */
  reasonDetails: Record<string, unknown>
  retryAfterSec: number | null
  rateLimit: RateLimitDecision | null
  challenge: ChallengeDecision | null
  /** الـ Gateway يصدر pass token (كوكي موقّع) بمدة passTokenTtlMinutes */
  issuePassToken: boolean
  passTokenTtlMinutes: number | null
  reputationSignals: ReputationSignalSuggestion[]
  /** خطوات الفحص (للـ dry-run والـ debugging وتقارير الـ AI، مش للتخزين مع كل حدث) */
  trace: TraceStep[]
}

// ==================================================================
// Constants
// ==================================================================

export const ENGINE_VERSION = 'policy-engine/2'

export const ENGINE_TUNING = {
  /** حد التحديد الصارم = rateLimitRequests × العامل ده */
  STRICT_RATE_FACTOR: 0.5,
  /** أقل شذوذ/ثقة من الـ AI عشان نقترح دليل للسمعة */
  AI_SIGNAL_MIN_SCORE: 0.6,
  AI_SIGNAL_MIN_CONFIDENCE: 0.5,
  AI_HIGH_SEVERITY_SCORE: 0.9,
  OVERLOAD_RETRY_SEC: 5,
  MAINTENANCE_RETRY_SEC: 120,
} as const

const ADVANCED_ORDER: readonly ChallengeType[] = [
  'TLS_FINGERPRINT',
  'CAPTCHA_FALLBACK',
]

const ADVANCED_TYPES: ReadonlySet<ChallengeType> = new Set<ChallengeType>(
  ADVANCED_ORDER,
)

// ==================================================================
// Bands (نطاقات الـ Risk)
// ==================================================================

export type RiskBand = 'ALLOW' | 'SOFT' | 'CHALLENGE' | 'BLOCK'

type Thresholds = Pick<
  PolicyValues,
  'allowMaxScore' | 'rateLimitMaxScore' | 'challengeMaxScore'
>

export function bandOf(score: number, p: Thresholds): RiskBand {
  if (score <= p.allowMaxScore) return 'ALLOW'
  if (score <= p.rateLimitMaxScore) return 'SOFT'
  if (score <= p.challengeMaxScore) return 'CHALLENGE'
  return 'BLOCK'
}

/** نطاقات الـ Risk بالأرقام (لصفحة /policies في الـ Dashboard) */
export function describeBands(p: Thresholds): Array<{
  band: RiskBand
  decision: string
  from: number
  to: number
  empty: boolean
}> {
  const rows: Array<{ band: RiskBand; decision: string; from: number; to: number }> = [
    { band: 'ALLOW', decision: 'ALLOW', from: 0, to: p.allowMaxScore },
    {
      band: 'SOFT',
      decision: 'MONITOR / RATE_LIMIT',
      from: p.allowMaxScore + 1,
      to: p.rateLimitMaxScore,
    },
    {
      band: 'CHALLENGE',
      decision: 'CHALLENGE / STRICT RATE LIMIT',
      from: p.rateLimitMaxScore + 1,
      to: p.challengeMaxScore,
    },
    { band: 'BLOCK', decision: 'BLOCK', from: p.challengeMaxScore + 1, to: 100 },
  ]

  return rows.map((row) => ({ ...row, empty: row.from > row.to }))
}

// ==================================================================
// Helpers
// ==================================================================

const clampRisk = (value: number): number => {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(100, Math.round(value)))
}

const clamp01 = (value: number): number => {
  if (!Number.isFinite(value)) return 0
  return Math.min(1, Math.max(0, value))
}

const toMs = (value: Date | string | null | undefined): number | null => {
  if (value === null || value === undefined) return null
  const ms = value instanceof Date ? value.getTime() : Date.parse(value)
  return Number.isFinite(ms) ? ms : null
}

function resolveBan(
  ban: PolicyEngineInput['visitor']['ban'],
  nowMs: number,
): { active: boolean; status: BanStatus; retryAfterSec: number | null } {
  if (!ban || ban.status === 'NONE') {
    return { active: false, status: 'NONE', retryAfterSec: null }
  }

  if (ban.status === 'PERMANENT') {
    return { active: true, status: 'PERMANENT', retryAfterSec: null }
  }

  const until = toMs(ban.bannedUntil)

  if (until !== null && until > nowMs) {
    return {
      active: true,
      status: 'TEMPORARY',
      retryAfterSec: Math.max(1, Math.ceil((until - nowMs) / 1000)),
    }
  }

  // مؤقت منتهي (أو من غير تاريخ) = مفيش حظر
  return { active: false, status: 'NONE', retryAfterSec: null }
}

interface ResolvedRisk {
  score: number
  scoreWithoutAi: number
  aiPoints: number
  components: RiskComponent[]
}

function resolveRisk(risk: RiskInput, policy: PolicyValues): ResolvedRisk {
  const all = risk.components ?? []

  if (all.length > 0) {
    // الـ AI مقفول للشركة = مكوّنه بيتشال من الحساب فعلًا
    const used = policy.enableAiAnomaly
      ? all
      : all.filter((c) => c.stage !== 'AI_ANOMALY')

    let total = 0
    let ai = 0

    for (const component of used) {
      const points = Math.max(0, component.points)
      total += points
      if (component.stage === 'AI_ANOMALY') ai += points
    }

    return {
      score: clampRisk(total),
      scoreWithoutAi: clampRisk(total - ai),
      aiPoints: ai,
      components: used,
    }
  }

  const score = clampRisk(risk.score)
  const ai = Math.max(0, risk.aiPoints ?? 0)

  return {
    score,
    scoreWithoutAi: clampRisk(score - ai),
    aiPoints: ai,
    components: [],
  }
}

function dominantStage(components: RiskComponent[]): DetectionStage {
  let best: RiskComponent | null = null

  for (const component of components) {
    if (component.points > 0 && (best === null || component.points > best.points)) {
      best = component
    }
  }

  return best ? best.stage : 'POLICY'
}

function topReasons(components: RiskComponent[]): string {
  return [...components]
    .filter((c) => c.points > 0)
    .sort((a, b) => b.points - a.points)
    .slice(0, 3)
    .map((c) => `${c.label} (+${Math.round(c.points)})`)
    .join('، ')
}

function pickAdvancedChallenge(
  done: ReadonlySet<ChallengeType>,
  caps: NonNullable<PolicyEngineInput['capabilities']>,
  canServe: boolean,
): ChallengeType | null {
  for (const type of ADVANCED_ORDER) {
    if (done.has(type)) continue
    if (type === 'TLS_FINGERPRINT' && !caps.tlsFingerprint) continue
    // الكابتشا محتاجة صفحة تتعرض
    if (type === 'CAPTCHA_FALLBACK' && (!caps.captcha || !canServe)) continue
    return type
  }

  return null
}

function ipLimit(
  kind: 'SOFT' | 'STRICT' | 'HARD',
  limit: number,
  windowSec: number,
  count: number,
): RateLimitDecision {
  const exceeded = count > limit

  return {
    kind,
    scope: 'IP',
    limit,
    windowSec,
    count,
    remaining: Math.max(0, limit - count),
    exceeded,
    retryAfterSec: exceeded ? windowSec : 0,
  }
}

function buildAiSignal(
  ai: PolicyEngineInput['ai'],
  policy: PolicyValues,
): ReputationSignalSuggestion | null {
  if (!ai || !policy.enableAiAnomaly) return null

  const anomalyScore = clamp01(ai.anomalyScore)
  const confidence = clamp01(ai.confidence)

  if (
    anomalyScore < ENGINE_TUNING.AI_SIGNAL_MIN_SCORE ||
    confidence < ENGINE_TUNING.AI_SIGNAL_MIN_CONFIDENCE
  ) {
    return null
  }

  return {
    type: 'AI_ANOMALY',
    severity:
      anomalyScore >= ENGINE_TUNING.AI_HIGH_SEVERITY_SCORE ? 'HIGH' : 'MEDIUM',
    confidence,
    count: 1,
    anomalyScore,
  }
}

// ==================================================================
// القرار الكامل
// ==================================================================

interface Verdict {
  decision: Decision
  action: GatewayAction
  httpStatus: number
  stage: DetectionStage
  reasonCode: string
  summary: string
  retryAfterSec?: number
  rateLimit?: RateLimitDecision
  challenge?: ChallengeDecision
  signals?: ReputationSignalSuggestion[]
  issuePassToken?: boolean
  /** بيتنفذ حتى لو السيرفر MONITOR_ONLY (حالة السيرفر نفسه) */
  always?: boolean
  /** false = ما تتسجلش كحدث أمني */
  log?: boolean
  extra?: Record<string, unknown>
}

export function decide(input: PolicyEngineInput): PolicyEngineResult {
  const nowMs = (input.now ?? new Date()).getTime()
  const { policy, server, visitor, rate } = input
  const caps = input.capabilities ?? {}
  const canServe = input.request?.canServeChallenge !== false
  const hardCount = rate.ipHardCount ?? rate.ipSoftCount

  const trace: TraceStep[] = []
  const note = (step: string, outcome: string, detail = '') => {
    trace.push({ step, outcome, note: detail })
  }

  const risk = resolveRisk(input.risk, policy)
  const aiSignal = buildAiSignal(input.ai, policy)
  const reasonsText = topReasons(risk.components)
  const why = reasonsText ? ` — الأسباب: ${reasonsText}` : ''

  const finalize = (v: Verdict): PolicyEngineResult => {
    const monitorOnly =
      server.mode === 'MONITOR_ONLY' && v.action !== 'PASS' && v.always !== true

    const action: GatewayAction = monitorOnly ? 'PASS' : v.action
    const httpStatus = monitorOnly ? 200 : v.httpStatus
    const shouldLog = v.log !== false

    const signals: ReputationSignalSuggestion[] = [...(v.signals ?? [])]
    if (shouldLog && aiSignal) signals.push(aiSignal)

    const challenge = monitorOnly ? null : (v.challenge ?? null)
    const retryAfterSec = monitorOnly ? null : (v.retryAfterSec ?? null)
    const issuePassToken = !monitorOnly && v.issuePassToken === true

    note(
      'FINAL',
      v.decision,
      monitorOnly
        ? `monitor-only: القرار اتسجل من غير تنفيذ (${v.reasonCode})`
        : v.reasonCode,
    )

    const reasonDetails: Record<string, unknown> = {
      engine: ENGINE_VERSION,
      reasonCode: v.reasonCode,
      intendedDecision: v.decision,
      enforced: !monitorOnly,
      monitorOnly,
      serverMode: server.mode,
      riskScore: risk.score,
      thresholds: {
        allowMaxScore: policy.allowMaxScore,
        rateLimitMaxScore: policy.rateLimitMaxScore,
        challengeMaxScore: policy.challengeMaxScore,
      },
      components: risk.components,
      ...(risk.aiPoints > 0 && { aiPoints: risk.aiPoints }),
      ...(v.rateLimit && { rateLimit: v.rateLimit }),
      ...(v.challenge && { challenge: v.challenge }),
      ...(input.ai && { ai: input.ai }),
      ...(v.extra ?? {}),
    }

    return {
      decision: v.decision,
      eventDecision: monitorOnly ? 'MONITOR' : v.decision,
      action,
      httpStatus,
      enforced: !monitorOnly,
      shouldLogEvent: shouldLog,
      riskScore: risk.score,
      decidedAtStage: v.stage,
      reasonCode: v.reasonCode,
      reasonSummary: v.summary,
      reasonDetails,
      retryAfterSec,
      rateLimit: v.rateLimit ?? null,
      challenge,
      issuePassToken,
      passTokenTtlMinutes: issuePassToken ? policy.passTokenTtlMinutes : null,
      reputationSignals: signals,
      trace,
    }
  }

  // ----------------------------------------------------------------
  // 1) حالة السيرفر
  // ----------------------------------------------------------------
  if (!server.dnsVerified) {
    note('SERVER_GATE', 'NOT_VERIFIED', 'dnsVerified=false')

    return finalize({
      decision: 'BLOCK',
      action: 'NOT_FOUND',
      httpStatus: 404,
      stage: 'POLICY',
      reasonCode: 'SERVER_NOT_VERIFIED',
      summary:
        'ملكية الدومين لسه ما اتثبتتش، فالترافيك مش بيتمرر (تحقق من الـ DNS الأول)',
      always: true,
      log: false,
    })
  }

  if (server.status === 'MAINTENANCE') {
    note('SERVER_GATE', 'MAINTENANCE', 'status=MAINTENANCE')

    return finalize({
      decision: 'ALLOW',
      action: 'UNAVAILABLE',
      httpStatus: 503,
      stage: 'POLICY',
      reasonCode: 'SERVER_MAINTENANCE',
      summary: 'السيرفر في وضع الصيانة',
      retryAfterSec: ENGINE_TUNING.MAINTENANCE_RETRY_SEC,
      always: true,
      log: false,
    })
  }

  note('SERVER_GATE', 'OK', `mode=${server.mode}`)

  // ----------------------------------------------------------------
  // 2) جهاز موثوق
  // ----------------------------------------------------------------
  if (visitor.isAllowlisted === true) {
    note('LIST', 'ALLOWLISTED')

    return finalize({
      decision: 'ALLOW',
      action: 'PASS',
      httpStatus: 200,
      stage: 'BAN_LIST',
      reasonCode: 'ALLOWLISTED_DEVICE',
      summary: 'جهاز موثوق (allowlist)',
    })
  }

  // ----------------------------------------------------------------
  // 3) حظر ساري
  // ----------------------------------------------------------------
  const ban = resolveBan(visitor.ban, nowMs)

  if (ban.active) {
    note('LIST', 'BANNED', ban.status)

    return finalize({
      decision: 'BLOCK',
      action: 'BLOCK',
      httpStatus: 403,
      stage: 'BAN_LIST',
      reasonCode: ban.status === 'PERMANENT' ? 'PERMANENT_BAN' : 'TEMPORARY_BAN',
      summary:
        ban.status === 'PERMANENT'
          ? 'مصدر محظور بشكل دائم'
          : `مصدر محظور مؤقتًا (متبقي ${Math.ceil((ban.retryAfterSec ?? 0) / 60)} دقيقة)`,
      ...(ban.retryAfterSec !== null && { retryAfterSec: ban.retryAfterSec }),
      extra: { banStatus: ban.status },
    })
  }

  note('LIST', 'CLEAR')

  // ----------------------------------------------------------------
  // 4) الحد الأقصى الصارم للـ IP
  // ----------------------------------------------------------------
  const hard = ipLimit(
    'HARD',
    policy.maxRequestsPerIp,
    policy.maxRequestsWindowSec,
    hardCount,
  )

  if (hard.exceeded) {
    note('HARD_LIMIT', 'EXCEEDED', `${hard.count}/${hard.limit} في ${hard.windowSec}ث`)

    const signal: ReputationSignalSuggestion = {
      type: 'HARD_LIMIT_EXCEEDED',
      severity: 'HIGH',
      confidence: 1,
      count: 1,
    }

    if (policy.banOnMaxRequests) {
      return finalize({
        decision: 'BLOCK',
        action: 'BLOCK',
        httpStatus: 403,
        stage: 'HARD_LIMIT',
        reasonCode: 'HARD_LIMIT_BAN',
        summary: `تجاوز الحد الأقصى للطلبات (${hard.count} من ${hard.limit} خلال ${hard.windowSec} ثانية): حظر مؤقت`,
        retryAfterSec: policy.temporaryBanMinutes * 60,
        rateLimit: hard,
        signals: [signal],
      })
    }

    return finalize({
      decision: 'RATE_LIMIT',
      action: 'THROTTLE',
      httpStatus: 429,
      stage: 'HARD_LIMIT',
      reasonCode: 'HARD_LIMIT_THROTTLE',
      summary: `تجاوز الحد الأقصى للطلبات (${hard.count} من ${hard.limit} خلال ${hard.windowSec} ثانية)`,
      retryAfterSec: hard.retryAfterSec,
      rateLimit: hard,
      signals: [signal],
    })
  }

  note('HARD_LIMIT', 'OK', `${hard.count}/${hard.limit}`)

  // ----------------------------------------------------------------
  // 5) ضغط على السيرفر كله (Load shedding)
  //    النضيف اللي معاه تصريح يعدي، والباقي 503
  // ----------------------------------------------------------------
  const serverCap = policy.maxServerRps ?? server.maxRequestsPerSecond ?? null

  if (
    serverCap !== null &&
    rate.serverRps !== undefined &&
    rate.serverRps > serverCap
  ) {
    const trusted =
      visitor.hasValidPassToken && risk.score <= policy.allowMaxScore

    if (!trusted) {
      note('CAPACITY', 'SHED', `${rate.serverRps}/${serverCap} rps`)

      return finalize({
        decision: 'RATE_LIMIT',
        action: 'UNAVAILABLE',
        httpStatus: 503,
        stage: 'HARD_LIMIT',
        reasonCode: 'SERVER_OVERLOADED',
        summary: `السيرفر تحت ضغط (${rate.serverRps} طلب/ث من سقف ${serverCap}): الترافيك المشكوك فيه بيتأجل`,
        retryAfterSec: ENGINE_TUNING.OVERLOAD_RETRY_SEC,
        rateLimit: {
          kind: 'SERVER',
          scope: 'SERVER',
          limit: serverCap,
          windowSec: 1,
          count: rate.serverRps,
          remaining: 0,
          exceeded: true,
          retryAfterSec: ENGINE_TUNING.OVERLOAD_RETRY_SEC,
        },
      })
    }

    note('CAPACITY', 'OVERLOADED_BUT_TRUSTED', 'تصريح صالح وخطورة منخفضة')
  } else {
    note('CAPACITY', 'OK')
  }

  // ----------------------------------------------------------------
  // 6) نتايج الاختبارات السابقة
  // ----------------------------------------------------------------
  const results = input.challenge?.results ?? []
  const doneTypes = new Set<ChallengeType>(results.map((r) => r.type))
  const baseline = results.find((r) => r.type === 'JS_SILENT')
  const advancedResults = results.filter((r) => ADVANCED_TYPES.has(r.type))
  const advancedFailed = advancedResults.find((r) => !r.passed)
  const advancedPassed = advancedResults.some((r) => r.passed)
  const passedChallenge = results.some((r) => r.passed)

  if (advancedFailed) {
    note('ADVANCED_CHALLENGE', 'FAILED', advancedFailed.type)

    return finalize({
      decision: 'BLOCK',
      action: 'BLOCK',
      httpStatus: 403,
      stage: advancedFailed.type === 'TLS_FINGERPRINT' ? 'TLS_FINGERPRINT' : 'POLICY',
      reasonCode: 'ADVANCED_CHALLENGE_FAILED',
      summary: `فشل في الاختبار المتقدم (${advancedFailed.type})${why}`,
      extra: { failedChallenge: advancedFailed.type },
    })
  }

  // ----------------------------------------------------------------
  // 7) اختبار JS الأساسي
  // ----------------------------------------------------------------
  let escalated = false

  if (!visitor.hasValidPassToken && policy.enableJsChallenge) {
    if (baseline === undefined) {
      const wanted =
        policy.challengeAllVisitors || risk.score > policy.allowMaxScore

      // الخطورة فوق حد الحظر: ما نديش فرصة اختبار
      if (wanted && canServe && risk.score <= policy.challengeMaxScore) {
        const everyone =
          policy.challengeAllVisitors && risk.score <= policy.allowMaxScore

        note('BASELINE_JS', 'REQUIRED', everyone ? 'لكل الزوار الجدد' : 'مشكوك فيه')

        return finalize({
          decision: 'CHALLENGE',
          action: 'CHALLENGE',
          httpStatus: 403,
          stage: 'JS_CHALLENGE',
          reasonCode: everyone ? 'BASELINE_JS_CHALLENGE' : 'SUSPECT_JS_CHALLENGE',
          summary: everyone
            ? 'زائر جديد من غير تصريح: اختبار JS الأساسي'
            : `خطورة ${risk.score}: اختبار JS الأساسي${why}`,
          challenge: { level: 'BASELINE', type: 'JS_SILENT', requiresPage: true },
        })
      }

      note('BASELINE_JS', 'SKIPPED', canServe ? 'مش مطلوب' : 'مفيش صفحة تتعرض')
    } else if (!baseline.passed) {
      escalated = true
      note('BASELINE_JS', 'FAILED', 'تصعيد للاختبارات المتقدمة')
    } else {
      note('BASELINE_JS', 'PASSED')
    }
  } else {
    note(
      'BASELINE_JS',
      'NOT_NEEDED',
      visitor.hasValidPassToken ? 'تصريح صالح' : 'الاختبار مقفول للشركة',
    )
  }

  // ----------------------------------------------------------------
  // 8) نطاق الـ Risk
  // ----------------------------------------------------------------
  const originalBand = bandOf(risk.score, policy)
  let band = originalBand
  const flags: string[] = []

  // الـ AI وحده ما يحظرش: لو من غيره الخطورة تحت حد الحظر ← CHALLENGE
  if (
    band === 'BLOCK' &&
    risk.aiPoints > 0 &&
    risk.scoreWithoutAi <= policy.challengeMaxScore
  ) {
    band = 'CHALLENGE'
    flags.push('AI_ONLY_CAPPED')
    note('AI_GUARD', 'CAPPED', 'الـ AI هو السبب الوحيد لتجاوز حد الحظر')
  }

  // فشل JS الأساسي: ما ينفعش يعدي كـ ALLOW/MONITOR
  if (escalated && (band === 'ALLOW' || band === 'SOFT')) {
    band = 'CHALLENGE'
    flags.push('ESCALATED_AFTER_FAILED_JS')
  }

  // نجح في اختبار متقدم: بيتنزل لنطاق التحديد
  if (advancedPassed && band === 'CHALLENGE') {
    band = 'SOFT'
    flags.push('ADVANCED_CHALLENGE_PASSED')
    note('ADVANCED_CHALLENGE', 'PASSED', 'نزل لنطاق التحديد')
  }

  note('RISK_BAND', band, `risk=${risk.score}`)

  const bandStage: DetectionStage =
    escalated && (originalBand === 'ALLOW' || originalBand === 'SOFT')
      ? 'JS_CHALLENGE'
      : dominantStage(risk.components)

  const extra: Record<string, unknown> = {
    ...(flags.length > 0 && { flags }),
  }

  const issueToken = passedChallenge && !visitor.hasValidPassToken

  if (band === 'ALLOW') {
    return finalize({
      decision: 'ALLOW',
      action: 'PASS',
      httpStatus: 200,
      stage: visitor.hasValidPassToken ? 'PASS_TOKEN' : 'POLICY',
      reasonCode: visitor.hasValidPassToken ? 'PASS_TOKEN_VALID' : 'RISK_LOW',
      summary: `خطورة ${risk.score} (≤ ${policy.allowMaxScore}): سماح`,
      issuePassToken: issueToken,
      extra,
    })
  }

  if (band === 'SOFT') {
    const limit = ipLimit(
      'SOFT',
      policy.rateLimitRequests,
      policy.rateLimitWindowSec,
      rate.ipSoftCount,
    )

    if (limit.exceeded) {
      return finalize({
        decision: 'RATE_LIMIT',
        action: 'THROTTLE',
        httpStatus: 429,
        stage: bandStage,
        reasonCode: 'SOFT_LIMIT_EXCEEDED',
        summary: `خطورة ${risk.score}: تجاوز حد الطلبات (${limit.count} من ${limit.limit} خلال ${limit.windowSec} ثانية)${why}`,
        retryAfterSec: limit.retryAfterSec,
        rateLimit: limit,
        signals: [
          { type: 'RATE_LIMIT_EXCEEDED', severity: 'MEDIUM', confidence: 1, count: 1 },
        ],
        extra,
      })
    }

    return finalize({
      decision: 'MONITOR',
      action: 'PASS',
      httpStatus: 200,
      stage: bandStage,
      reasonCode: 'RISK_MODERATE_MONITORED',
      summary: `خطورة ${risk.score} (بين ${policy.allowMaxScore + 1} و${policy.rateLimitMaxScore}): سماح مع مراقبة وتحديد معدل${why}`,
      rateLimit: limit,
      issuePassToken: issueToken,
      extra,
    })
  }

  if (band === 'CHALLENGE') {
    const next = pickAdvancedChallenge(doneTypes, caps, canServe)

    if (next !== null) {
      return finalize({
        decision: 'CHALLENGE',
        action: 'CHALLENGE',
        httpStatus: 403,
        stage: next === 'TLS_FINGERPRINT' ? 'TLS_FINGERPRINT' : bandStage,
        reasonCode: 'ADVANCED_CHALLENGE',
        summary: `خطورة ${risk.score} (بين ${policy.rateLimitMaxScore + 1} و${policy.challengeMaxScore}): اختبار إضافي (${next})${why}`,
        challenge: {
          level: 'ADVANCED',
          type: next,
          requiresPage: next !== 'TLS_FINGERPRINT',
        },
        extra,
      })
    }

    // مفيش اختبار متقدم متاح: تحديد صارم (الدوسيه: CHALLENGE / STRICT RATE LIMIT)
    const strictLimit = Math.max(
      1,
      Math.floor(policy.rateLimitRequests * ENGINE_TUNING.STRICT_RATE_FACTOR),
    )

    const limit = ipLimit(
      'STRICT',
      strictLimit,
      policy.rateLimitWindowSec,
      rate.ipSoftCount,
    )

    note('ADVANCED_CHALLENGE', 'UNAVAILABLE', 'تحديد صارم بدل الاختبار')

    if (limit.exceeded) {
      return finalize({
        decision: 'RATE_LIMIT',
        action: 'THROTTLE',
        httpStatus: 429,
        stage: bandStage,
        reasonCode: 'STRICT_LIMIT_EXCEEDED',
        summary: `خطورة ${risk.score}: تحديد صارم (${limit.count} من ${limit.limit} خلال ${limit.windowSec} ثانية)${why}`,
        retryAfterSec: limit.retryAfterSec,
        rateLimit: limit,
        signals: [
          { type: 'RATE_LIMIT_EXCEEDED', severity: 'MEDIUM', confidence: 1, count: 1 },
        ],
        extra,
      })
    }

    return finalize({
      decision: 'MONITOR',
      action: 'PASS',
      httpStatus: 200,
      stage: bandStage,
      reasonCode: 'CHALLENGE_UNAVAILABLE_STRICT_LIMIT',
      summary: `خطورة ${risk.score}: مفيش اختبار متاح، سماح بتحديد صارم ومراقبة${why}`,
      rateLimit: limit,
      issuePassToken: issueToken,
      extra,
    })
  }

  return finalize({
    decision: 'BLOCK',
    action: 'BLOCK',
    httpStatus: 403,
    stage: bandStage,
    reasonCode: 'RISK_ABOVE_THRESHOLD',
    summary: `خطورة ${risk.score} (> ${policy.challengeMaxScore}): حظر${why}`,
    extra,
  })
}

// ==================================================================
// واجهة قديمة (متوافقة): بتحوّل Risk Score لقرار من غير أي سياق
// فضلت زي ما هي عشان أي import قديم يفضل شغال. الجديد: decide()
// ==================================================================

export type PolicyThresholds = {
  allowMaxScore: number
  rateLimitMaxScore: number
  challengeMaxScore: number
  rateLimitRps?: number
  rateLimitRequests?: number
  rateLimitWindowSec?: number
  enableJsChallenge?: boolean
}

export type DecisionType = 'ALLOW' | 'RATE_LIMIT' | 'CHALLENGE' | 'BLOCK'

export type PolicyDecision = {
  decision: DecisionType
  riskScore: number
  rateLimitRps?: number
  rateLimitRequests?: number
  rateLimitWindowSec?: number
  requireChallenge?: boolean
  reason: string
}

export function evaluatePolicy(
  riskScore: number,
  policy: PolicyThresholds,
): PolicyDecision {
  const score = clampRisk(riskScore)
  const band = bandOf(score, policy)

  if (band === 'ALLOW') {
    return {
      decision: 'ALLOW',
      riskScore: score,
      reason: `Risk ${score} ≤ allow threshold ${policy.allowMaxScore}`,
    }
  }

  if (band === 'SOFT') {
    const result: PolicyDecision = {
      decision: 'RATE_LIMIT',
      riskScore: score,
      reason: `Risk ${score} in RATE_LIMIT band (${policy.allowMaxScore + 1}–${policy.rateLimitMaxScore})`,
    }

    if (policy.rateLimitRps !== undefined) {
      result.rateLimitRps = policy.rateLimitRps
    }
    if (policy.rateLimitRequests !== undefined) {
      result.rateLimitRequests = policy.rateLimitRequests
    }
    if (policy.rateLimitWindowSec !== undefined) {
      result.rateLimitWindowSec = policy.rateLimitWindowSec
    }

    return result
  }

  if (band === 'CHALLENGE') {
    return {
      decision: 'CHALLENGE',
      riskScore: score,
      requireChallenge: policy.enableJsChallenge !== false,
      reason: `Risk ${score} in CHALLENGE band (${policy.rateLimitMaxScore + 1}–${policy.challengeMaxScore})`,
    }
  }

  return {
    decision: 'BLOCK',
    riskScore: score,
    reason: `Risk ${score} > challenge threshold ${policy.challengeMaxScore}`,
  }
}

export function forcedBlock(reason: string, riskScore = 100): PolicyDecision {
  return { decision: 'BLOCK', riskScore, reason }
}