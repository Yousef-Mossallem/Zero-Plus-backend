// backend/src/core/reputation.engine.ts
// ==================================================================
// Zero Plus - Reputation Engine (pure)
// ------------------------------------------------------------------
// منطق سمعة الجهاز (1–10) والحظر، كدوال نقية: مفيش DB ولا Fastify.
// بيطابق منطق reputation.service.ts (التقادم، سقف النقاط، المعتدي المتكرر،
// الحظر المؤقت والدائم، الجهاز الموثوق، الحظر اليدوي) بس من غير أي I/O،
// فينفع يتنسخ للـ Gateway وينفع الـ Simulation Lab يستخدمه وينفع يتختبر بأرقام.
//
// الأرقام هنا بتطابق REPUTATION_TUNING في reputation.schema.ts:
// لو غيرتوا واحد غيّروا التاني.
//
// القديم شغال: applyReputationEvent / isCurrentlyBanned / الأنواع بنفس الأسماء.
// ==================================================================

// ==================================================================
// Types
// ==================================================================

export type BanStatus = 'NONE' | 'TEMPORARY' | 'PERMANENT'

export type ScoreBand = 'CLEAN' | 'LOW' | 'ELEVATED' | 'HIGH' | 'CRITICAL'

export type ReputationState = {
  score: number
  failedChecks: number
  banStatus: BanStatus
  bannedUntil: Date | null
  // ---- اختيارية (الجديد): من غيرها بيشتغل زي القديم ----
  isManualBan?: boolean
  isAllowlisted?: boolean
  isKnownBotnet?: boolean
  /** آخر دليل سلبي (أساس التقادم). لو مفيش ولا createdAt: مفيش تقادم */
  lastFailedAt?: Date | null
  createdAt?: Date | null
  bannedAt?: Date | null
  banReason?: string | null
}

export type ReputationPolicyRules = {
  autoBanAfterFails: number
  temporaryBanMinutes: number
  /** الاسم الجديد (متطابق مع Policy.permanentBanScore) */
  permanentBanScore?: number
  /** الاسم القديم: لسه مقبول */
  permanentBanMinScore?: number
  /** Policy.banOnMaxRequests: حظر مؤقت عند تجاوز الحد الأقصى */
  banOnMaxRequests?: boolean
}

export type ReputationEvent = {
  // ---- القديم ----
  challengeFailed?: boolean
  scoreDelta?: number
  forcePermanent?: boolean
  positiveSignal?: boolean
  // ---- الجديد ----
  /** نقاط جاهزة (من الأدلة)، ممكن تكون سالبة. بتغلب على scoreDelta */
  points?: number
  /** كام فشل يتحسب (الأقصى 2 في الحدث الواحد) */
  failedIncrement?: number
  /** تجاوز الحد الأقصى للطلبات (بيحظر مؤقتًا لو banOnMaxRequests) */
  hardLimitHit?: boolean
  /** مصدر معروف ببوت نت (بيوقف التقادم) */
  knownBotnet?: boolean
  /** النقاط اتضرب فيها عامل المعتدي المتكرر قبل كده (زي reputation.service)؟ */
  skipRepeatFactor?: boolean
  /** سبب بيتسجل في banReason لو حصل حظر */
  reason?: string
}

export type ReputationChange = {
  scoreBefore: number
  scoreAfter: number
  pointsRaw: number
  pointsApplied: number
  decayApplied: number
  failedBefore: number
  failedAfter: number
  banBefore: BanStatus
  banAfter: BanStatus
  newlyBanned: boolean
  /** مؤقت اتحوّل لدائم */
  escalated: boolean
  /** مؤقت اتمدّد */
  extended: boolean
  banType: 'TEMPORARY' | 'PERMANENT' | null
  reason: string | null
}

export type ReputationResult = {
  state: ReputationState
  change: ReputationChange
}

// ==================================================================
// Tuning (بيطابق REPUTATION_TUNING)
// ==================================================================

export const REPUTATION_ENGINE_TUNING = {
  MAX_POINTS_PER_EVENT: 5,
  MIN_POINTS_PER_EVENT: -2,
  /** أقصى فشل بيتحسب في حدث واحد (يمنع حظر فوري من تقرير واحد) */
  MAX_FAILED_PER_EVENT: 2,
  DECAY_AFTER_HOURS: 24,
  DECAY_STEP: 1,
  /** نقاط فشل الاختبار (بيطابق CHALLENGE_FAILED في كتالوج الأدلة) */
  DEFAULT_FAILED_CHALLENGE_POINTS: 2,
  DEFAULT_POSITIVE_POINTS: -1,
  DEFAULT_PERMANENT_SCORE: 9,
} as const

// ==================================================================
// Helpers
// ==================================================================

const clampScore = (value: number): number =>
  Math.min(10, Math.max(1, Math.round(Number.isFinite(value) ? value : 1)))

const round2 = (value: number): number => Math.round(value * 100) / 100

function resolvePermanentScore(rules: ReputationPolicyRules): number {
  return (
    rules.permanentBanScore ??
    rules.permanentBanMinScore ??
    REPUTATION_ENGINE_TUNING.DEFAULT_PERMANENT_SCORE
  )
}

export function getScoreBand(score: number): ScoreBand {
  if (score <= 1) return 'CLEAN'
  if (score <= 3) return 'LOW'
  if (score <= 6) return 'ELEVATED'
  if (score <= 8) return 'HIGH'
  return 'CRITICAL'
}

/** اقتراح قديم للـ Risk (0–30). الـ Risk Engine بيستخدم reputationScore بأوزانه هو */
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

/** المعتدي المتكرر بياخد نقاط أكتر (يتطبق على النقاط الموجبة بس) */
export function repeatOffenderFactor(failedChecks: number): number {
  if (failedChecks >= 5) return 1.5
  if (failedChecks >= 3) return 1.25
  return 1
}

/** الحظر الفعلي: المؤقت المنتهي (أو من غير تاريخ) = NONE */
export function resolveBan(
  state: Pick<ReputationState, 'banStatus' | 'bannedUntil'>,
  now: Date = new Date(),
): {
  status: BanStatus
  active: boolean
  minutesLeft: number | null
} {
  if (state.banStatus === 'PERMANENT') {
    return { status: 'PERMANENT', active: true, minutesLeft: null }
  }

  if (
    state.banStatus === 'TEMPORARY' &&
    state.bannedUntil !== null &&
    state.bannedUntil.getTime() > now.getTime()
  ) {
    return {
      status: 'TEMPORARY',
      active: true,
      minutesLeft: Math.ceil((state.bannedUntil.getTime() - now.getTime()) / 60_000),
    }
  }

  return { status: 'NONE', active: false, minutesLeft: null }
}

/**
 * التقادم: كل 24 ساعة من غير أدلة سلبية = -1 للسمعة و-1 لعداد الفشل.
 * ما بيتطبقش على: الموثوق / الحظر اليدوي / البوت نت / الدائم / المؤقت الساري.
 * anchor = نقطة البداية الجديدة (عشان نفس المدة ما تتحسبش مرتين).
 */
export function computeDecay(
  state: ReputationState,
  now: Date = new Date(),
): {
  steps: number
  scorePoints: number
  failedAfter: number
  anchor: Date | null
} {
  const none = {
    steps: 0,
    scorePoints: 0,
    failedAfter: state.failedChecks,
    anchor: null as Date | null,
  }

  const ban = resolveBan(state, now)

  if (
    state.isAllowlisted === true ||
    state.isManualBan === true ||
    state.isKnownBotnet === true ||
    ban.status === 'PERMANENT' ||
    ban.status === 'TEMPORARY'
  ) {
    return none
  }

  const from = state.lastFailedAt ?? state.createdAt ?? null

  if (from === null) return none

  const periodMs = REPUTATION_ENGINE_TUNING.DECAY_AFTER_HOURS * 3_600_000
  const steps = Math.floor((now.getTime() - from.getTime()) / periodMs)

  if (steps <= 0) return none

  return {
    steps,
    scorePoints: Math.min(
      Math.max(0, state.score - 1),
      steps * REPUTATION_ENGINE_TUNING.DECAY_STEP,
    ),
    failedAfter: Math.max(0, state.failedChecks - steps),
    anchor: new Date(from.getTime() + steps * periodMs),
  }
}

/** السمعة الفعلية دلوقتي (بعد التقادم) من غير أي كتابة: للـ lookup */
export function describeReputation(state: ReputationState, now: Date = new Date()) {
  const decay = computeDecay(state, now)
  const score = Math.max(1, state.score - decay.scorePoints)
  const ban =
    state.isAllowlisted === true
      ? { status: 'NONE' as BanStatus, active: false, minutesLeft: null }
      : resolveBan(state, now)

  return {
    score,
    scoreBand: getScoreBand(score),
    failedChecks: decay.failedAfter,
    banStatus: ban.status,
    isCurrentlyBanned: ban.active,
    minutesLeftOnBan: ban.minutesLeft,
    reputationRiskPoints: state.isAllowlisted === true ? 0 : reputationRiskPoints(score),
  }
}

// ==================================================================
// الحدث الكامل (النسخة الغنية)
// ==================================================================

export function evaluateReputationEvent(
  current: ReputationState,
  event: ReputationEvent,
  rules: ReputationPolicyRules,
  now: Date = new Date(),
): ReputationResult {
  const nowMs = now.getTime()
  const permanentScore = resolvePermanentScore(rules)

  // ---- 1) تنظيف الحظر المنتهي ----
  const ban0 = resolveBan(current, now)

  let banStatus: BanStatus = ban0.status
  let bannedUntil: Date | null = ban0.status === 'TEMPORARY' ? current.bannedUntil : null
  let bannedAt: Date | null = ban0.status !== 'NONE' ? (current.bannedAt ?? null) : null
  let banReason: string | null = ban0.status !== 'NONE' ? (current.banReason ?? null) : null
  let isManualBan = ban0.status !== 'NONE' ? (current.isManualBan ?? false) : false

  const isKnownBotnet = (current.isKnownBotnet ?? false) || event.knownBotnet === true

  const baseState = (): ReputationState => ({
    score: current.score,
    failedChecks: current.failedChecks,
    banStatus: 'NONE',
    bannedUntil: null,
    isManualBan: false,
    isAllowlisted: current.isAllowlisted ?? false,
    isKnownBotnet,
    lastFailedAt: current.lastFailedAt ?? null,
    createdAt: current.createdAt ?? null,
    bannedAt: null,
    banReason: null,
  })

  // ---- 2) جهاز موثوق: ما بيتغيرش ولا بيتحظر ----
  if (current.isAllowlisted === true) {
    return {
      state: baseState(),
      change: {
        scoreBefore: current.score,
        scoreAfter: current.score,
        pointsRaw: 0,
        pointsApplied: 0,
        decayApplied: 0,
        failedBefore: current.failedChecks,
        failedAfter: current.failedChecks,
        banBefore: 'NONE',
        banAfter: 'NONE',
        newlyBanned: false,
        escalated: false,
        extended: false,
        banType: null,
        reason: null,
      },
    }
  }

  // ---- 3) التقادم ----
  const decay = computeDecay(
    {
      ...current,
      banStatus,
      bannedUntil,
      isManualBan,
      isKnownBotnet,
    },
    now,
  )

  const scoreBase = Math.max(1, current.score - decay.scorePoints)
  const failedBase = decay.failedAfter

  // ---- 4) النقاط والفشل ----
  let basePoints = 0

  if (typeof event.points === 'number') {
    basePoints = event.points
  } else if (event.challengeFailed) {
    basePoints =
      typeof event.scoreDelta === 'number'
        ? event.scoreDelta
        : REPUTATION_ENGINE_TUNING.DEFAULT_FAILED_CHALLENGE_POINTS
  } else if (event.positiveSignal && !event.forcePermanent) {
    basePoints = REPUTATION_ENGINE_TUNING.DEFAULT_POSITIVE_POINTS
  } else if (typeof event.scoreDelta === 'number') {
    basePoints = event.scoreDelta
  }

  const factor =
    basePoints > 0 && event.skipRepeatFactor !== true
      ? repeatOffenderFactor(failedBase)
      : 1

  const pointsRaw = round2(basePoints * factor)

  const pointsApplied = Math.round(
    Math.min(
      REPUTATION_ENGINE_TUNING.MAX_POINTS_PER_EVENT,
      Math.max(REPUTATION_ENGINE_TUNING.MIN_POINTS_PER_EVENT, pointsRaw),
    ),
  )

  const failedInc = Math.max(
    0,
    Math.min(
      REPUTATION_ENGINE_TUNING.MAX_FAILED_PER_EVENT,
      Math.round(event.failedIncrement ?? (event.challengeFailed ? 1 : 0)),
    ),
  )

  const negative = pointsApplied > 0 || pointsRaw > 0 || failedInc > 0

  const failedAfter = failedBase + failedInc
  let scoreAfter = clampScore(scoreBase + pointsApplied)

  // ---- 5) الحظر ----
  const wasActive = ban0.active
  const wasTemporary = ban0.status === 'TEMPORARY'
  const untilBefore = bannedUntil
  let reason: string | null = null

  if (event.forcePermanent === true) {
    if (banStatus !== 'PERMANENT') {
      bannedAt = now
      banReason = event.reason ?? 'حظر دائم'
      reason = banReason
    }

    banStatus = 'PERMANENT'
    bannedUntil = null
    scoreAfter = Math.max(scoreAfter, permanentScore)
  } else if (banStatus !== 'PERMANENT' && negative) {
    if (scoreAfter >= permanentScore) {
      banStatus = 'PERMANENT'
      bannedUntil = null
      bannedAt = now
      isManualBan = false
      banReason = `سمعة حرجة (${scoreAfter}/10)${event.reason ? `: ${event.reason}` : ''}`
      reason = banReason
    } else if (!isManualBan) {
      const failTrigger = failedInc > 0 && failedAfter >= rules.autoBanAfterFails
      const limitTrigger = event.hardLimitHit === true && rules.banOnMaxRequests !== false

      if (failTrigger || limitTrigger) {
        const until = new Date(nowMs + rules.temporaryBanMinutes * 60_000)

        if (banStatus === 'TEMPORARY') {
          // دليل جديد أثناء الحظر: بنمدّه
          if (bannedUntil === null || until > bannedUntil) bannedUntil = until
        } else {
          banStatus = 'TEMPORARY'
          bannedUntil = until
          bannedAt = now
          banReason = limitTrigger
            ? 'تجاوز الحد الأقصى للطلبات'
            : `فشل ${failedAfter} اختبار${event.reason ? `: ${event.reason}` : ''}`
          reason = banReason
        }
      }
    }
  }

  const newlyBanned = !wasActive && banStatus !== 'NONE'
  const escalated = wasTemporary && banStatus === 'PERMANENT'
  const extended =
    wasTemporary &&
    banStatus === 'TEMPORARY' &&
    bannedUntil !== null &&
    untilBefore !== null &&
    bannedUntil.getTime() > untilBefore.getTime()

  if (banStatus === 'NONE') {
    bannedAt = null
    banReason = null
    isManualBan = false
  }

  return {
    state: {
      score: scoreAfter,
      failedChecks: failedAfter,
      banStatus,
      bannedUntil,
      isManualBan,
      isAllowlisted: false,
      isKnownBotnet,
      lastFailedAt: negative ? now : (decay.anchor ?? current.lastFailedAt ?? null),
      createdAt: current.createdAt ?? null,
      bannedAt,
      banReason,
    },
    change: {
      scoreBefore: current.score,
      scoreAfter,
      pointsRaw,
      pointsApplied,
      decayApplied: decay.scorePoints,
      failedBefore: current.failedChecks,
      failedAfter,
      banBefore: ban0.status,
      banAfter: banStatus,
      newlyBanned,
      escalated,
      extended,
      banType: banStatus === 'NONE' ? null : banStatus,
      reason,
    },
  }
}

// ==================================================================
// الواجهة القديمة (متوافقة): بترجّع الحالة الجديدة بس
// ==================================================================

export function applyReputationEvent(
  current: ReputationState,
  event: ReputationEvent,
  rules: ReputationPolicyRules,
  now: Date = new Date(),
): ReputationState {
  return evaluateReputationEvent(current, event, rules, now).state
}

export function isCurrentlyBanned(
  state: ReputationState,
  now: Date = new Date(),
): { banned: boolean; reason?: string; minutesLeft?: number } {
  if (state.isAllowlisted === true) return { banned: false }

  const ban = resolveBan(state, now)

  if (ban.status === 'PERMANENT') {
    return { banned: true, reason: 'Permanent ban (reputation score critical)' }
  }

  if (ban.status === 'TEMPORARY' && state.bannedUntil !== null) {
    return {
      banned: true,
      reason: `Temporary ban until ${state.bannedUntil.toISOString()}`,
      ...(ban.minutesLeft !== null && { minutesLeft: ban.minutesLeft }),
    }
  }

  return { banned: false }
}