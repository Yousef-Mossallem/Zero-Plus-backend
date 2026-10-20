// backend/src/modules/reputation/reputation.service.ts
// ==================================================================
// Zero Plus - Reputation Service
// ------------------------------------------------------------------
// السمعة الذكية: الـ Gateway يبعت أدلة (signals) والباك يحسب النقاط
// حسب (نوع الدليل × الخطورة × التأكد × التكرار × تاريخ المعتدي)،
// ويطبق Policy الشركة في الحظر، ويخفض السمعة تدريجيًا مع الوقت.
//
// قواعد أساسية:
//   1) Lazy: السجل بيتنشئ فقط عند دليل سلبي أو فشل اختبار (الزائر النضيف ما بيتخزنش)
//   2) الحظر المؤقت/الدائم بيطلع من Policy الشركة فقط (الـ Gateway ما يفرضش حظر)
//   3) الجهاز الموثوق (isAllowlisted) ما بيتحظرش ولا بتتغير سمعته
//   4) المطابقة بالبصمة بتستخدم deviceFingerprint فقط (JA3/JA4 بتتشارك بين
//      ملايين المتصفحات فمش مناسبة للحظر، بتتخزن للتحليل بس)
//   5) كل عملية معزولة بـ organizationId، والعمليات اليدوية بتسجل Notification
//   6) منع تكرار الأدلة (dedupe) وidempotencyKey في الذاكرة: بيتصفّر مع
//      إعادة التشغيل وغير مشترك بين أكتر من instance (للـ production: Redis)
// ==================================================================

import { Prisma, type BanStatus, type ReputationEntry } from '@prisma/client'
import type { FastifyInstance } from 'fastify'

import {
  REPUTATION_TUNING,
  SIGNAL_CATALOG,
  computeSignalPoints,
  getScoreBand,
  pointsFromSignals,
  repeatOffenderFactor,
  reputationRiskPoints,
  resolveEffectiveBan,
} from './reputation.schema.js'

import type {
  AllowlistInput,
  AppliedSignalResult,
  ApplyReputationBatchInput,
  ApplyReputationBatchResult,
  ApplyReputationInput,
  ApplyReputationResult,
  GatewayBanItem,
  GatewayBansListResult,
  GatewayBansQuery,
  ListReputationQuery,
  LookupReputationQuery,
  LookupReputationResult,
  ManualBanInput,
  ReputationChallengesQuery,
  ReputationEntryPublic,
  ReputationMatchedBy,
  ReputationStatsResult,
  ResetReputationInput,
  ScoreBand,
  Severity,
  SignalDefinition,
  SignalInput,
  SignalType,
  UnbanInput,
} from './reputation.schema.js'

// ==================================================================
// Config
// ==================================================================

const DEFAULT_POLICY = {
  autoBanAfterFails: 2,
  temporaryBanMinutes: 120,
  permanentBanScore: 9,
  banOnMaxRequests: true,
} as const

type PolicySnapshot = {
  autoBanAfterFails: number
  temporaryBanMinutes: number
  permanentBanScore: number
  banOnMaxRequests: boolean
}

interface OrgContext {
  policy: PolicySnapshot
}

/** أقصى عدد فشل بيتحسب في تقرير واحد (يمنع حظر فوري من تقرير واحد مليان أدلة) */
const MAX_FAILED_PER_REPORT = 2
/** عتبة إشعار "سمعة حرجة" */
const CRITICAL_SCORE = 8
const MAX_TX_ATTEMPTS = 3
const IDEMPOTENCY_TTL_MS = 10 * 60_000
const ORG_ACTIVE_CACHE_TTL_MS = 30_000

// ==================================================================
// Types & Errors
// ==================================================================

export class ReputationServiceError extends Error {
  public readonly statusCode: number
  public readonly code: string
  public readonly details?: unknown

  constructor(
    message: string,
    statusCode: number,
    code: string,
    details?: unknown,
  ) {
    super(message)
    this.name = 'ReputationServiceError'
    this.statusCode = statusCode
    this.code = code
    this.details = details
  }
}

/** مين عمل الإجراء اليدوي (للـ Audit) */
export interface ReputationActor {
  userId: string
  email?: string
}

export interface ListReputationResult {
  data: ReputationEntryPublic[]
  pagination: {
    page: number
    limit: number
    total: number
    totalPages: number
    hasNextPage: boolean
    hasPreviousPage: boolean
  }
}

export interface ChallengeLogPublic {
  id: string
  challengeType: string
  passed: boolean
  durationMs: number | null
  failureReason: string | null
  serverId: string | null
  createdAt: string
}

export interface ListChallengesResult {
  data: ChallengeLogPublic[]
  pagination: ListReputationResult['pagination']
}

export interface ManualActionResult {
  entry: ReputationEntryPublic
  /** false = الحالة المطلوبة كانت موجودة أصلًا (ما اتعملش تغيير) */
  changed: boolean
}

// ==================================================================
// Helpers (دوال صرفة)
// ==================================================================

const round2 = (value: number) => Math.round(value * 100) / 100
const clampScore = (value: number) => Math.min(10, Math.max(1, Math.round(value)))

function isPrismaError(
  error: unknown,
  code: string,
): error is Prisma.PrismaClientKnownRequestError {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError && error.code === code
  )
}

const notFound = () =>
  new ReputationServiceError('سجل السمعة غير موجود', 404, 'REPUTATION_NOT_FOUND')

export function toPublic(entry: ReputationEntry): ReputationEntryPublic {
  return {
    id: entry.id,
    organizationId: entry.organizationId,
    ipAddress: entry.ipAddress,
    deviceFingerprint: entry.deviceFingerprint,
    ja3Fingerprint: entry.ja3Fingerprint,
    ja4Fingerprint: entry.ja4Fingerprint,
    countryCode: entry.countryCode,
    asn: entry.asn,
    asOrg: entry.asOrg,
    ipType: entry.ipType,
    score: entry.score,
    scoreBand: getScoreBand(entry.score),
    banStatus: entry.banStatus,
    bannedUntil: entry.bannedUntil?.toISOString() ?? null,
    bannedAt: entry.bannedAt?.toISOString() ?? null,
    banReason: entry.banReason,
    isManualBan: entry.isManualBan,
    isAllowlisted: entry.isAllowlisted,
    failedChecksCount: entry.failedChecksCount,
    successfulChecks: entry.successfulChecks,
    totalRequests: entry.totalRequests,
    lastFailedAt: entry.lastFailedAt?.toISOString() ?? null,
    lastPath: entry.lastPath,
    lastUserAgent: entry.lastUserAgent,
    avgRequestRate: entry.avgRequestRate,
    isKnownBotnet: entry.isKnownBotnet,
    firstSeenAt: entry.firstSeenAt.toISOString(),
    lastSeenAt: entry.lastSeenAt.toISOString(),
    createdAt: entry.createdAt.toISOString(),
    updatedAt: entry.updatedAt.toISOString(),
  }
}

/**
 * تقادم السمعة: كل DECAY_AFTER_HOURS ساعة من غير أدلة سلبية = تخفيض نقطة
 * (وبينزل معاها عداد الفشل، فمحدش يتحظر بسبب فشلين بينهم شهرين).
 * ما بيتطبقش على: الحظر الدائم / اليدوي / البوت نت المعروف / الجهاز الموثوق /
 * الحظر المؤقت الساري.
 * anchor = نقطة البداية الجديدة (بتتقدم عشان نفس المدة ما تتحسبش مرتين).
 */
function computeDecay(entry: ReputationEntry, now: Date) {
  const none = {
    steps: 0,
    scorePoints: 0,
    failedAfter: entry.failedChecksCount,
    anchor: null as Date | null,
  }

  const activeTemporaryBan =
    entry.banStatus === 'TEMPORARY' &&
    entry.bannedUntil !== null &&
    entry.bannedUntil.getTime() > now.getTime()

  if (
    entry.isAllowlisted ||
    entry.isManualBan ||
    entry.isKnownBotnet ||
    entry.banStatus === 'PERMANENT' ||
    activeTemporaryBan
  ) {
    return none
  }

  const from = entry.lastFailedAt ?? entry.createdAt
  const periodMs = REPUTATION_TUNING.DECAY_AFTER_HOURS * 3_600_000
  const steps = Math.floor((now.getTime() - from.getTime()) / periodMs)

  if (steps <= 0) return none

  return {
    steps,
    scorePoints: Math.min(
      Math.max(0, entry.score - 1),
      steps * REPUTATION_TUNING.DECAY_STEP,
    ),
    failedAfter: Math.max(0, entry.failedChecksCount - steps),
    anchor: new Date(from.getTime() + steps * periodMs),
  }
}

const SEVERITY_ORDER: Record<Severity, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
}

/** دمج الأدلة المكررة من نفس النوع في نفس التقرير */
function mergeSignals(
  signals: ApplyReputationInput['signals'],
): Array<SignalInput & { note?: string }> {
  const merged = new Map<SignalType, SignalInput & { note?: string }>()

  for (const signal of signals) {
    const type = signal.type as SignalType
    const current = merged.get(type)

    if (!current) {
      merged.set(type, {
        type,
        severity: signal.severity,
        confidence: signal.confidence,
        count: signal.count,
        ...(signal.anomalyScore !== undefined
          ? { anomalyScore: signal.anomalyScore }
          : {}),
        ...(signal.note !== undefined ? { note: signal.note } : {}),
      })
      continue
    }

    current.count = (current.count ?? 1) + signal.count
    current.confidence = Math.max(current.confidence ?? 0, signal.confidence)
    current.anomalyScore = Math.max(
      current.anomalyScore ?? 0,
      signal.anomalyScore ?? 0,
    )

    if (
      SEVERITY_ORDER[signal.severity] >
      SEVERITY_ORDER[current.severity ?? 'MEDIUM']
    ) {
      current.severity = signal.severity
    }
  }

  return [...merged.values()]
}

function describeSignals(signals: SignalInput[]): string {
  const labels = signals
    .filter((s) => computeSignalPoints(s) > 0)
    .sort((a, b) => computeSignalPoints(b) - computeSignalPoints(a))
    .slice(0, 3)
    .map((s) => (SIGNAL_CATALOG[s.type] as SignalDefinition).label)

  return labels.length > 0 ? labels.join('، ') : 'أدلة سلبية متراكمة'
}

// ---- ذاكرة منع التكرار (key → وقت الانتهاء) ----
const signalSeen = new Map<string, number>()
const idempotencySeen = new Map<string, number>()
const orgActiveCache = new Map<string, { active: boolean; expiresAt: number }>()

function isFresh(map: Map<string, number>, key: string, nowMs: number) {
  const expiresAt = map.get(key)
  return expiresAt !== undefined && expiresAt > nowMs
}

function prune(map: Map<string, number>, nowMs: number) {
  if (map.size < 5000) return

  for (const [key, expiresAt] of map) {
    if (expiresAt <= nowMs) map.delete(key)
  }
}

// ==================================================================
// Service
// ==================================================================

export class ReputationService {
  constructor(private readonly fastify: FastifyInstance) {}

  // ================================================================
  // Private: سياق الشركة والـ Policy
  // ================================================================

  /** شركة موجودة ونشطة + الـ Policy بتاعتها (استعلام واحد) */
  private async getOrgContext(
    organizationId: string,
    cache?: Map<string, OrgContext>,
  ): Promise<OrgContext> {
    const hit = cache?.get(organizationId)

    if (hit) return hit

    const org = await this.fastify.prisma.organization.findUnique({
      where: { id: organizationId },
      select: {
        isActive: true,
        policy: {
          select: {
            autoBanAfterFails: true,
            temporaryBanMinutes: true,
            permanentBanScore: true,
            banOnMaxRequests: true,
          },
        },
      },
    })

    if (!org) {
      throw new ReputationServiceError(
        'المؤسسة غير موجودة',
        404,
        'ORGANIZATION_NOT_FOUND',
      )
    }

    if (!org.isActive) {
      throw new ReputationServiceError(
        'المؤسسة غير مفعّلة',
        403,
        'ORGANIZATION_INACTIVE',
      )
    }

    const ctx: OrgContext = {
      policy: { ...DEFAULT_POLICY, ...(org.policy ?? {}) },
    }

    cache?.set(organizationId, ctx)

    return ctx
  }

  /** للـ lookup (مسار ساخن): كاش 30 ثانية لفحص التفعيل فقط */
  private async assertOrgActiveCached(organizationId: string) {
    const nowMs = Date.now()
    const hit = orgActiveCache.get(organizationId)

    if (hit && hit.expiresAt > nowMs) {
      if (!hit.active) {
        throw new ReputationServiceError(
          'المؤسسة غير مفعّلة',
          403,
          'ORGANIZATION_INACTIVE',
        )
      }
      return
    }

    const org = await this.fastify.prisma.organization.findUnique({
      where: { id: organizationId },
      select: { isActive: true },
    })

    if (!org) {
      throw new ReputationServiceError(
        'المؤسسة غير موجودة',
        404,
        'ORGANIZATION_NOT_FOUND',
      )
    }

    orgActiveCache.set(organizationId, {
      active: org.isActive,
      expiresAt: nowMs + ORG_ACTIVE_CACHE_TTL_MS,
    })

    if (!org.isActive) {
      throw new ReputationServiceError(
        'المؤسسة غير مفعّلة',
        403,
        'ORGANIZATION_INACTIVE',
      )
    }
  }

  private async loadPolicy(organizationId: string): Promise<PolicySnapshot> {
    const policy = await this.fastify.prisma.policy.findUnique({
      where: { organizationId },
      select: {
        autoBanAfterFails: true,
        temporaryBanMinutes: true,
        permanentBanScore: true,
        banOnMaxRequests: true,
      },
    })

    return { ...DEFAULT_POLICY, ...(policy ?? {}) }
  }

  private async runSerializable<T>(
    fn: (tx: Prisma.TransactionClient) => Promise<T>,
  ): Promise<T> {
    for (let attempt = 1; ; attempt++) {
      try {
        return await this.fastify.prisma.$transaction(fn, {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
        })
      } catch (error) {
        // P2034: تعارض Transactions | P2002: سباق إنشاء نفس السجل
        const retryable = isPrismaError(error, 'P2034') || isPrismaError(error, 'P2002')

        if (retryable && attempt < MAX_TX_ATTEMPTS) continue

        if (retryable) {
          throw new ReputationServiceError(
            'حصل تعارض أثناء حفظ السمعة، حاول مرة أخرى',
            409,
            'CONFLICT',
          )
        }

        throw error
      }
    }
  }

  private async findOwned(
    db: Prisma.TransactionClient | FastifyInstance['prisma'],
    organizationId: string,
    id: string,
  ): Promise<ReputationEntry> {
    const entry = await db.reputationEntry.findFirst({
      // organizationId جزء أساسي: ما ينفعش حد يوصل لسجل شركة تانية
      where: { id, organizationId },
    })

    if (!entry) throw notFound()

    return entry
  }

  private async writeAudit(
    tx: Prisma.TransactionClient,
    organizationId: string,
    title: string,
    message: string,
    metadata: Record<string, unknown>,
    severity = 1,
  ) {
    await tx.notification.create({
      data: {
        organizationId,
        type: 'SYSTEM',
        title,
        message,
        severity,
        metadata: metadata as Prisma.InputJsonObject,
      },
    })
  }

  // ================================================================
  // Dashboard: قراءة
  // ================================================================

  async list(
    organizationId: string,
    query: ListReputationQuery,
  ): Promise<ListReputationResult> {
    const now = new Date()
    const and: Prisma.ReputationEntryWhereInput[] = []

    // الحظر المؤقت المنتهي بيتحسب NONE (من غير ما ننتظر تنظيف)
    if (query.banStatus === 'PERMANENT') {
      and.push({ banStatus: 'PERMANENT' })
    } else if (query.banStatus === 'TEMPORARY') {
      and.push({ banStatus: 'TEMPORARY', bannedUntil: { gt: now } })
    } else if (query.banStatus === 'NONE') {
      and.push({
        OR: [
          { banStatus: 'NONE' },
          { banStatus: 'TEMPORARY', bannedUntil: { lte: now } },
          { banStatus: 'TEMPORARY', bannedUntil: null },
        ],
      })
    }

    if (query.search) {
      and.push({
        OR: [
          { ipAddress: { contains: query.search, mode: 'insensitive' } },
          { deviceFingerprint: { contains: query.search, mode: 'insensitive' } },
        ],
      })
    }

    const where: Prisma.ReputationEntryWhereInput = {
      organizationId,
      ...(and.length > 0 && { AND: and }),
      ...(query.ipType && { ipType: query.ipType }),
      ...(query.countryCode && { countryCode: query.countryCode }),
      ...(query.asn !== undefined && { asn: query.asn }),
      ...(query.isAllowlisted !== undefined && { isAllowlisted: query.isAllowlisted }),
      ...(query.isManualBan !== undefined && { isManualBan: query.isManualBan }),
      ...(query.isKnownBotnet !== undefined && { isKnownBotnet: query.isKnownBotnet }),
      ...((query.minScore !== undefined || query.maxScore !== undefined) && {
        score: {
          ...(query.minScore !== undefined && { gte: query.minScore }),
          ...(query.maxScore !== undefined && { lte: query.maxScore }),
        },
      }),
      ...((query.lastSeenAfter || query.lastSeenBefore) && {
        lastSeenAt: {
          ...(query.lastSeenAfter && { gte: new Date(query.lastSeenAfter) }),
          ...(query.lastSeenBefore && { lte: new Date(query.lastSeenBefore) }),
        },
      }),
    }

    const [total, rows] = await this.fastify.prisma.$transaction([
      this.fastify.prisma.reputationEntry.count({ where }),
      this.fastify.prisma.reputationEntry.findMany({
        where,
        orderBy: [
          { [query.sortBy]: query.sortOrder } as Prisma.ReputationEntryOrderByWithRelationInput,
          { id: 'asc' },
        ],
        skip: (query.page - 1) * query.limit,
        take: query.limit,
      }),
    ])

    const totalPages = Math.ceil(total / query.limit)

    return {
      data: rows.map(toPublic),
      pagination: {
        page: query.page,
        limit: query.limit,
        total,
        totalPages,
        hasNextPage: query.page < totalPages,
        hasPreviousPage: query.page > 1,
      },
    }
  }

  async getById(
    organizationId: string,
    id: string,
  ): Promise<ReputationEntryPublic> {
    return toPublic(await this.findOwned(this.fastify.prisma, organizationId, id))
  }

  async listChallenges(
    organizationId: string,
    id: string,
    query: ReputationChallengesQuery,
  ): Promise<ListChallengesResult> {
    await this.findOwned(this.fastify.prisma, organizationId, id)

    const where: Prisma.ChallengeLogWhereInput = {
      reputationEntryId: id,
      organizationId,
      ...(query.passed !== undefined && { passed: query.passed }),
    }

    const [total, rows] = await this.fastify.prisma.$transaction([
      this.fastify.prisma.challengeLog.count({ where }),
      this.fastify.prisma.challengeLog.findMany({
        where,
        orderBy: [{ createdAt: 'desc' }, { id: 'asc' }],
        skip: (query.page - 1) * query.limit,
        take: query.limit,
      }),
    ])

    const totalPages = Math.ceil(total / query.limit)

    return {
      data: rows.map((log) => ({
        id: log.id,
        challengeType: log.challengeType,
        passed: log.passed,
        durationMs: log.durationMs,
        failureReason: log.failureReason,
        serverId: log.serverId,
        createdAt: log.createdAt.toISOString(),
      })),
      pagination: {
        page: query.page,
        limit: query.limit,
        total,
        totalPages,
        hasNextPage: query.page < totalPages,
        hasPreviousPage: query.page > 1,
      },
    }
  }

  async getStats(organizationId: string): Promise<ReputationStatsResult> {
    const now = new Date()
    const db = this.fastify.prisma
    const base = { organizationId }

    const [
      total,
      permanent,
      activeTemporary,
      allowlisted,
      knownBotnets,
      clean,
      low,
      elevated,
      high,
      critical,
    ] = await db.$transaction([
      db.reputationEntry.count({ where: base }),
      db.reputationEntry.count({ where: { ...base, banStatus: 'PERMANENT' } }),
      db.reputationEntry.count({
        where: { ...base, banStatus: 'TEMPORARY', bannedUntil: { gt: now } },
      }),
      db.reputationEntry.count({ where: { ...base, isAllowlisted: true } }),
      db.reputationEntry.count({ where: { ...base, isKnownBotnet: true } }),
      db.reputationEntry.count({ where: { ...base, score: { lte: 1 } } }),
      db.reputationEntry.count({ where: { ...base, score: { gte: 2, lte: 3 } } }),
      db.reputationEntry.count({ where: { ...base, score: { gte: 4, lte: 6 } } }),
      db.reputationEntry.count({ where: { ...base, score: { gte: 7, lte: 8 } } }),
      db.reputationEntry.count({ where: { ...base, score: { gte: 9 } } }),
    ])

    const byBand: Record<ScoreBand, number> = {
      CLEAN: clean,
      LOW: low,
      ELEVATED: elevated,
      HIGH: high,
      CRITICAL: critical,
    }

    return {
      total,
      byBanStatus: {
        NONE: Math.max(0, total - permanent - activeTemporary),
        TEMPORARY: activeTemporary,
        PERMANENT: permanent,
      },
      byBand,
      allowlisted,
      knownBotnets,
    }
  }

  // ================================================================
  // Dashboard: إجراءات يدوية
  // ================================================================

  async manualBan(
    organizationId: string,
    id: string,
    input: ManualBanInput,
    actor: ReputationActor,
  ): Promise<ManualActionResult> {
    const policy = await this.loadPolicy(organizationId)

    return this.fastify.prisma.$transaction(async (tx) => {
      const entry = await this.findOwned(tx, organizationId, id)

      if (entry.isAllowlisted) {
        throw new ReputationServiceError(
          'الجهاز ده موثوق (allowlist). ارفع الثقة عنه الأول قبل الحظر',
          409,
          'ENTRY_ALLOWLISTED',
        )
      }

      const now = new Date()
      const permanent = input.type === 'PERMANENT'

      const updated = await tx.reputationEntry.update({
        where: { id },
        data: {
          banStatus: input.type,
          bannedUntil: permanent
            ? null
            : new Date(
                now.getTime() +
                  (input.minutes ?? policy.temporaryBanMinutes) * 60_000,
              ),
          bannedAt: now,
          banReason: input.reason,
          isManualBan: true,
          ...(permanent && {
            score: Math.max(entry.score, policy.permanentBanScore),
          }),
        },
      })

      await tx.notification.create({
        data: {
          organizationId,
          type: 'NEW_BLOCK',
          title: permanent ? 'حظر دائم يدوي' : 'حظر مؤقت يدوي',
          message: `${actor.email ?? 'مستخدم'} حظر ${entry.ipAddress}: ${input.reason}`,
          severity: permanent ? 3 : 2,
          metadata: {
            action: 'MANUAL_BAN',
            reputationEntryId: id,
            ipAddress: entry.ipAddress,
            banType: input.type,
            bannedUntil: updated.bannedUntil?.toISOString() ?? null,
            reason: input.reason,
            byUserId: actor.userId,
            byEmail: actor.email ?? null,
          } as Prisma.InputJsonObject,
        },
      })

      return { entry: toPublic(updated), changed: true }
    })
  }

  async unban(
    organizationId: string,
    id: string,
    input: UnbanInput,
    actor: ReputationActor,
  ): Promise<ManualActionResult> {
    const policy = await this.loadPolicy(organizationId)

    return this.fastify.prisma.$transaction(async (tx) => {
      const entry = await this.findOwned(tx, organizationId, id)

      if (entry.banStatus === 'NONE' && !input.resetScore) {
        return { entry: toPublic(entry), changed: false }
      }

      // من غير resetScore: نخلي السمعة تحت عتبة الحظر الدائم والفشل تحت عتبة
      // الحظر التلقائي، وإلا أول دليل جديد هيحظره فورًا تاني
      const updated = await tx.reputationEntry.update({
        where: { id },
        data: {
          banStatus: 'NONE',
          bannedUntil: null,
          bannedAt: null,
          banReason: null,
          isManualBan: false,
          ...(input.resetScore
            ? { score: 1, failedChecksCount: 0, lastFailedAt: null }
            : {
                score: Math.min(entry.score, policy.permanentBanScore - 1),
                failedChecksCount: Math.min(
                  entry.failedChecksCount,
                  Math.max(0, policy.autoBanAfterFails - 1),
                ),
              }),
        },
      })

      await this.writeAudit(
        tx,
        organizationId,
        'تم رفع الحظر',
        `${actor.email ?? 'مستخدم'} رفع الحظر عن ${entry.ipAddress}`,
        {
          action: 'UNBAN',
          reputationEntryId: id,
          ipAddress: entry.ipAddress,
          previousBanStatus: entry.banStatus,
          resetScore: input.resetScore,
          reason: input.reason ?? null,
          byUserId: actor.userId,
          byEmail: actor.email ?? null,
        },
      )

      return { entry: toPublic(updated), changed: true }
    })
  }

  async setAllowlist(
    organizationId: string,
    id: string,
    input: AllowlistInput,
    actor: ReputationActor,
  ): Promise<ManualActionResult> {
    return this.fastify.prisma.$transaction(async (tx) => {
      const entry = await this.findOwned(tx, organizationId, id)

      if (entry.isAllowlisted === input.enabled) {
        return { entry: toPublic(entry), changed: false }
      }

      // الثقة بترفع الحظر الحالي وبتمنع أي حظر جاي
      const updated = await tx.reputationEntry.update({
        where: { id },
        data: input.enabled
          ? {
              isAllowlisted: true,
              banStatus: 'NONE',
              bannedUntil: null,
              bannedAt: null,
              banReason: null,
              isManualBan: false,
            }
          : { isAllowlisted: false },
      })

      await this.writeAudit(
        tx,
        organizationId,
        input.enabled ? 'تمت إضافة جهاز موثوق' : 'تم إلغاء الثقة في جهاز',
        `${actor.email ?? 'مستخدم'} ${input.enabled ? 'وثّق' : 'ألغى توثيق'} ${entry.ipAddress}`,
        {
          action: input.enabled ? 'ALLOWLIST_ON' : 'ALLOWLIST_OFF',
          reputationEntryId: id,
          ipAddress: entry.ipAddress,
          reason: input.reason ?? null,
          byUserId: actor.userId,
          byEmail: actor.email ?? null,
        },
      )

      return { entry: toPublic(updated), changed: true }
    })
  }

  async resetReputation(
    organizationId: string,
    id: string,
    input: ResetReputationInput,
    actor: ReputationActor,
  ): Promise<ManualActionResult> {
    return this.fastify.prisma.$transaction(async (tx) => {
      const entry = await this.findOwned(tx, organizationId, id)

      const updated = await tx.reputationEntry.update({
        where: { id },
        data: {
          score: 1,
          failedChecksCount: 0,
          lastFailedAt: null,
          banStatus: 'NONE',
          bannedUntil: null,
          bannedAt: null,
          banReason: null,
          isManualBan: false,
          isKnownBotnet: false,
        },
      })

      await this.writeAudit(
        tx,
        organizationId,
        'تم تصفير سمعة جهاز',
        `${actor.email ?? 'مستخدم'} صفّر سمعة ${entry.ipAddress}`,
        {
          action: 'RESET',
          reputationEntryId: id,
          ipAddress: entry.ipAddress,
          scoreBefore: entry.score,
          reason: input.reason ?? null,
          byUserId: actor.userId,
          byEmail: actor.email ?? null,
        },
      )

      return { entry: toPublic(updated), changed: true }
    })
  }

  // ================================================================
  // Gateway: LOOKUP (قبل القرار)
  // ================================================================

  /**
   * الترتيب: سجل الـ IP أولًا، وبعدين deviceFingerprint (جهاز غيّر الـ IP).
   * لو الـ IP نضيف لكن نفس الجهاز محظور عندنا ← بنرجّع حظر الجهاز.
   * الجهاز الموثوق على الـ IP ليه الأولوية.
   * السمعة المرجّعة بعد التقادم (قراءة فقط، من غير كتابة).
   */
  async lookup(query: LookupReputationQuery): Promise<LookupReputationResult> {
    await this.assertOrgActiveCached(query.organizationId)

    const db = this.fastify.prisma
    const now = new Date()

    const ipEntry = await db.reputationEntry.findUnique({
      where: {
        organizationId_ipAddress: {
          organizationId: query.organizationId,
          ipAddress: query.ipAddress,
        },
      },
    })

    const deviceEntry =
      query.deviceFingerprint && !ipEntry?.isAllowlisted
        ? await db.reputationEntry.findFirst({
            where: {
              organizationId: query.organizationId,
              deviceFingerprint: query.deviceFingerprint,
              isAllowlisted: false,
              ...(ipEntry && { id: { not: ipEntry.id } }),
            },
            orderBy: [{ score: 'desc' }, { lastSeenAt: 'desc' }],
          })
        : null

    let chosen: ReputationEntry | null = ipEntry
    let matchedBy: ReputationMatchedBy | null = ipEntry ? 'IP' : null

    if (deviceEntry) {
      if (!ipEntry) {
        chosen = deviceEntry
        matchedBy = 'DEVICE_FINGERPRINT'
      } else {
        const ipBan = resolveEffectiveBan(ipEntry.banStatus, ipEntry.bannedUntil, now)
        const deviceBan = resolveEffectiveBan(
          deviceEntry.banStatus,
          deviceEntry.bannedUntil,
          now,
        )

        if (deviceBan.isCurrentlyBanned && !ipBan.isCurrentlyBanned) {
          chosen = deviceEntry
          matchedBy = 'DEVICE_FINGERPRINT'
        }
      }
    }

    if (!chosen) {
      return {
        found: false,
        matchedBy: null,
        entry: null,
        effective: {
          score: 1,
          scoreBand: 'CLEAN',
          banStatus: 'NONE',
          isCurrentlyBanned: false,
          bannedUntil: null,
          minutesLeftOnBan: null,
          isAllowlisted: false,
          isManualBan: false,
          isKnownBotnet: false,
          failedChecksCount: 0,
          reputationRiskPoints: 0,
        },
      }
    }

    // تنظيف الحظر المؤقت المنتهي (بيرفع updatedAt فالـ Gateway يشيله من الـ Redis)
    if (
      chosen.banStatus === 'TEMPORARY' &&
      !resolveEffectiveBan(chosen.banStatus, chosen.bannedUntil, now).isCurrentlyBanned
    ) {
      await db.reputationEntry.updateMany({
        where: {
          id: chosen.id,
          banStatus: 'TEMPORARY',
          OR: [{ bannedUntil: null }, { bannedUntil: { lte: now } }],
        },
        data: {
          banStatus: 'NONE',
          bannedUntil: null,
          bannedAt: null,
          banReason: null,
          isManualBan: false,
        },
      })

      chosen = { ...chosen, banStatus: 'NONE', bannedUntil: null }
    }

    const decay = computeDecay(chosen, now)
    const effectiveScore = Math.max(1, chosen.score - decay.scorePoints)

    const ban = chosen.isAllowlisted
      ? { banStatusEffective: 'NONE' as BanStatus, isCurrentlyBanned: false, minutesLeftOnBan: null }
      : resolveEffectiveBan(chosen.banStatus, chosen.bannedUntil, now)

    return {
      found: true,
      matchedBy,
      entry: toPublic(chosen),
      effective: {
        score: effectiveScore,
        scoreBand: getScoreBand(effectiveScore),
        banStatus: ban.banStatusEffective,
        isCurrentlyBanned: ban.isCurrentlyBanned,
        bannedUntil:
          ban.banStatusEffective === 'TEMPORARY'
            ? (chosen.bannedUntil?.toISOString() ?? null)
            : null,
        minutesLeftOnBan: ban.minutesLeftOnBan,
        isAllowlisted: chosen.isAllowlisted,
        isManualBan: chosen.isManualBan,
        isKnownBotnet: chosen.isKnownBotnet,
        failedChecksCount: decay.failedAfter,
        reputationRiskPoints: chosen.isAllowlisted
          ? 0
          : reputationRiskPoints(effectiveScore),
      },
    }
  }

  // ================================================================
  // Gateway: APPLY (تسجيل الأدلة)
  // ================================================================

  async apply(input: ApplyReputationInput): Promise<ApplyReputationResult> {
    return this.applyWithCache(input, new Map())
  }

  async applyBatch(
    input: ApplyReputationBatchInput,
  ): Promise<ApplyReputationBatchResult> {
    const cache = new Map<string, OrgContext>()
    const results: ApplyReputationBatchResult['results'] = []
    let succeeded = 0
    let newlyBanned = 0

    // بالتتابع: تقريران لنفس الـ IP في نفس الدفعة ما يتعارضوش
    for (const [index, report] of input.reports.entries()) {
      try {
        const result = await this.applyWithCache(report, cache)

        results.push({ index, ok: true, result })
        succeeded++

        if (result.change?.newlyBanned) newlyBanned++
      } catch (error) {
        if (error instanceof ReputationServiceError) {
          results.push({
            index,
            ok: false,
            code: error.code,
            message: error.message,
          })
        } else {
          this.fastify.log.error({ err: error, index }, 'Reputation batch item failed')
          results.push({
            index,
            ok: false,
            code: 'INTERNAL_ERROR',
            message: 'Internal error',
          })
        }
      }
    }

    return {
      results,
      summary: {
        total: input.reports.length,
        succeeded,
        failed: input.reports.length - succeeded,
        newlyBanned,
      },
    }
  }

  private async applyWithCache(
    input: ApplyReputationInput,
    cache: Map<string, OrgContext>,
  ): Promise<ApplyReputationResult> {
    const { organizationId, ipAddress } = input
    const nowMs = Date.now()

    const ctx = await this.getOrgContext(organizationId, cache)

    if (input.serverId) {
      const server = await this.fastify.prisma.server.findFirst({
        where: { id: input.serverId, organizationId },
        select: { id: true },
      })

      if (!server) {
        throw new ReputationServiceError(
          'السيرفر غير موجود أو لا ينتمي لهذه المؤسسة',
          404,
          'SERVER_NOT_FOUND',
        )
      }
    }

    // ---- Idempotency: نفس التقرير اتبعت قبل كده ----
    const idemKey = input.idempotencyKey
      ? `${organizationId}:${input.idempotencyKey}`
      : null

    if (idemKey && isFresh(idempotencySeen, idemKey, nowMs)) {
      const existing = await this.fastify.prisma.reputationEntry.findUnique({
        where: { organizationId_ipAddress: { organizationId, ipAddress } },
      })

      return {
        applied: false,
        entry: existing ? toPublic(existing) : null,
        change: null,
      }
    }

    const { result, marks } = await this.runSerializable((tx) =>
      this.applyInTransaction(tx, input, ctx.policy),
    )

    // علامات منع التكرار بتتسجل بعد نجاح الـ Transaction بس
    for (const mark of marks) signalSeen.set(mark.key, mark.expiresAt)

    if (idemKey) idempotencySeen.set(idemKey, nowMs + IDEMPOTENCY_TTL_MS)

    prune(signalSeen, nowMs)
    prune(idempotencySeen, nowMs)

    return result
  }

  /**
   * القلب: بيحسب كل حاجة جوه Transaction واحدة.
   * بيتنفّذ تاني لو الـ Transaction اتعاد، فمفيش side effects برا (العلامات بترجع كقيمة).
   */
  private async applyInTransaction(
    tx: Prisma.TransactionClient,
    input: ApplyReputationInput,
    policy: PolicySnapshot,
  ): Promise<{
    result: ApplyReputationResult
    marks: Array<{ key: string; expiresAt: number }>
  }> {
    const { organizationId, ipAddress } = input
    const now = new Date()
    const nowMs = now.getTime()
    const marks: Array<{ key: string; expiresAt: number }> = []

    const existing = await tx.reputationEntry.findUnique({
      where: { organizationId_ipAddress: { organizationId, ipAddress } },
    })

    // ---- 1) الأدلة بعد الدمج ومنع التكرار ----
    const candidates: SignalInput[] = mergeSignals(input.signals)

    // الباك بيولّد دليل الاختبار بنفسه من نتيجته
    if (input.challenge) {
      candidates.push({
        type: input.challenge.passed ? 'CHALLENGE_PASSED' : 'CHALLENGE_FAILED',
        severity: 'MEDIUM',
        confidence: 1,
        count: 1,
      })
    }

    const accepted: SignalInput[] = []
    const dedupedTypes: SignalType[] = []

    for (const signal of candidates) {
      const def: SignalDefinition = SIGNAL_CATALOG[signal.type]
      const key = `${organizationId}:${ipAddress}:${signal.type}`

      if (def.dedupeWindowSec > 0) {
        if (isFresh(signalSeen, key, nowMs)) {
          dedupedTypes.push(signal.type)
          continue
        }

        marks.push({ key, expiresAt: nowMs + def.dedupeWindowSec * 1000 })
      }

      accepted.push(signal)
    }

    const rawBase = pointsFromSignals(accepted).raw

    // ---- 2) Lazy: زائر ملوش سجل وملوش دليل سلبي = لا شيء ----
    if (!existing && rawBase <= 0) {
      return {
        result: { applied: false, entry: null, change: null },
        marks: [],
      }
    }

    const enrichment = this.buildEnrichment(input)

    // ---- 3) جهاز موثوق: عدادات فقط، من غير سمعة ولا حظر ----
    if (existing?.isAllowlisted) {
      const saved = await tx.reputationEntry.update({
        where: { id: existing.id },
        data: {
          lastSeenAt: now,
          totalRequests: existing.totalRequests + input.requestCount,
          ...(input.challenge?.passed && {
            successfulChecks: existing.successfulChecks + 1,
          }),
          ...enrichment,
        },
      })

      await this.logChallenge(tx, input, saved.id)

      return {
        result: {
          applied: true,
          entry: toPublic(saved),
          change: {
            scoreBefore: existing.score,
            scoreAfter: existing.score,
            pointsRaw: 0,
            pointsApplied: 0,
            decayApplied: 0,
            failedChecksBefore: existing.failedChecksCount,
            failedChecksAfter: existing.failedChecksCount,
            banStatusBefore: 'NONE',
            banStatusAfter: 'NONE',
            newlyBanned: false,
            banType: null,
            signals: [],
          },
        },
        marks: [],
      }
    }

    // ---- 4) نقطة البداية: تقادم السجل القديم / وراثة من نفس الجهاز ----
    let scoreBase = 1
    let failedBase = 0
    let inheritedBotnet = false
    const decay = existing ? computeDecay(existing, now) : null

    if (existing) {
      scoreBase = existing.score - (decay?.scorePoints ?? 0)
      failedBase = decay?.failedAfter ?? existing.failedChecksCount
    } else if (input.deviceFingerprint) {
      // جهاز معروف بسوء السمعة ظهر بعنوان جديد: يبدأ من سمعته السابقة (أقل بنقطة)
      const sameDevice = await tx.reputationEntry.findFirst({
        where: {
          organizationId,
          deviceFingerprint: input.deviceFingerprint,
          isAllowlisted: false,
          score: { gte: 3 },
        },
        orderBy: { score: 'desc' },
      })

      if (sameDevice) {
        scoreBase = Math.max(1, sameDevice.score - 1)
        inheritedBotnet = sameDevice.isKnownBotnet
      }
    }

    // ---- 5) النقاط: الوزن × الخطورة × التأكد × التكرار × تاريخ المعتدي ----
    const factor = rawBase > 0 ? repeatOffenderFactor(failedBase) : 1
    const pointsRaw = round2(pointsFromSignals(accepted).raw * factor)

    const pointsApplied = Math.round(
      Math.min(
        REPUTATION_TUNING.MAX_POINTS_PER_REPORT,
        Math.max(REPUTATION_TUNING.MIN_POINTS_PER_REPORT, pointsRaw),
      ),
    )

    const negativeEvidence = pointsApplied > 0 || pointsRaw > 0

    const failedSignals = accepted.filter(
      (s) =>
        (SIGNAL_CATALOG[s.type] as SignalDefinition).countsAsFailedCheck &&
        computeSignalPoints(s) > 0,
    ).length

    const failedInc = Math.min(MAX_FAILED_PER_REPORT, failedSignals)
    const failedAfter = failedBase + failedInc
    const successInc = accepted.some((s) => s.type === 'CHALLENGE_PASSED') ? 1 : 0

    const scoreBefore = existing?.score ?? 1
    const scoreAfter = clampScore(scoreBase + pointsApplied)

    // ---- 6) الحظر (من Policy الشركة فقط) ----
    const banBefore = existing
      ? resolveEffectiveBan(existing.banStatus, existing.bannedUntil, now)
      : null

    let banStatus: BanStatus = banBefore?.banStatusEffective ?? 'NONE'
    let bannedUntil: Date | null =
      banStatus === 'TEMPORARY' ? (existing?.bannedUntil ?? null) : null
    let bannedAt: Date | null = banStatus !== 'NONE' ? (existing?.bannedAt ?? null) : null
    let banReason: string | null = banStatus !== 'NONE' ? (existing?.banReason ?? null) : null
    let isManualBan = banStatus !== 'NONE' ? (existing?.isManualBan ?? false) : false

    const reasonText = describeSignals(accepted)
    const hardLimitHit = accepted.some(
      (s) => s.type === 'HARD_LIMIT_EXCEEDED' && computeSignalPoints(s) > 0,
    )

    if (banStatus !== 'PERMANENT' && negativeEvidence) {
      if (scoreAfter >= policy.permanentBanScore) {
        // سمعة حرجة ← حظر دائم
        banStatus = 'PERMANENT'
        bannedUntil = null
        bannedAt = now
        banReason = `سمعة حرجة (${scoreAfter}/10): ${reasonText}`
        isManualBan = false
      } else if (!isManualBan) {
        const failTrigger = failedInc > 0 && failedAfter >= policy.autoBanAfterFails
        const limitTrigger = hardLimitHit && policy.banOnMaxRequests

        if (failTrigger || limitTrigger) {
          const until = new Date(nowMs + policy.temporaryBanMinutes * 60_000)

          if (banStatus === 'TEMPORARY') {
            // دليل جديد أثناء الحظر: بنمدّه
            if (!bannedUntil || until > bannedUntil) bannedUntil = until
          } else {
            banStatus = 'TEMPORARY'
            bannedUntil = until
            bannedAt = now
            banReason = limitTrigger
              ? 'تجاوز الحد الأقصى للطلبات'
              : `فشل ${failedAfter} اختبار: ${reasonText}`
          }
        }
      }
    }

    const wasBanned = banBefore?.isCurrentlyBanned ?? false
    const newlyBanned = !wasBanned && banStatus !== 'NONE'
    const escalated =
      wasBanned && banBefore?.banStatusEffective === 'TEMPORARY' && banStatus === 'PERMANENT'

    // ---- 7) الكتابة ----
    const knownBotnet =
      inheritedBotnet ||
      (accepted.some((s) => s.type === 'KNOWN_BOTNET') && pointsApplied > 0)

    const lastFailedAt = negativeEvidence ? now : (decay?.anchor ?? undefined)

    const data = {
      score: scoreAfter,
      failedChecksCount: failedAfter,
      successfulChecks: (existing?.successfulChecks ?? 0) + successInc,
      totalRequests: (existing?.totalRequests ?? 0) + input.requestCount,
      banStatus,
      bannedUntil,
      bannedAt,
      banReason,
      isManualBan,
      lastSeenAt: now,
      ...(lastFailedAt && { lastFailedAt }),
      ...(knownBotnet && { isKnownBotnet: true }),
      ...enrichment,
    }

    const saved = existing
      ? await tx.reputationEntry.update({ where: { id: existing.id }, data })
      : await tx.reputationEntry.create({
          data: { organizationId, ipAddress, firstSeenAt: now, ...data },
        })

    await this.logChallenge(tx, input, saved.id)

    // ---- 8) الإشعارات (عند التحوّل فقط) ----
    if (newlyBanned || escalated) {
      await tx.notification.create({
        data: {
          organizationId,
          type: 'NEW_BLOCK',
          title: banStatus === 'PERMANENT' ? 'حظر دائم تلقائي' : 'حظر مؤقت تلقائي',
          message: `تم حظر ${ipAddress}: ${banReason ?? reasonText}`,
          severity: banStatus === 'PERMANENT' ? 4 : 3,
          metadata: {
            reputationEntryId: saved.id,
            ipAddress,
            banType: banStatus,
            bannedUntil: bannedUntil?.toISOString() ?? null,
            score: scoreAfter,
            failedChecks: failedAfter,
            signals: accepted.map((s) => s.type),
          } as Prisma.InputJsonObject,
        },
      })
    } else if (scoreAfter >= CRITICAL_SCORE && scoreBefore < CRITICAL_SCORE) {
      await tx.notification.create({
        data: {
          organizationId,
          type: 'CRITICAL_REPUTATION',
          title: 'سمعة حرجة لمصدر مشبوه',
          message: `سمعة ${ipAddress} وصلت ${scoreAfter}/10: ${reasonText}`,
          severity: 4,
          metadata: {
            reputationEntryId: saved.id,
            ipAddress,
            score: scoreAfter,
            signals: accepted.map((s) => s.type),
          } as Prisma.InputJsonObject,
        },
      })
    }

    // ---- 9) الرد ----
    const signals: AppliedSignalResult[] = [
      ...accepted.map((s) => ({
        type: s.type,
        points: round2(computeSignalPoints(s) * (computeSignalPoints(s) > 0 ? factor : 1)),
        deduped: false,
      })),
      ...dedupedTypes.map((type) => ({ type, points: 0, deduped: true })),
    ]

    return {
      result: {
        applied: true,
        entry: toPublic(saved),
        change: {
          scoreBefore,
          scoreAfter,
          pointsRaw,
          pointsApplied,
          decayApplied: decay?.scorePoints ?? 0,
          failedChecksBefore: existing?.failedChecksCount ?? 0,
          failedChecksAfter: failedAfter,
          banStatusBefore: banBefore?.banStatusEffective ?? 'NONE',
          banStatusAfter: banStatus,
          newlyBanned,
          banType: banStatus === 'NONE' ? null : banStatus,
          signals,
        },
      },
      marks,
    }
  }

  private buildEnrichment(input: ApplyReputationInput) {
    return {
      ...(input.deviceFingerprint && { deviceFingerprint: input.deviceFingerprint }),
      ...(input.ja3Fingerprint && { ja3Fingerprint: input.ja3Fingerprint }),
      ...(input.ja4Fingerprint && { ja4Fingerprint: input.ja4Fingerprint }),
      ...(input.countryCode && { countryCode: input.countryCode }),
      ...(input.asn !== undefined && { asn: input.asn }),
      ...(input.asOrg && { asOrg: input.asOrg }),
      ...(input.ipType && { ipType: input.ipType }),
      ...(input.lastPath && { lastPath: input.lastPath }),
      ...(input.lastUserAgent && { lastUserAgent: input.lastUserAgent }),
      ...(input.avgRequestRate !== undefined && {
        avgRequestRate: input.avgRequestRate,
      }),
    }
  }

  private async logChallenge(
    tx: Prisma.TransactionClient,
    input: ApplyReputationInput,
    reputationEntryId: string,
  ) {
    if (!input.challenge) return

    await tx.challengeLog.create({
      data: {
        challengeType: input.challenge.type,
        passed: input.challenge.passed,
        durationMs: input.challenge.durationMs ?? null,
        failureReason: input.challenge.passed
          ? null
          : (input.challenge.failureReason ?? null),
        reputationEntryId,
        serverId: input.serverId ?? null,
        organizationId: input.organizationId,
      },
    })
  }

  // ================================================================
  // Gateway: مزامنة الحظر (للـ Redis)
  // ================================================================

  /**
   * أول تشغيل (من غير updatedSince): الحظر الساري + الأجهزة الموثوقة فقط.
   * بعد كده (updatedSince): كل سجل اتغير حتى لو بقى NONE، عشان الـ Gateway يشيله.
   * شركات موقوفة ما بتتبعتش. serverTime بيتاخد قبل الاستعلام فمفيش تعديل بيضيع.
   *
   * تنبيه: انتهاء الحظر المؤقت بالوقت مش بيغيّر الصف، فالـ Gateway لازم يحط
   * TTL على المفتاح = bannedUntil.
   */
  async listBansForGateway(
    query: GatewayBansQuery,
  ): Promise<GatewayBansListResult> {
    const serverTime = new Date()

    const where: Prisma.ReputationEntryWhereInput = {
      organization: { isActive: true },
      ...(query.organizationId && { organizationId: query.organizationId }),
      ...(query.updatedSince
        ? { updatedAt: { gt: new Date(query.updatedSince) } }
        : {
            OR: [
              { banStatus: 'PERMANENT' },
              { banStatus: 'TEMPORARY', bannedUntil: { gt: serverTime } },
              { isAllowlisted: true },
            ],
          }),
    }

    const rows = await this.fastify.prisma.reputationEntry.findMany({
      where,
      orderBy: [{ updatedAt: 'asc' }, { id: 'asc' }],
      take: query.limit + 1,
      ...(query.cursor && { cursor: { id: query.cursor }, skip: 1 }),
    })

    const hasMore = rows.length > query.limit
    const page = hasMore ? rows.slice(0, query.limit) : rows

    const bans: GatewayBanItem[] = page.map((entry) => ({
      id: entry.id,
      organizationId: entry.organizationId,
      ipAddress: entry.ipAddress,
      deviceFingerprint: entry.deviceFingerprint,
      ja3Fingerprint: entry.ja3Fingerprint,
      ja4Fingerprint: entry.ja4Fingerprint,
      banStatus: entry.banStatus,
      bannedUntil: entry.bannedUntil?.toISOString() ?? null,
      isAllowlisted: entry.isAllowlisted,
      updatedAt: entry.updatedAt.toISOString(),
    }))

    return {
      bans,
      nextCursor: hasMore ? (page[page.length - 1]?.id ?? null) : null,
      serverTime: serverTime.toISOString(),
    }
  }
}