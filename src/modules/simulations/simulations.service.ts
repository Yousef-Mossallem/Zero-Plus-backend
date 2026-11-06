// ==================================================================
// Zero Plus - Simulations Service
// ------------------------------------------------------------------
// مسؤول عن:
//   - إنشاء / إيقاف / جلب / قائمة SimulationRun
//   - دمج الديفولتات (pattern → weights، ip pools، AI…)
//   - إصدار توكن المحاكاة (jti + exp) وربطه بالـ Run
//   - منع أكثر من Run نشط لنفس السيرفر (أو لنفس الشركة)
//   - تحديث العدادات من الـ Worker
//   - جلب أحداث مرتبطة بـ simulationRunId
//
// الـ Worker (simulations.worker.ts) هو من يبعت الترافيك للـ Gateway.
// هنا: DB + قواعد المنتج + عقد الفرونت.
// ==================================================================

import {
    Prisma,
    type SimulationRun,
    type SimulationStatus,
} from '@prisma/client'
import type { FastifyInstance } from 'fastify'

import {
    resolvePersonaWeights,
    type CreateSimulationInput,
    type ListSimulationsQuery,
    type SimulationEventsQuery,
    type SimulationIntensity,
    type SimulationOptions,
    type SimulationPattern,
} from './simulations.schema.js'
import {
    issueSimulationToken,
    revokeSimulationToken,
    type IssuedSimulationToken,
} from './simulations.token.js'

// ------------------------------------------------------------------
// أخطاء موحّدة للـ Routes
// ------------------------------------------------------------------

export class SimulationServiceError extends Error {
  public readonly statusCode: number
  public readonly code: string

  constructor(message: string, statusCode = 400, code = 'SIMULATION_ERROR') {
    super(message)
    this.name = 'SimulationServiceError'
    this.statusCode = statusCode
    this.code = code
  }
}

// ------------------------------------------------------------------
// ثوابت تشغيل
// ------------------------------------------------------------------

/** حجم برك الـ IP الافتراضي — كفاية اختبارات شبه حقيقية */
const DEFAULT_IP_POOL_LEGIT = 40
const DEFAULT_IP_POOL_ATTACK = 100

const TOKEN_TTL_SEC = 60 * 30 // 30 دقيقة أو مدة الـ Run إن أطول قليلًا
const ACTIVE_STATUSES: SimulationStatus[] = ['PENDING', 'RUNNING']

// ------------------------------------------------------------------
// دمج options النهائية المخزّنة في DB
// ------------------------------------------------------------------

function buildStoredOptions(
  pattern: SimulationPattern,
  input?: SimulationOptions,
): Record<string, unknown> {
  const weights = resolvePersonaWeights(pattern, input)
  return {
    personaWeights: weights,
    ipPoolLegit: input?.ipPoolLegit ?? DEFAULT_IP_POOL_LEGIT,
    ipPoolAttack: input?.ipPoolAttack ?? DEFAULT_IP_POOL_ATTACK,
    enableJaHeaders: input?.enableJaHeaders ?? true,
    aiMode: input?.aiMode ?? 'auto',
    aiFixedScore: input?.aiFixedScore ?? 0.35,
    paths:
      input?.paths && input.paths.length > 0
        ? input.paths
        : ['/', '/login', '/api/health', '/products', '/contact'],
    seed: input?.seed ?? null,
  }
}

function intensityFactor(intensity: SimulationIntensity): number {
  switch (intensity) {
    case 'LOW':
      return 0.6
    case 'HIGH':
      return 1.4
    default:
      return 1
  }
}

// ------------------------------------------------------------------
// شكل الرد للفرونت (ثابت — ما تكسروش الـ UI)
// ------------------------------------------------------------------

export function serializeSimulationRun(
  run: SimulationRun & {
    server?: { id: string; domain: string; status: string; mode: string }
    startedBy?: { id: string; fullName: string; email: string } | null
  },
) {
  return {
    id: run.id,
    status: run.status,
    pattern: run.pattern,
    intensity: run.intensity,
    serverId: run.serverId,
    serverDomain: run.server?.domain ?? null,
    serverStatus: run.server?.status ?? null,
    serverMode: run.server?.mode ?? null,
    organizationId: run.organizationId,
    durationSec: run.durationSec,
    targetRps: run.targetRps,
    maxRps: run.maxRps,
    totals: {
      sent: run.totalSent,
      allowed: run.totalAllowed,
      challenged: run.totalChallenged,
      rateLimited: run.totalRateLimited,
      blocked: run.totalBlocked,
      failed: run.totalFailed,
    },
    avgLatencyMs: run.avgLatencyMs,
    options: run.options ?? {},
    errorMessage: run.errorMessage,
    startedByUserId: run.startedByUserId,
    startedBy: run.startedBy
      ? {
          id: run.startedBy.id,
          fullName: run.startedBy.fullName,
          email: run.startedBy.email,
        }
      : null,
    tokenExpiresAt: run.tokenExpiresAt?.toISOString() ?? null,
    startedAt: run.startedAt.toISOString(),
    stoppedAt: run.stoppedAt?.toISOString() ?? null,
    createdAt: run.createdAt.toISOString(),
    updatedAt: run.updatedAt.toISOString(),
  }
}

// ------------------------------------------------------------------
// Service
// ------------------------------------------------------------------

export class SimulationsService {
  constructor(private readonly fastify: FastifyInstance) {}

  // ================================================================
  // START
  // ================================================================

  async start(
    organizationId: string,
    userId: string,
    input: CreateSimulationInput,
  ) {
    const server = await this.fastify.prisma.server.findFirst({
      where: { id: input.serverId, organizationId },
      select: {
        id: true,
        domain: true,
        status: true,
        mode: true,
        dnsVerified: true,
        organizationId: true,
      },
    })

    if (!server) {
      throw new SimulationServiceError('Server not found', 404, 'SERVER_NOT_FOUND')
    }

    if (!server.dnsVerified) {
      throw new SimulationServiceError(
        'Server domain is not verified',
        400,
        'SERVER_NOT_VERIFIED',
      )
    }

    if (server.status === 'MAINTENANCE') {
      throw new SimulationServiceError(
        'Server is under maintenance',
        400,
        'SERVER_MAINTENANCE',
      )
    }

    // منع تداخل: Run نشط على نفس السيرفر
    const existing = await this.fastify.prisma.simulationRun.findFirst({
      where: {
        organizationId,
        serverId: server.id,
        status: { in: ACTIVE_STATUSES },
      },
      select: { id: true, status: true },
    })

    if (existing) {
      throw new SimulationServiceError(
        `An active simulation already exists for this server (${existing.id})`,
        409,
        'SIMULATION_ALREADY_RUNNING',
      )
    }

    const pattern = input.pattern as SimulationPattern
    const intensity = input.intensity as SimulationIntensity
    const storedOptions = buildStoredOptions(pattern, input.options)

    // تطبيق شدة بسيطة على targetRps مع احترام maxRps
    const factor = intensityFactor(intensity)
    let targetRps = Math.max(
      1,
      Math.round(input.targetRps * factor),
    )
    const maxRps = input.maxRps
    if (targetRps > maxRps) targetRps = maxRps

    const durationSec = input.durationSec
    const tokenTtlSec = Math.max(TOKEN_TTL_SEC, durationSec + 120)
    const tokenExpiresAt = new Date(Date.now() + tokenTtlSec * 1000)

    const run = await this.fastify.prisma.simulationRun.create({
      data: {
        organizationId,
        serverId: server.id,
        startedByUserId: userId,
        pattern: pattern as never,
        intensity: intensity as never,
        status: 'PENDING',
        targetRps,
        maxRps,
        durationSec,
        options: storedOptions as Prisma.InputJsonValue,
        tokenExpiresAt,
      },
      include: {
        server: {
          select: { id: true, domain: true, status: true, mode: true },
        },
        startedBy: {
          select: { id: true, fullName: true, email: true },
        },
      },
    })

    // إصدار توكن مربوط بالـ Run
    let issued: IssuedSimulationToken
    try {
      issued = await issueSimulationToken({
        runId: run.id,
        organizationId,
        serverId: server.id,
        domain: server.domain,
        exp: tokenExpiresAt,
        maxRps,
      })
    } catch (err) {
      await this.fastify.prisma.simulationRun.update({
        where: { id: run.id },
        data: {
          status: 'FAILED',
          errorMessage: (err as Error).message,
          stoppedAt: new Date(),
        },
      })
      throw new SimulationServiceError(
        'Failed to issue simulation token',
        500,
        'TOKEN_ISSUE_FAILED',
      )
    }

    const updated = await this.fastify.prisma.simulationRun.update({
      where: { id: run.id },
      data: {
        tokenJti: issued.jti,
        status: 'RUNNING',
        startedAt: new Date(),
      },
      include: {
        server: {
          select: { id: true, domain: true, status: true, mode: true },
        },
        startedBy: {
          select: { id: true, fullName: true, email: true },
        },
      },
    })

    // تشغيل الـ Worker في الخلفية (لا ننتظر انتهاء المحاكاة)
    this.kickWorker({
      runId: updated.id,
      organizationId,
      serverId: server.id,
      domain: server.domain,
      tokenHeader: issued.headerValue,
      tokenExpiresAt,
      durationSec,
      targetRps,
      maxRps,
      options: storedOptions,
    }).catch(async (err) => {
      this.fastify.log.error({ err, runId: updated.id }, 'simulation worker failed')
      try {
        await this.markFailed(updated.id, organizationId, (err as Error).message)
      } catch {
        /* ignore */
      }
    })

    return {
      run: serializeSimulationRun(updated),
      // التوكن للتشخيص الداخلي فقط — الفرونت لا يحتاجه
      // (الـ Worker يستخدمه من الذاكرة/الممرّر أعلاه)
    }
  }

  // ================================================================
  // STOP
  // ================================================================

  async stop(organizationId: string, runId: string) {
    const run = await this.requireRun(organizationId, runId)

    if (!ACTIVE_STATUSES.includes(run.status)) {
      throw new SimulationServiceError(
        `Simulation is not active (status=${run.status})`,
        400,
        'SIMULATION_NOT_ACTIVE',
      )
    }

    if (run.tokenJti) {
      await revokeSimulationToken(run.tokenJti).catch(() => undefined)
    }

    const stopped = await this.fastify.prisma.simulationRun.update({
      where: { id: run.id },
      data: {
        status: 'STOPPED',
        stoppedAt: new Date(),
        tokenJti: null,
      },
      include: {
        server: {
          select: { id: true, domain: true, status: true, mode: true },
        },
        startedBy: {
          select: { id: true, fullName: true, email: true },
        },
      },
    })

    // إشارة للـ Worker إن كان بيتابع الحالة من DB — يكفي status=STOPPED

    return serializeSimulationRun(stopped)
  }

  // ================================================================
  // GET ONE
  // ================================================================

  async getById(organizationId: string, runId: string) {
    const run = await this.fastify.prisma.simulationRun.findFirst({
      where: { id: runId, organizationId },
      include: {
        server: {
          select: { id: true, domain: true, status: true, mode: true },
        },
        startedBy: {
          select: { id: true, fullName: true, email: true },
        },
      },
    })

    if (!run) {
      throw new SimulationServiceError('Simulation not found', 404, 'NOT_FOUND')
    }

    return serializeSimulationRun(run)
  }

  // ================================================================
  // LIST
  // ================================================================

  async list(organizationId: string, query: ListSimulationsQuery) {
    const page = query.page
    const limit = query.limit
    const where: Prisma.SimulationRunWhereInput = {
      organizationId,
      ...(query.status ? { status: query.status as SimulationStatus } : {}),
      ...(query.serverId ? { serverId: query.serverId } : {}),
      ...(query.pattern ? { pattern: query.pattern as never } : {}),
    }

    const [total, rows] = await Promise.all([
      this.fastify.prisma.simulationRun.count({ where }),
      this.fastify.prisma.simulationRun.findMany({
        where,
        orderBy: { startedAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
        include: {
          server: {
            select: { id: true, domain: true, status: true, mode: true },
          },
          startedBy: {
            select: { id: true, fullName: true, email: true },
          },
        },
      }),
    ])

    return {
      items: rows.map(serializeSimulationRun),
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.max(1, Math.ceil(total / limit)),
        hasNextPage: page * limit < total,
        hasPreviousPage: page > 1,
      },
    }
  }

  // ================================================================
  // EVENTS for a run
  // ================================================================

  async listEvents(
    organizationId: string,
    runId: string,
    query: SimulationEventsQuery,
  ) {
    await this.requireRun(organizationId, runId)

    const page = query.page
    const limit = query.limit
    const where: Prisma.SecurityEventWhereInput = {
      organizationId,
      simulationRunId: runId,
      ...(query.decision ? { decision: query.decision as never } : {}),
    }

    const [total, events] = await Promise.all([
      this.fastify.prisma.securityEvent.count({ where }),
      this.fastify.prisma.securityEvent.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
        select: {
          id: true,
          createdAt: true,
          ipAddress: true,
          path: true,
          method: true,
          decision: true,
          riskScore: true,
          decidedAtStage: true,
          processingTimeMs: true,
          reasonSummary: true,
          reasonDetails: true,
          isChallenged: true,
          challengeType: true,
          challengePassed: true,
          anomalyScore: true,
          ipType: true,
          userAgent: true,
          requestId: true,
        },
      }),
    ])

    return {
      events,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.max(1, Math.ceil(total / limit)),
        hasNextPage: page * limit < total,
        hasPreviousPage: page > 1,
      },
    }
  }

  // ================================================================
  // يستدعيها الـ Worker فقط
  // ================================================================

  async applyCounters(
    runId: string,
    organizationId: string,
    delta: {
      sent?: number
      allowed?: number
      challenged?: number
      rateLimited?: number
      blocked?: number
      failed?: number
      latencyMsSample?: number
    },
  ) {
    const run = await this.fastify.prisma.simulationRun.findFirst({
      where: { id: runId, organizationId },
      select: {
        id: true,
        status: true,
        totalSent: true,
        avgLatencyMs: true,
      },
    })
    if (!run) return
    if (run.status !== 'RUNNING' && run.status !== 'PENDING') return

    let avgLatencyMs: number | undefined
    if (
      typeof delta.latencyMsSample === 'number' &&
      Number.isFinite(delta.latencyMsSample)
    ) {
      const prevCount = run.totalSent
      const sample = Math.max(0, Math.round(delta.latencyMsSample))
      if (run.avgLatencyMs == null || prevCount <= 0) {
        avgLatencyMs = sample
      } else {
        avgLatencyMs = Math.round(
          (run.avgLatencyMs * prevCount + sample) / (prevCount + 1),
        )
      }
    }

    await this.fastify.prisma.simulationRun.update({
      where: { id: runId },
      data: {
        ...(delta.sent ? { totalSent: { increment: delta.sent } } : {}),
        ...(delta.allowed ? { totalAllowed: { increment: delta.allowed } } : {}),
        ...(delta.challenged
          ? { totalChallenged: { increment: delta.challenged } }
          : {}),
        ...(delta.rateLimited
          ? { totalRateLimited: { increment: delta.rateLimited } }
          : {}),
        ...(delta.blocked ? { totalBlocked: { increment: delta.blocked } } : {}),
        ...(delta.failed ? { totalFailed: { increment: delta.failed } } : {}),
        ...(avgLatencyMs !== undefined ? { avgLatencyMs } : {}),
      },
    })
  }

  async markCompleted(runId: string, organizationId: string) {
    const run = await this.fastify.prisma.simulationRun.findFirst({
      where: { id: runId, organizationId },
    })
    if (!run) return
    if (run.status === 'STOPPED' || run.status === 'COMPLETED') return

    if (run.tokenJti) {
      await revokeSimulationToken(run.tokenJti).catch(() => undefined)
    }

    await this.fastify.prisma.simulationRun.update({
      where: { id: runId },
      data: {
        status: 'COMPLETED',
        stoppedAt: new Date(),
        tokenJti: null,
      },
    })
  }

  async markFailed(runId: string, organizationId: string, message: string) {
    const run = await this.fastify.prisma.simulationRun.findFirst({
      where: { id: runId, organizationId },
    })
    if (!run) return

    if (run.tokenJti) {
      await revokeSimulationToken(run.tokenJti).catch(() => undefined)
    }

    await this.fastify.prisma.simulationRun.update({
      where: { id: runId },
      data: {
        status: 'FAILED',
        errorMessage: message.slice(0, 2000),
        stoppedAt: new Date(),
        tokenJti: null,
      },
    })
  }

  /**
   * هل الـ Worker لسه لازم يكمّل؟
   */
  async isRunActive(runId: string, organizationId: string): Promise<boolean> {
    const run = await this.fastify.prisma.simulationRun.findFirst({
      where: { id: runId, organizationId },
      select: { status: true },
    })
    return !!run && ACTIVE_STATUSES.includes(run.status)
  }

  // ================================================================
  // Helpers
  // ================================================================

  private async requireRun(organizationId: string, runId: string) {
    const run = await this.fastify.prisma.simulationRun.findFirst({
      where: { id: runId, organizationId },
    })
    if (!run) {
      throw new SimulationServiceError('Simulation not found', 404, 'NOT_FOUND')
    }
    return run
  }

  /**
   * استدعاء ديناميكي لتجنّب اعتماد دائري وقت التحميل.
   * الـ Worker يقرأ options.ipPoolAttack (افتراضي 100) ويبني بركة IPs.
   */
  private async kickWorker(payload: {
    runId: string
    organizationId: string
    serverId: string
    domain: string
    tokenHeader: string
    tokenExpiresAt: Date
    durationSec: number
    targetRps: number
    maxRps: number
    options: Record<string, unknown>
  }) {
    const mod = await import('./simulations.worker.js')
    if (typeof mod.startSimulationWorker === 'function') {
      await mod.startSimulationWorker(this.fastify, payload)
      return
    }
    // لو الـ Worker لسه مش جاهز — الـ Run يفضل RUNNING والفرونت يشتغل على العقد
    this.fastify.log.warn(
      { runId: payload.runId },
      'startSimulationWorker not found — run left RUNNING without traffic',
    )
  }
}

export default SimulationsService