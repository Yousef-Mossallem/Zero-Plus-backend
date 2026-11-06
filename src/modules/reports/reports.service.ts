// backend/src/modules/reports/reports.service.ts
// ==================================================================
// Zero Plus - Reports Service
// ------------------------------------------------------------------
// مسؤول عن:
//   - إنشاء تقارير أمنية (PENDING → GENERATING → READY | FAILED)
//   - جمع بيانات مُصفّاة من DB وإرسالها لـ Gemini
//   - قائمة / تفاصيل / حذف التقارير
//   - Chat مع سياق إحصائي اختياري للشركة
//   - إشعار REPORT_READY + بث Socket
//
// قواعد التصفية (قبل Gemini):
//   - BLOCK + CHALLENGE: كلها
//   - RATE_LIMIT: كل 5 أحداث واحد
//   - ALLOW: فقط surgeDetected = true
//   - Reputation: score >= 5 أو banStatus != NONE
//   - ChallengeLog: failed فقط (passed = false)
//   - SimulationRun: كاملة
//   - serverName (domain) بدل serverId — بدون originIp / أسرار
// ==================================================================

import {
  Prisma,
  type Report,
  type ReportStatus,
  type ReportType,
  type Decision,
} from '@prisma/client'
import type { FastifyInstance } from 'fastify'

import { SocketEvents } from '../../plugins/socket.plugin.js'
import { NotificationsService } from '../notifications/notifications.service.js'
import {
  chat as geminiChat,
  generateReport as geminiGenerateReport,
  GeminiClientError,
} from './gemini.client.js'
import type {
  ChatInput,
  CollectedReportData,
  CreateReportInput,
  ListReportsQuery,
  ReportChallengeForAi,
  ReportEventForAi,
  ReportReputationForAi,
  ReportServerSummaryForAi,
  ReportSimulationForAi,
} from './reports.schema.js'

// ==================================================================
// Config
// ==================================================================

function envInt(name: string, fallback: number): number {
  const value = Number(process.env[name])
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback
}

const REPORT_MAX_EVENTS = envInt('REPORT_MAX_EVENTS', 3000)
const REPORT_MAX_REPUTATIONS = envInt('REPORT_MAX_REPUTATIONS', 500)
const REPORT_MAX_CHALLENGES = envInt('REPORT_MAX_CHALLENGES', 500)
const REPORT_MAX_SIMULATIONS = envInt('REPORT_MAX_SIMULATIONS', 50)

// ==================================================================
// Errors
// ==================================================================

export class ReportServiceError extends Error {
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
    this.name = 'ReportServiceError'
    this.statusCode = statusCode
    this.code = code
    this.details = details
  }
}

const reportNotFound = () =>
  new ReportServiceError('التقرير غير موجود', 404, 'REPORT_NOT_FOUND')

// ==================================================================
// Types
// ==================================================================

export interface ListReportsResult {
  reports: Report[]
  pagination: {
    total: number
    page: number
    limit: number
    totalPages: number
    hasNextPage: boolean
    hasPreviousPage: boolean
  }
  summary: Partial<Record<ReportStatus, number>>
}

export interface ChatResult {
  reply: string
  model: string
  tokensUsed: number | null
}

export interface ReportRealtimePayload {
  id: string
  organizationId: string
  title: string
  type: ReportType
  status: ReportStatus
  serverId: string | null
  errorMessage: string | null
  action: 'created' | 'status_changed' | 'deleted'
  updatedAt: string
}

// ==================================================================
// Helpers
// ==================================================================

function isPrismaError(
  error: unknown,
  code: string,
): error is Prisma.PrismaClientKnownRequestError {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError && error.code === code
  )
}

function defaultTitle(
  type: ReportType,
  periodStart: Date,
  periodEnd: Date,
  domain?: string | null,
): string {
  const fmt = (d: Date) => d.toISOString().slice(0, 10)
  const range = `${fmt(periodStart)} → ${fmt(periodEnd)}`
  const scope = domain ? ` — ${domain}` : ''
  switch (type) {
    case 'PERIODIC':
      return `تقرير دوري${scope} (${range})`
    case 'INCIDENT':
      return `تقرير حادثة${scope} (${range})`
    default:
      return `تقرير حسب الطلب${scope} (${range})`
  }
}

/** إخفاء خفيف لآخر octet — مفيد لو هيتصدر خارجيًا لاحقًا */
function maskIp(ip: string): string {
  if (ip.includes(':')) {
    // IPv6 مبسّط
    const parts = ip.split(':')
    if (parts.length > 2) return parts.slice(0, 3).join(':') + ':*'
    return ip
  }
  const m = ip.match(/^(\d+\.\d+\.\d+)\.\d+$/)
  return m ? `${m[1]}.x` : ip
}

// ==================================================================
// Service
// ==================================================================

export class ReportsService {
  constructor(private readonly fastify: FastifyInstance) {}

  private notifications() {
    return new NotificationsService(this.fastify)
  }

  private emitReportStatus(payload: ReportRealtimePayload) {
    try {
      if (typeof this.fastify.broadcastToOrg === 'function') {
        this.fastify.broadcastToOrg(
          payload.organizationId,
          // لو SocketEvents.REPORT_STATUS مش معرّف عندك، استخدم نفس اسم السيرفرات أو أضفه
          (SocketEvents as { REPORT_STATUS?: string }).REPORT_STATUS ??
            'report:status',
          payload,
        )
      }
    } catch (err) {
      this.fastify.log.warn({ err, reportId: payload.id }, 'broadcast report failed')
    }
  }

  // ================================================================
  // createReport — يرجع فورًا + توليد بالخلفية
  // ================================================================

  async createReport(
    organizationId: string,
    input: CreateReportInput,
  ): Promise<Report> {
    const prisma = this.fastify.prisma

    // التحقق من السيرفر لو محدد
    let domain: string | null = null
    if (input.serverId) {
      const server = await prisma.server.findFirst({
        where: { id: input.serverId, organizationId },
        select: { id: true, domain: true },
      })
      if (!server) {
        throw new ReportServiceError(
          'السيرفر غير موجود ضمن حسابك',
          404,
          'SERVER_NOT_FOUND',
        )
      }
      domain = server.domain
    }

    if (input.securityEventId) {
      const ev = await prisma.securityEvent.findFirst({
        where: { id: input.securityEventId, organizationId },
        select: { id: true },
      })
      if (!ev) {
        throw new ReportServiceError(
          'الحدث الأمني غير موجود',
          404,
          'SECURITY_EVENT_NOT_FOUND',
        )
      }
    }

    const title =
      input.title?.trim() ||
      defaultTitle(input.type, input.periodStart, input.periodEnd, domain)

    const report = await prisma.report.create({
      data: {
        organizationId,
        title,
        type: input.type,
        status: 'PENDING',
        periodStart: input.periodStart,
        periodEnd: input.periodEnd,
        serverId: input.serverId ?? null,
        securityEventId: input.securityEventId ?? null,
      },
    })

    this.emitReportStatus({
      id: report.id,
      organizationId,
      title: report.title,
      type: report.type,
      status: report.status,
      serverId: report.serverId,
      errorMessage: null,
      action: 'created',
      updatedAt: report.updatedAt.toISOString(),
    })

    // خلفية — مش بنستنى
    void this.generateAsync(report.id, organizationId, input).catch((err) => {
      this.fastify.log.error(
        { err, reportId: report.id },
        'generateAsync unhandled',
      )
    })

    return report
  }

  // ================================================================
  // generateAsync
  // ================================================================

  private async generateAsync(
    reportId: string,
    organizationId: string,
    input: CreateReportInput,
  ): Promise<void> {
    const prisma = this.fastify.prisma

    try {
      await prisma.report.update({
        where: { id: reportId },
        data: { status: 'GENERATING', errorMessage: null },
      })

      this.emitReportStatus({
        id: reportId,
        organizationId,
        title: input.title || reportId,
        type: input.type,
        status: 'GENERATING',
        serverId: input.serverId ?? null,
        errorMessage: null,
        action: 'status_changed',
        updatedAt: new Date().toISOString(),
      })

      const data = await this.collectReportData(
        organizationId,
        input.serverId,
        input.periodStart,
        input.periodEnd,
      )

      const ai = await geminiGenerateReport(input.title, data)

      const blockedCount = data.stats.blockedCount

      const updated = await prisma.report.update({
        where: { id: reportId },
        data: {
          status: 'READY',
          content: ai.text,
          summary: ai.summary,
          tokensUsed: ai.tokensUsed,
          modelUsed: ai.model,
          eventCount: data.stats.totalEventsSampled,
          blockedCount,
          errorMessage: null,
          metadata: {
            stats: data.stats,
            promptTokens: ai.promptTokens,
            candidatesTokens: ai.candidatesTokens,
            finishReason: ai.finishReason,
          } as Prisma.InputJsonValue,
        },
      })

      await this.notifications().create({
        organizationId,
        type: 'SYSTEM',
        title: 'التقرير جاهز',
        message: `التقرير «${updated.title}» أصبح جاهزًا للعرض.`,
        severity: 1,
        metadata: { reportId, type: updated.type },
      })

      this.emitReportStatus({
        id: updated.id,
        organizationId,
        title: updated.title,
        type: updated.type,
        status: 'READY',
        serverId: updated.serverId,
        errorMessage: null,
        action: 'status_changed',
        updatedAt: updated.updatedAt.toISOString(),
      })
    } catch (err) {
      const message =
        err instanceof GeminiClientError
          ? err.message
          : err instanceof Error
            ? err.message
            : 'فشل توليد التقرير'

      this.fastify.log.error({ err, reportId }, 'report generation failed')

      try {
        const failed = await prisma.report.update({
          where: { id: reportId },
          data: {
            status: 'FAILED',
            errorMessage: message.slice(0, 1000),
          },
        })

        this.emitReportStatus({
          id: failed.id,
          organizationId,
          title: failed.title,
          type: failed.type,
          status: 'FAILED',
          serverId: failed.serverId,
          errorMessage: failed.errorMessage,
          action: 'status_changed',
          updatedAt: failed.updatedAt.toISOString(),
        })
      } catch (updateErr) {
        this.fastify.log.error(
          { updateErr, reportId },
          'failed to mark report FAILED',
        )
      }
    }
  }

  // ================================================================
  // collectReportData — تصفية ذكية
  // ================================================================

  async collectReportData(
    organizationId: string,
    serverId: string | null | undefined,
    periodStart: Date,
    periodEnd: Date,
  ): Promise<CollectedReportData> {
    const prisma = this.fastify.prisma

    const org = await prisma.organization.findUnique({
      where: { id: organizationId },
      select: { name: true },
    })

    const serverWhere: Prisma.ServerWhereInput = {
      organizationId,
      ...(serverId ? { id: serverId } : {}),
    }

    const servers = await prisma.server.findMany({
      where: serverWhere,
      select: {
        id: true,
        domain: true,
        status: true,
        mode: true,
        dnsVerified: true,
        originReachable: true,
        gatewayReachable: true,
        maxRequestsPerSecond: true,
        safeRequestsPerSecond: true,
        probeRecommendation: true,
      },
    })

    const serverMap = Object.fromEntries(servers.map((s) => [s.id, s.domain]))
    const serverIds = servers.map((s) => s.id)

    const eventBase: Prisma.SecurityEventWhereInput = {
      organizationId,
      createdAt: { gte: periodStart, lte: periodEnd },
      ...(serverId
        ? { serverId }
        : serverIds.length
          ? { serverId: { in: serverIds } }
          : { serverId: { in: [] } }),
    }

    // --- أحداث: BLOCK + CHALLENGE كامل ---
    const criticalEvents = await prisma.securityEvent.findMany({
      where: {
        ...eventBase,
        decision: { in: ['BLOCK', 'CHALLENGE'] satisfies Decision[] },
      },
      orderBy: { createdAt: 'desc' },
      take: REPORT_MAX_EVENTS,
      select: {
        decision: true,
        riskScore: true,
        path: true,
        method: true,
        countryCode: true,
        ipType: true,
        decidedAtStage: true,
        surgeDetected: true,
        pathSensitive: true,
        isChallenged: true,
        challengeType: true,
        challengePassed: true,
        reasonSummary: true,
        serverId: true,
        ipAddress: true,
        createdAt: true,
      },
    })

    // --- RATE_LIMIT: نجيب دفعة ونأخذ كل 5 ---
    const rateLimitRaw = await prisma.securityEvent.findMany({
      where: { ...eventBase, decision: 'RATE_LIMIT' },
      orderBy: { createdAt: 'desc' },
      take: Math.min(REPORT_MAX_EVENTS, 5000),
      select: {
        decision: true,
        riskScore: true,
        path: true,
        method: true,
        countryCode: true,
        ipType: true,
        decidedAtStage: true,
        surgeDetected: true,
        pathSensitive: true,
        isChallenged: true,
        challengeType: true,
        challengePassed: true,
        reasonSummary: true,
        serverId: true,
        ipAddress: true,
        createdAt: true,
      },
    })
    const rateLimitSampled = rateLimitRaw.filter((_, i) => i % 5 === 0)

    // --- ALLOW + surge فقط ---
    const allowSurge = await prisma.securityEvent.findMany({
      where: {
        ...eventBase,
        decision: 'ALLOW',
        surgeDetected: true,
      },
      orderBy: { createdAt: 'desc' },
      take: Math.min(1000, REPORT_MAX_EVENTS),
      select: {
        decision: true,
        riskScore: true,
        path: true,
        method: true,
        countryCode: true,
        ipType: true,
        decidedAtStage: true,
        surgeDetected: true,
        pathSensitive: true,
        isChallenged: true,
        challengeType: true,
        challengePassed: true,
        reasonSummary: true,
        serverId: true,
        ipAddress: true,
        createdAt: true,
      },
    })

    const mapEvent = (
      e: (typeof criticalEvents)[number],
    ): ReportEventForAi => ({
      decision: e.decision,
      riskScore: e.riskScore,
      path: e.path,
      method: e.method,
      countryCode: e.countryCode,
      ipType: e.ipType,
      decidedAtStage: e.decidedAtStage,
      surgeDetected: e.surgeDetected,
      pathSensitive: e.pathSensitive,
      isChallenged: e.isChallenged,
      challengeType: e.challengeType,
      challengePassed: e.challengePassed,
      reasonSummary: e.reasonSummary,
      serverName: serverMap[e.serverId] ?? 'سيرفر محذوف',
      ipAddress: maskIp(e.ipAddress),
      createdAt: e.createdAt.toISOString(),
    })

    let events: ReportEventForAi[] = [
      ...criticalEvents.map(mapEvent),
      ...rateLimitSampled.map(mapEvent),
      ...allowSurge.map(mapEvent),
    ]

    if (events.length > REPORT_MAX_EVENTS) {
      events = events.slice(0, REPORT_MAX_EVENTS)
    }

    // --- سمعة ---
    const reputationsRaw = await prisma.reputationEntry.findMany({
      where: {
        organizationId,
        OR: [{ score: { gte: 5 } }, { banStatus: { not: 'NONE' } }],
      },
      orderBy: [{ score: 'desc' }, { lastSeenAt: 'desc' }],
      take: REPORT_MAX_REPUTATIONS,
      select: {
        ipAddress: true,
        score: true,
        banStatus: true,
        bannedUntil: true,
        failedChecksCount: true,
        jsFailCount: true,
        advancedFailCount: true,
        isKnownBotnet: true,
        ipType: true,
        countryCode: true,
        totalRequests: true,
      },
    })

    const reputations: ReportReputationForAi[] = reputationsRaw.map((r) => ({
      ipAddress: maskIp(r.ipAddress),
      score: r.score,
      banStatus: r.banStatus,
      bannedUntil: r.bannedUntil?.toISOString() ?? null,
      failedChecksCount: r.failedChecksCount,
      jsFailCount: r.jsFailCount,
      advancedFailCount: r.advancedFailCount,
      isKnownBotnet: r.isKnownBotnet,
      ipType: r.ipType,
      countryCode: r.countryCode,
      totalRequests: r.totalRequests,
    }))

    // --- تحديات فاشلة ---
    const challengesRaw = await prisma.challengeLog.findMany({
      where: {
        organizationId,
        passed: false,
        createdAt: { gte: periodStart, lte: periodEnd },
        ...(serverId ? { serverId } : {}),
      },
      orderBy: { createdAt: 'desc' },
      take: REPORT_MAX_CHALLENGES,
      select: {
        challengeType: true,
        passed: true,
        durationMs: true,
        failureReason: true,
        serverId: true,
        createdAt: true,
      },
    })

    const challenges: ReportChallengeForAi[] = challengesRaw.map((c) => ({
      challengeType: c.challengeType,
      passed: c.passed,
      durationMs: c.durationMs,
      failureReason: c.failureReason,
      serverName: c.serverId
        ? (serverMap[c.serverId] ?? 'سيرفر محذوف')
        : null,
      createdAt: c.createdAt.toISOString(),
    }))

    // --- محاكاة ---
    const simulationsRaw = await prisma.simulationRun.findMany({
      where: {
        organizationId,
        startedAt: { gte: periodStart, lte: periodEnd },
        ...(serverId ? { serverId } : {}),
      },
      orderBy: { startedAt: 'desc' },
      take: REPORT_MAX_SIMULATIONS,
      select: {
        pattern: true,
        status: true,
        targetRps: true,
        totalSent: true,
        totalAllowed: true,
        totalRateLimited: true,
        totalChallenged: true,
        totalBlocked: true,
        serverId: true,
        startedAt: true,
        stoppedAt: true,
      },
    })

    const simulations: ReportSimulationForAi[] = simulationsRaw.map((s) => ({
      pattern: s.pattern,
      status: s.status,
      targetRps: s.targetRps,
      totalSent: s.totalSent,
      totalAllowed: s.totalAllowed,
      totalRateLimited: s.totalRateLimited,
      totalChallenged: s.totalChallenged,
      totalBlocked: s.totalBlocked,
      serverName: serverMap[s.serverId] ?? 'سيرفر محذوف',
      startedAt: s.startedAt.toISOString(),
      stoppedAt: s.stoppedAt?.toISOString() ?? null,
    }))

    const serversForAi: ReportServerSummaryForAi[] = servers.map((s) => ({
      domain: s.domain,
      status: s.status,
      mode: s.mode,
      dnsVerified: s.dnsVerified,
      originReachable: s.originReachable,
      gatewayReachable: s.gatewayReachable,
      maxRequestsPerSecond: s.maxRequestsPerSecond,
      safeRequestsPerSecond: s.safeRequestsPerSecond,
      probeRecommendation: s.probeRecommendation,
    }))

    const blockedCount = criticalEvents.filter((e) => e.decision === 'BLOCK')
      .length
    const challengedCount = criticalEvents.filter(
      (e) => e.decision === 'CHALLENGE',
    ).length

    return {
      periodStart: periodStart.toISOString(),
      periodEnd: periodEnd.toISOString(),
      organizationName: org?.name ?? 'Organization',
      servers: serversForAi,
      events,
      reputations,
      challenges,
      simulations,
      stats: {
        totalEventsSampled: events.length,
        blockedCount,
        challengedCount,
        rateLimitedSampled: rateLimitSampled.length,
        allowSurgeCount: allowSurge.length,
        highRiskReputations: reputations.length,
        failedChallenges: challenges.length,
      },
    }
  }

  // ================================================================
  // getReports
  // ================================================================

  async getReports(
    organizationId: string,
    query: ListReportsQuery,
  ): Promise<ListReportsResult> {
    const prisma = this.fastify.prisma
    const where: Prisma.ReportWhereInput = { organizationId }

    if (query.status) where.status = query.status
    if (query.type) where.type = query.type
    if (query.serverId) where.serverId = query.serverId

    if (query.startDate || query.endDate) {
      where.createdAt = {
        ...(query.startDate && { gte: query.startDate }),
        ...(query.endDate && { lte: query.endDate }),
      }
    }

    const skip = (query.page - 1) * query.limit

    const [reports, total, grouped] = await Promise.all([
      prisma.report.findMany({
        where,
        skip,
        take: query.limit,
        orderBy: {
          [query.sortBy]: query.sortOrder,
        } as Prisma.ReportOrderByWithRelationInput,
        // القائمة: من غير content الثقيل
        select: {
          id: true,
          title: true,
          type: true,
          status: true,
          periodStart: true,
          periodEnd: true,
          summary: true,
          errorMessage: true,
          eventCount: true,
          blockedCount: true,
          tokensUsed: true,
          modelUsed: true,
          serverId: true,
          securityEventId: true,
          organizationId: true,
          createdAt: true,
          updatedAt: true,
          content: false,
          metadata: false,
        },
      }),
      prisma.report.count({ where }),
      prisma.report.groupBy({
        by: ['status'],
        where: { organizationId },
        _count: { _all: true },
      }),
    ])

    const summary: Partial<Record<ReportStatus, number>> = {}
    for (const row of grouped) {
      summary[row.status] = row._count._all
    }

    const totalPages = Math.ceil(total / query.limit) || 1

    // findMany مع select بيرجع نوع ضيق — نرجّع كـ Report[] للواجهة
    return {
      reports: reports as unknown as Report[],
      pagination: {
        total,
        page: query.page,
        limit: query.limit,
        totalPages,
        hasNextPage: query.page < totalPages,
        hasPreviousPage: query.page > 1,
      },
      summary,
    }
  }

  // ================================================================
  // getReportById
  // ================================================================

  async getReportById(
    organizationId: string,
    reportId: string,
  ): Promise<Report> {
    const report = await this.fastify.prisma.report.findFirst({
      where: { id: reportId, organizationId },
    })
    if (!report) throw reportNotFound()
    return report
  }

  // ================================================================
  // deleteReport
  // ================================================================

  async deleteReport(
    organizationId: string,
    reportId: string,
  ): Promise<{ id: string }> {
    const existing = await this.fastify.prisma.report.findFirst({
      where: { id: reportId, organizationId },
      select: {
        id: true,
        title: true,
        type: true,
        status: true,
        serverId: true,
      },
    })
    if (!existing) throw reportNotFound()

    try {
      await this.fastify.prisma.report.delete({ where: { id: reportId } })
    } catch (error) {
      if (isPrismaError(error, 'P2025')) throw reportNotFound()
      throw error
    }

    this.emitReportStatus({
      id: existing.id,
      organizationId,
      title: existing.title,
      type: existing.type,
      status: existing.status,
      serverId: existing.serverId,
      errorMessage: null,
      action: 'deleted',
      updatedAt: new Date().toISOString(),
    })

    return { id: reportId }
  }

  // ================================================================
  // chat
  // ================================================================

  async chat(
    organizationId: string,
    input: ChatInput,
  ): Promise<ChatResult> {
    let systemContext: string | undefined

    if (input.includeContext) {
      systemContext = await this.buildChatContext(
        organizationId,
        input.serverId,
      )
    }

    const history = input.messages.map((m) => ({
      role: m.role,
      content: m.content,
    }))

    history.push({ role: 'user' as const, content: input.message })

    try {
      const result = await geminiChat(history, systemContext)
      return {
        reply: result.text,
        model: result.model,
        tokensUsed: result.tokensUsed,
      }
    } catch (err) {
      if (err instanceof GeminiClientError) {
        throw new ReportServiceError(
          err.message,
          err.statusCode >= 400 && err.statusCode < 600 ? err.statusCode : 502,
          err.code,
          err.details,
        )
      }
      throw err
    }
  }

  /**
   * إحصائيات سريعة للـ chat — بدون أسرار أو originIp
   */
  private async buildChatContext(
    organizationId: string,
    serverId?: string | null,
  ): Promise<string> {
    const prisma = this.fastify.prisma
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)

    const eventWhere: Prisma.SecurityEventWhereInput = {
      organizationId,
      createdAt: { gte: since },
      ...(serverId ? { serverId } : {}),
    }

    const [
      org,
      serversCount,
      eventsLast7d,
      blockedLast7d,
      bannedIps,
      servers,
    ] = await Promise.all([
      prisma.organization.findUnique({
        where: { id: organizationId },
        select: { name: true, plan: true },
      }),
      prisma.server.count({
        where: {
          organizationId,
          ...(serverId ? { id: serverId } : {}),
        },
      }),
      prisma.securityEvent.count({ where: eventWhere }),
      prisma.securityEvent.count({
        where: { ...eventWhere, decision: 'BLOCK' },
      }),
      prisma.reputationEntry.count({
        where: {
          organizationId,
          banStatus: { not: 'NONE' },
        },
      }),
      prisma.server.findMany({
        where: {
          organizationId,
          ...(serverId ? { id: serverId } : {}),
        },
        select: {
          domain: true,
          status: true,
          mode: true,
          safeRequestsPerSecond: true,
          probeRecommendation: true,
        },
        take: 25,
      }),
    ])

    const payload = {
      organization: org?.name ?? 'unknown',
      plan: org?.plan ?? 'unknown',
      window: 'last_7_days',
      serversCount,
      eventsLast7d,
      blockedLast7d,
      bannedIps,
      servers: servers.map((s) => ({
        domain: s.domain,
        status: s.status,
        mode: s.mode,
        safeRps: s.safeRequestsPerSecond,
        probe: s.probeRecommendation,
      })),
    }

    return JSON.stringify(payload)
  }
}

export default ReportsService