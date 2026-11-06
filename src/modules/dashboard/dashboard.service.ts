// backend/src/modules/dashboard/dashboard.service.ts
// ==================================================================
// Zero Plus - Dashboard Service
// ------------------------------------------------------------------
// قراءة فقط — تجميع إحصائيات الشركة للداشبورد
// كل الاستعلامات الثقيلة تشتغل بالتوازي (Promise.all)
//
// getOverview        → أرقام الصفحة الرئيسية
// getTimeline        → نقاط الرسم البياني (date_trunc)
// getTop             → أعلى ip/path/country/asn/ipType/stage
// getServersSummary  → ملخص كل السيرفرات + أحداث آخر ساعة
// getThreatMap       → توزيع الدول + threatLevel
// ==================================================================

import { Prisma, type Decision, type ServerStatus } from '@prisma/client'
import type { FastifyInstance } from 'fastify'

import {
  computeThreatLevel,
  periodFromRange,
  RANGE_CONFIG,
  type DashboardRange,
  type OverviewResult,
  type ServerSummaryItem,
  type ServersSummaryResult,
  type TimelinePoint,
  type TimelineResult,
  type TopBy,
  type TopItem,
  type TopResult,
  type ThreatMapCountry,
  type ThreatMapResult,
} from './dashboard.schema.js'

// ==================================================================
// Errors
// ==================================================================

export class DashboardServiceError extends Error {
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
    this.name = 'DashboardServiceError'
    this.statusCode = statusCode
    this.code = code
    this.details = details
  }
}

// ==================================================================
// Helpers
// ==================================================================

function emptyServerStatus(): Record<ServerStatus, number> {
  return {
    ONLINE: 0,
    DEGRADED: 0,
    OFFLINE: 0,
    PENDING: 0,
    MAINTENANCE: 0,
  }
}

function decisionCountsFromRows(
  rows: Array<{ decision: Decision; _count: { _all: number } }>,
) {
  const base = {
    ALLOW: 0,
    MONITOR: 0,
    RATE_LIMIT: 0,
    CHALLENGE: 0,
    BLOCK: 0,
  }
  for (const row of rows) {
    base[row.decision] = row._count._all
  }
  return base
}

function eventWhere(
  organizationId: string,
  periodStart: Date,
  periodEnd: Date,
  serverId?: string,
): Prisma.SecurityEventWhereInput {
  return {
    organizationId,
    createdAt: { gte: periodStart, lte: periodEnd },
    ...(serverId ? { serverId } : {}),
  }
}

/** تقريب رقم عشري */
function round1(n: number): number {
  return Math.round(n * 10) / 10
}

// ==================================================================
// Service
// ==================================================================

export class DashboardService {
  constructor(private readonly fastify: FastifyInstance) {}

  private get prisma() {
    return this.fastify.prisma
  }

  /**
   * يتأكد إن السيرفر تابع لنفس المنظمة (لو اتبعت serverId)
   */
  private async assertServerOwned(
    organizationId: string,
    serverId: string | undefined,
  ): Promise<void> {
    if (!serverId) return
    const s = await this.prisma.server.findFirst({
      where: { id: serverId, organizationId },
      select: { id: true },
    })
    if (!s) {
      throw new DashboardServiceError(
        'السيرفر غير موجود ضمن حسابك',
        404,
        'SERVER_NOT_FOUND',
      )
    }
  }

  // ================================================================
  // GET /dashboard/overview
  // ================================================================

  async getOverview(
    organizationId: string,
    range: DashboardRange,
    serverId?: string,
  ): Promise<OverviewResult> {
    await this.assertServerOwned(organizationId, serverId)

    const { periodStart, periodEnd, config } = periodFromRange(range)
    const where = eventWhere(organizationId, periodStart, periodEnd, serverId)

    const [
      total,
      byDecision,
      avgRisk,
      surgeCount,
      challengedTotal,
      challengePassed,
      challengeFailed,
      serversGrouped,
      activeBans,
      permanentBans,
      policy,
      criticalEntries,
      newBansInRange,
      unreadNotifications,
    ] = await Promise.all([
      this.prisma.securityEvent.count({ where }),

      this.prisma.securityEvent.groupBy({
        by: ['decision'],
        where,
        _count: { _all: true },
      }),

      this.prisma.securityEvent.aggregate({
        where,
        _avg: { riskScore: true },
      }),

      this.prisma.securityEvent.count({
        where: { ...where, surgeDetected: true },
      }),

      this.prisma.securityEvent.count({
        where: { ...where, isChallenged: true },
      }),

      this.prisma.securityEvent.count({
        where: { ...where, isChallenged: true, challengePassed: true },
      }),

      this.prisma.securityEvent.count({
        where: { ...where, isChallenged: true, challengePassed: false },
      }),

      this.prisma.server.groupBy({
        by: ['status'],
        where: { organizationId },
        _count: { _all: true },
      }),

      this.prisma.reputationEntry.count({
        where: {
          organizationId,
          banStatus: 'TEMPORARY',
          OR: [{ bannedUntil: null }, { bannedUntil: { gt: new Date() } }],
        },
      }),

      this.prisma.reputationEntry.count({
        where: { organizationId, banStatus: 'PERMANENT' },
      }),

      this.prisma.policy.findUnique({
        where: { organizationId },
        select: { permanentBanScore: true },
      }),

      // criticalEntries — بعد ما نعرف العتبة؛ مؤقتًا score >= 9 كافتراضي
      // هنحسبها تحت بعد policy
      Promise.resolve(0),

      this.prisma.reputationEntry.count({
        where: {
          organizationId,
          bannedAt: { gte: periodStart, lte: periodEnd },
          banStatus: { not: 'NONE' },
        },
      }),

      this.prisma.notification.count({
        where: { organizationId, isRead: false },
      }),
    ])

    const permanentBanScore = policy?.permanentBanScore ?? 9
    const criticalEntriesCount = await this.prisma.reputationEntry.count({
      where: {
        organizationId,
        score: { gte: permanentBanScore },
      },
    })

    const decisions = decisionCountsFromRows(byDecision)
    const servers = emptyServerStatus()
    for (const row of serversGrouped) {
      servers[row.status] = row._count._all
    }

    // challenged في traffic = decision CHALLENGE أو isChallenged
    // حسب المواصفات: challenged من isChallenged=true
    return {
      range,
      rangeLabel: config.label,
      periodStart: periodStart.toISOString(),
      periodEnd: periodEnd.toISOString(),
      traffic: {
        total,
        allowed: decisions.ALLOW,
        blocked: decisions.BLOCK,
        challenged: challengedTotal,
        rateLimited: decisions.RATE_LIMIT,
        monitored: decisions.MONITOR,
      },
      risk: {
        avgScore: round1(avgRisk._avg.riskScore ?? 0),
        surgeDetected: surgeCount > 0,
        surgeCount,
      },
      challenges: {
        total: challengedTotal,
        passed: challengePassed,
        failed: challengeFailed,
      },
      servers,
      reputation: {
        activeBans,
        permanentBans,
        criticalEntries: criticalEntriesCount,
        newBansInRange,
      },
      unreadNotifications,
      serverId: serverId ?? null,
      generatedAt: new Date().toISOString(),
    }
  }

  // ================================================================
  // GET /dashboard/timeline
  // ================================================================

  async getTimeline(
    organizationId: string,
    range: DashboardRange,
    serverId?: string,
  ): Promise<TimelineResult> {
    await this.assertServerOwned(organizationId, serverId)

    const { periodStart, periodEnd, config } = periodFromRange(range)

    // تجميع بـ PostgreSQL
    // 1h → buckets كل 5 دقايق؛ الباقي date_trunc hour/day
    type RawRow = {
      bucket: Date
      total: bigint | number
      blocked: bigint | number
      challenged: bigint | number
      rate_limited: bigint | number
      allowed: bigint | number
      monitored: bigint | number
      avg_risk: number | null
    }

    let rows: RawRow[]

    if (range === '1h') {
      // date_trunc إلى 5 دقايق
      rows = await this.prisma.$queryRaw<RawRow[]>`
        SELECT
          to_timestamp(
            floor(extract(epoch FROM se."createdAt") / 300) * 300
          ) AT TIME ZONE 'UTC' AS bucket,
          COUNT(*)::bigint AS total,
          COUNT(*) FILTER (WHERE se.decision = 'BLOCK')::bigint AS blocked,
          COUNT(*) FILTER (WHERE se."isChallenged" = true)::bigint AS challenged,
          COUNT(*) FILTER (WHERE se.decision = 'RATE_LIMIT')::bigint AS rate_limited,
          COUNT(*) FILTER (WHERE se.decision = 'ALLOW')::bigint AS allowed,
          COUNT(*) FILTER (WHERE se.decision = 'MONITOR')::bigint AS monitored,
          AVG(se."riskScore")::float AS avg_risk
        FROM "SecurityEvent" se
        WHERE se."organizationId" = ${organizationId}
          AND se."createdAt" >= ${periodStart}
          AND se."createdAt" <= ${periodEnd}
          ${serverId ? Prisma.sql`AND se."serverId" = ${serverId}` : Prisma.empty}
        GROUP BY 1
        ORDER BY 1 ASC
      `
    } else {
      const trunc = config.truncUnit // hour | day
      rows = await this.prisma.$queryRaw<RawRow[]>`
        SELECT
          date_trunc(${Prisma.raw(`'${trunc}'`)}, se."createdAt") AS bucket,
          COUNT(*)::bigint AS total,
          COUNT(*) FILTER (WHERE se.decision = 'BLOCK')::bigint AS blocked,
          COUNT(*) FILTER (WHERE se."isChallenged" = true)::bigint AS challenged,
          COUNT(*) FILTER (WHERE se.decision = 'RATE_LIMIT')::bigint AS rate_limited,
          COUNT(*) FILTER (WHERE se.decision = 'ALLOW')::bigint AS allowed,
          COUNT(*) FILTER (WHERE se.decision = 'MONITOR')::bigint AS monitored,
          AVG(se."riskScore")::float AS avg_risk
        FROM "SecurityEvent" se
        WHERE se."organizationId" = ${organizationId}
          AND se."createdAt" >= ${periodStart}
          AND se."createdAt" <= ${periodEnd}
          ${serverId ? Prisma.sql`AND se."serverId" = ${serverId}` : Prisma.empty}
        GROUP BY 1
        ORDER BY 1 ASC
      `
    }

    const points: TimelinePoint[] = rows.map((r) => ({
      time: new Date(r.bucket).toISOString(),
      total: Number(r.total),
      blocked: Number(r.blocked),
      challenged: Number(r.challenged),
      rateLimited: Number(r.rate_limited),
      allowed: Number(r.allowed),
      monitored: Number(r.monitored),
      avgRiskScore: round1(Number(r.avg_risk ?? 0)),
    }))

    return {
      range,
      interval: config.interval,
      periodStart: periodStart.toISOString(),
      periodEnd: periodEnd.toISOString(),
      serverId: serverId ?? null,
      points,
      generatedAt: new Date().toISOString(),
    }
  }

  // ================================================================
  // GET /dashboard/top
  // ================================================================

  async getTop(
    organizationId: string,
    by: TopBy,
    range: DashboardRange,
    limit: number,
    serverId?: string,
  ): Promise<TopResult> {
    await this.assertServerOwned(organizationId, serverId)

    const { periodStart, periodEnd } = periodFromRange(range)

    let items: TopItem[]

    switch (by) {
      case 'ip':
        items = await this.topByIp(
          organizationId,
          periodStart,
          periodEnd,
          limit,
          serverId,
        )
        break
      case 'path':
        items = await this.topByPath(
          organizationId,
          periodStart,
          periodEnd,
          limit,
          serverId,
        )
        break
      case 'country':
        items = await this.topByCountry(
          organizationId,
          periodStart,
          periodEnd,
          limit,
          serverId,
        )
        break
      case 'asn':
        items = await this.topByAsn(
          organizationId,
          periodStart,
          periodEnd,
          limit,
          serverId,
        )
        break
      case 'ipType':
        items = await this.topByIpType(
          organizationId,
          periodStart,
          periodEnd,
          limit,
          serverId,
        )
        break
      case 'stage':
        items = await this.topByStage(
          organizationId,
          periodStart,
          periodEnd,
          limit,
          serverId,
        )
        break
      default:
        items = []
    }

    return {
      by,
      range,
      limit,
      serverId: serverId ?? null,
      items,
      generatedAt: new Date().toISOString(),
    }
  }

  private async topByIp(
    organizationId: string,
    periodStart: Date,
    periodEnd: Date,
    limit: number,
    serverId?: string,
  ): Promise<TopItem[]> {
    type Row = {
      value: string
      total: bigint
      blocked: bigint
      challenged: bigint
      rate_limited: bigint
      avg_risk: number | null
      max_risk: number | null
    }

    const rows = await this.prisma.$queryRaw<Row[]>`
      SELECT
        se."ipAddress" AS value,
        COUNT(*)::bigint AS total,
        COUNT(*) FILTER (WHERE se.decision = 'BLOCK')::bigint AS blocked,
        COUNT(*) FILTER (WHERE se."isChallenged" = true)::bigint AS challenged,
        COUNT(*) FILTER (WHERE se.decision = 'RATE_LIMIT')::bigint AS rate_limited,
        AVG(se."riskScore")::float AS avg_risk,
        MAX(se."riskScore")::int AS max_risk
      FROM "SecurityEvent" se
      WHERE se."organizationId" = ${organizationId}
        AND se."createdAt" >= ${periodStart}
        AND se."createdAt" <= ${periodEnd}
        ${serverId ? Prisma.sql`AND se."serverId" = ${serverId}` : Prisma.empty}
      GROUP BY se."ipAddress"
      ORDER BY total DESC
      LIMIT ${limit}
    `

    return rows.map((r) => ({
      value: r.value,
      total: Number(r.total),
      blocked: Number(r.blocked),
      challenged: Number(r.challenged),
      rateLimited: Number(r.rate_limited),
      avgRiskScore: round1(Number(r.avg_risk ?? 0)),
      maxRiskScore: Number(r.max_risk ?? 0),
    }))
  }

  private async topByPath(
    organizationId: string,
    periodStart: Date,
    periodEnd: Date,
    limit: number,
    serverId?: string,
  ): Promise<TopItem[]> {
    type Row = {
      value: string
      total: bigint
      blocked: bigint
      challenged: bigint
      rate_limited: bigint
      allowed: bigint
      avg_risk: number | null
    }

    const rows = await this.prisma.$queryRaw<Row[]>`
      SELECT
        se.path AS value,
        COUNT(*)::bigint AS total,
        COUNT(*) FILTER (WHERE se.decision = 'BLOCK')::bigint AS blocked,
        COUNT(*) FILTER (WHERE se."isChallenged" = true)::bigint AS challenged,
        COUNT(*) FILTER (WHERE se.decision = 'RATE_LIMIT')::bigint AS rate_limited,
        COUNT(*) FILTER (WHERE se.decision = 'ALLOW')::bigint AS allowed,
        AVG(se."riskScore")::float AS avg_risk
      FROM "SecurityEvent" se
      WHERE se."organizationId" = ${organizationId}
        AND se."createdAt" >= ${periodStart}
        AND se."createdAt" <= ${periodEnd}
        ${serverId ? Prisma.sql`AND se."serverId" = ${serverId}` : Prisma.empty}
      GROUP BY se.path
      ORDER BY total DESC
      LIMIT ${limit}
    `

    return rows.map((r) => ({
      value: r.value,
      total: Number(r.total),
      blocked: Number(r.blocked),
      challenged: Number(r.challenged),
      rateLimited: Number(r.rate_limited),
      allowed: Number(r.allowed),
      avgRiskScore: round1(Number(r.avg_risk ?? 0)),
    }))
  }

  private async topByCountry(
    organizationId: string,
    periodStart: Date,
    periodEnd: Date,
    limit: number,
    serverId?: string,
  ): Promise<TopItem[]> {
    type Row = {
      value: string | null
      total: bigint
      blocked: bigint
      challenged: bigint
      avg_risk: number | null
    }

    const rows = await this.prisma.$queryRaw<Row[]>`
      SELECT
        COALESCE(se."countryCode", 'ZZ') AS value,
        COUNT(*)::bigint AS total,
        COUNT(*) FILTER (WHERE se.decision = 'BLOCK')::bigint AS blocked,
        COUNT(*) FILTER (WHERE se."isChallenged" = true)::bigint AS challenged,
        AVG(se."riskScore")::float AS avg_risk
      FROM "SecurityEvent" se
      WHERE se."organizationId" = ${organizationId}
        AND se."createdAt" >= ${periodStart}
        AND se."createdAt" <= ${periodEnd}
        ${serverId ? Prisma.sql`AND se."serverId" = ${serverId}` : Prisma.empty}
      GROUP BY 1
      ORDER BY total DESC
      LIMIT ${limit}
    `

    return rows.map((r) => ({
      value: r.value ?? 'ZZ',
      total: Number(r.total),
      blocked: Number(r.blocked),
      challenged: Number(r.challenged),
      avgRiskScore: round1(Number(r.avg_risk ?? 0)),
    }))
  }

  private async topByAsn(
    organizationId: string,
    periodStart: Date,
    periodEnd: Date,
    limit: number,
    serverId?: string,
  ): Promise<TopItem[]> {
    type Row = {
      value: string
      label: string | null
      total: bigint
      blocked: bigint
      challenged: bigint
      avg_risk: number | null
    }

    // asn من الحدث + asOrg من أحدث ReputationEntry لنفس الـ org/IP إن وُجد
    const rows = await this.prisma.$queryRaw<Row[]>`
      SELECT
        COALESCE(se.asn::text, 'unknown') AS value,
        (
          SELECT re."asOrg"
          FROM "ReputationEntry" re
          WHERE re."organizationId" = se."organizationId"
            AND re."ipAddress" = se."ipAddress"
            AND re."asOrg" IS NOT NULL
          ORDER BY re."updatedAt" DESC
          LIMIT 1
        ) AS label,
        COUNT(*)::bigint AS total,
        COUNT(*) FILTER (WHERE se.decision = 'BLOCK')::bigint AS blocked,
        COUNT(*) FILTER (WHERE se."isChallenged" = true)::bigint AS challenged,
        AVG(se."riskScore")::float AS avg_risk
      FROM "SecurityEvent" se
      WHERE se."organizationId" = ${organizationId}
        AND se."createdAt" >= ${periodStart}
        AND se."createdAt" <= ${periodEnd}
        ${serverId ? Prisma.sql`AND se."serverId" = ${serverId}` : Prisma.empty}
      GROUP BY se.asn, se."organizationId"
      ORDER BY total DESC
      LIMIT ${limit}
    `

    return rows.map((r) => ({
      value: r.value,
      label: r.label,
      total: Number(r.total),
      blocked: Number(r.blocked),
      challenged: Number(r.challenged),
      avgRiskScore: round1(Number(r.avg_risk ?? 0)),
    }))
  }

  private async topByIpType(
    organizationId: string,
    periodStart: Date,
    periodEnd: Date,
    limit: number,
    serverId?: string,
  ): Promise<TopItem[]> {
    type Row = {
      value: string | null
      total: bigint
      blocked: bigint
      challenged: bigint
      avg_risk: number | null
    }

    const rows = await this.prisma.$queryRaw<Row[]>`
      SELECT
        COALESCE(se."ipType"::text, 'UNKNOWN') AS value,
        COUNT(*)::bigint AS total,
        COUNT(*) FILTER (WHERE se.decision = 'BLOCK')::bigint AS blocked,
        COUNT(*) FILTER (WHERE se."isChallenged" = true)::bigint AS challenged,
        AVG(se."riskScore")::float AS avg_risk
      FROM "SecurityEvent" se
      WHERE se."organizationId" = ${organizationId}
        AND se."createdAt" >= ${periodStart}
        AND se."createdAt" <= ${periodEnd}
        ${serverId ? Prisma.sql`AND se."serverId" = ${serverId}` : Prisma.empty}
      GROUP BY 1
      ORDER BY total DESC
      LIMIT ${limit}
    `

    return rows.map((r) => ({
      value: r.value ?? 'UNKNOWN',
      total: Number(r.total),
      blocked: Number(r.blocked),
      challenged: Number(r.challenged),
      avgRiskScore: round1(Number(r.avg_risk ?? 0)),
    }))
  }

  private async topByStage(
    organizationId: string,
    periodStart: Date,
    periodEnd: Date,
    limit: number,
    serverId?: string,
  ): Promise<TopItem[]> {
    type Row = {
      value: string | null
      total: bigint
      blocked: bigint
      challenged: bigint
      avg_risk: number | null
    }

    const rows = await this.prisma.$queryRaw<Row[]>`
      SELECT
        COALESCE(se."decidedAtStage"::text, 'UNKNOWN') AS value,
        COUNT(*)::bigint AS total,
        COUNT(*) FILTER (WHERE se.decision = 'BLOCK')::bigint AS blocked,
        COUNT(*) FILTER (WHERE se."isChallenged" = true)::bigint AS challenged,
        AVG(se."riskScore")::float AS avg_risk
      FROM "SecurityEvent" se
      WHERE se."organizationId" = ${organizationId}
        AND se."createdAt" >= ${periodStart}
        AND se."createdAt" <= ${periodEnd}
        ${serverId ? Prisma.sql`AND se."serverId" = ${serverId}` : Prisma.empty}
      GROUP BY 1
      ORDER BY total DESC
      LIMIT ${limit}
    `

    return rows.map((r) => ({
      value: r.value ?? 'UNKNOWN',
      total: Number(r.total),
      blocked: Number(r.blocked),
      challenged: Number(r.challenged),
      avgRiskScore: round1(Number(r.avg_risk ?? 0)),
    }))
  }

  // ================================================================
  // GET /dashboard/servers
  // ================================================================

  async getServersSummary(
    organizationId: string,
  ): Promise<ServersSummaryResult> {
    const hourAgo = new Date(Date.now() - 60 * 60 * 1000)

    const servers = await this.prisma.server.findMany({
      where: { organizationId },
      orderBy: { domain: 'asc' },
      select: {
        id: true,
        domain: true,
        status: true,
        mode: true,
        dnsVerified: true,
        gatewayReachable: true,
        originReachable: true,
        avgResponseTimeMs: true,
        currentLoadPercent: true,
        maxRequestsPerSecond: true,
        safeRequestsPerSecond: true,
        p95ResponseTimeMs: true,
        probeRecommendation: true,
        probeConfidence: true,
        lastProbeAt: true,
        lastHealthCheckAt: true,
      },
    })

    const ids = servers.map((s) => s.id)

    // أحداث آخر ساعة مجمّعة لكل سيرفر
    type EvRow = {
      serverId: string
      total: bigint
      blocked: bigint
      last_at: Date | null
    }

    const evRows =
      ids.length === 0
        ? []
        : await this.prisma.$queryRaw<EvRow[]>`
            SELECT
              se."serverId" AS "serverId",
              COUNT(*)::bigint AS total,
              COUNT(*) FILTER (WHERE se.decision = 'BLOCK')::bigint AS blocked,
              MAX(se."createdAt") AS last_at
            FROM "SecurityEvent" se
            WHERE se."organizationId" = ${organizationId}
              AND se."createdAt" >= ${hourAgo}
              AND se."serverId" IN (${Prisma.join(ids)})
            GROUP BY se."serverId"
          `

    const evMap = new Map(
      evRows.map((r) => [
        r.serverId,
        {
          total: Number(r.total),
          blocked: Number(r.blocked),
          lastAt: r.last_at,
        },
      ]),
    )

    const items: ServerSummaryItem[] = servers.map((s) => {
      const ev = evMap.get(s.id)
      return {
        id: s.id,
        domain: s.domain,
        status: s.status,
        mode: s.mode,
        dnsVerified: s.dnsVerified,
        gatewayReachable: s.gatewayReachable,
        originReachable: s.originReachable,
        avgResponseTimeMs: s.avgResponseTimeMs,
        currentLoadPercent: s.currentLoadPercent,
        maxRequestsPerSecond: s.maxRequestsPerSecond,
        safeRequestsPerSecond: s.safeRequestsPerSecond,
        p95ResponseTimeMs: s.p95ResponseTimeMs,
        probeRecommendation: s.probeRecommendation,
        probeConfidence: s.probeConfidence,
        lastProbeAt: s.lastProbeAt?.toISOString() ?? null,
        eventsLastHour: ev?.total ?? 0,
        blockedLastHour: ev?.blocked ?? 0,
        lastHealthCheckAt: s.lastHealthCheckAt?.toISOString() ?? null,
        lastEventAt: ev?.lastAt ? new Date(ev.lastAt).toISOString() : null,
      }
    })

    const totals = {
      count: items.length,
      online: items.filter((s) => s.status === 'ONLINE').length,
      degraded: items.filter((s) => s.status === 'DEGRADED').length,
      offline: items.filter((s) => s.status === 'OFFLINE').length,
      pending: items.filter((s) => s.status === 'PENDING').length,
      maintenance: items.filter((s) => s.status === 'MAINTENANCE').length,
    }

    return {
      servers: items,
      totals,
      generatedAt: new Date().toISOString(),
    }
  }

  // ================================================================
  // GET /dashboard/threat-map
  // ================================================================

  async getThreatMap(
    organizationId: string,
    range: DashboardRange,
  ): Promise<ThreatMapResult> {
    const { periodStart, periodEnd } = periodFromRange(range)

    type Row = {
      code: string | null
      total: bigint
      blocked: bigint
      challenged: bigint
    }

    const rows = await this.prisma.$queryRaw<Row[]>`
      SELECT
        se."countryCode" AS code,
        COUNT(*)::bigint AS total,
        COUNT(*) FILTER (WHERE se.decision = 'BLOCK')::bigint AS blocked,
        COUNT(*) FILTER (WHERE se."isChallenged" = true)::bigint AS challenged
      FROM "SecurityEvent" se
      WHERE se."organizationId" = ${organizationId}
        AND se."createdAt" >= ${periodStart}
        AND se."createdAt" <= ${periodEnd}
      GROUP BY se."countryCode"
      ORDER BY total DESC
    `

    let unknownCountryTotal = 0
    const countries: ThreatMapCountry[] = []

    for (const r of rows) {
      const total = Number(r.total)
      const blocked = Number(r.blocked)
      const challenged = Number(r.challenged)

      if (!r.code) {
        unknownCountryTotal += total
        continue
      }

      const blockRate = total > 0 ? blocked / total : 0
      countries.push({
        code: r.code,
        total,
        blocked,
        challenged,
        blockRate: round1(blockRate * 100) / 100,
        threatLevel: computeThreatLevel(blockRate),
      })
    }

    return {
      range,
      periodStart: periodStart.toISOString(),
      periodEnd: periodEnd.toISOString(),
      countries,
      unknownCountryTotal,
      generatedAt: new Date().toISOString(),
    }
  }
}

export default DashboardService