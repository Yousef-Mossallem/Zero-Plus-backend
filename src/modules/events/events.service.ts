// backend/src/modules/events/events.service.ts
// ==================================================================
// Zero Plus - Security Events Service
// بعد إنشاء الحدث: بث لحظي للـ Dashboard عبر Socket.IO
// ==================================================================

import type { FastifyInstance } from 'fastify'
import { Prisma } from '@prisma/client'

import type {
  CreateEventInput,
  GetEventsQuery,
} from './events.schema.js'
import { SocketEvents } from '../../plugins/socket.plugin.js'
import type { GatewayEventInput } from './events.internal.routes.js'

// ------------------------------------------------------------------
// Errors
// ------------------------------------------------------------------

class EventServiceError extends Error {
  public readonly statusCode: number

  constructor(message: string, statusCode: number) {
    super(message)
    this.name = 'EventServiceError'
    this.statusCode = statusCode
  }
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

/**
 * قرارات تستحق ظهور فوري أوضح في الـ Live feed.
 * باقي الأحداث برضو بتتبعت، بس الفرونت يقدر يفلتر.
 */
const HIGHLIGHT_DECISIONS = new Set(['BLOCK', 'CHALLENGE', 'RATE_LIMIT', 'MONITOR'])

/**
 * Payload خفيف للـ Socket — مش الصف كامل من DB.
 */
function toRealtimePayload(event: {
  id: string
  organizationId: string
  serverId: string
  ipAddress: string
  path: string
  method: string
  riskScore: number
  anomalyScore: number | null
  confidence: number | null
  decision: string
  reasonSummary: string | null
  countryCode: string | null
  ipType: string | null
  isChallenged: boolean
  challengePassed: boolean | null
  createdAt: Date
}) {
  return {
    id: event.id,
    organizationId: event.organizationId,
    serverId: event.serverId,
    ipAddress: event.ipAddress,
    path: event.path,
    method: event.method,
    riskScore: event.riskScore,
    anomalyScore: event.anomalyScore,
    confidence: event.confidence,
    decision: event.decision,
    reasonSummary: event.reasonSummary,
    countryCode: event.countryCode,
    ipType: event.ipType,
    isChallenged: event.isChallenged,
    challengePassed: event.challengePassed,
    createdAt: event.createdAt.toISOString(),
    highlight: HIGHLIGHT_DECISIONS.has(event.decision),
  }
}

/**
 * بث آمن: لو Socket مش متسجل (اختبارات) متعملش crash.
 */
function emitSecurityEvent(
  fastify: FastifyInstance,
  organizationId: string,
  payload: ReturnType<typeof toRealtimePayload>,
) {
  try {
    if (typeof fastify.broadcastToOrg === 'function') {
      fastify.broadcastToOrg(
        organizationId,
        SocketEvents.SECURITY_EVENT_NEW,
        payload,
      )
    }
  } catch (err) {
    fastify.log.warn({ err, organizationId }, 'Failed to broadcast security_event:new')
  }
}

// ------------------------------------------------------------------
// CREATE EVENT
// ------------------------------------------------------------------

export async function createEvent(
  fastify: FastifyInstance,
  organizationId: string,
  data: CreateEventInput,
) {
  const server = await fastify.prisma.server.findFirst({
    where: {
      id: data.serverId,
      organizationId,
    },
    select: {
      id: true,
    },
  })

  if (!server) {
    throw new EventServiceError(
      'السيرفر غير موجود أو لا ينتمي إلى هذه المؤسسة',
      404,
    )
  }

  if (data.reputationEntryId) {
    const reputationEntry =
      await fastify.prisma.reputationEntry.findFirst({
        where: {
          id: data.reputationEntryId,
          organizationId,
        },
        select: {
          id: true,
        },
      })

    if (!reputationEntry) {
      throw new EventServiceError(
        'Reputation Entry غير موجود أو لا ينتمي إلى هذه المؤسسة',
        404,
      )
    }
  }

  const event = await fastify.prisma.securityEvent.create({
    data: {
      serverId: data.serverId,
      organizationId,

      ipAddress: data.ipAddress,
      path: data.path,
      method: data.method,

      userAgent: data.userAgent ?? null,
      referer: data.referer ?? null,
      requestId: data.requestId ?? null,

      riskScore: data.riskScore,
      anomalyScore: data.anomalyScore,
      confidence: data.confidence,

      decision: data.decision,

      reasonSummary: data.reasonSummary ?? null,

      reasonDetails: data.reasonDetails
        ? (data.reasonDetails as Prisma.InputJsonObject)
        : Prisma.JsonNull,

      countryCode: data.countryCode ?? null,
      asn: data.asn ?? null,
      ipType: data.ipType ?? null,

      isChallenged: data.isChallenged ?? false,
      challengePassed: data.challengePassed ?? null,

      reputationEntryId: data.reputationEntryId ?? null,
    },
  })

  // ------------------------------------------------------------------
  // Realtime: Dashboard Live Traffic / Security Events
  // ------------------------------------------------------------------
  emitSecurityEvent(
    fastify,
    organizationId,
    toRealtimePayload(event),
  )

  return event
}

// ------------------------------------------------------------------
// GET EVENTS
// ------------------------------------------------------------------

export async function getEvents(
  fastify: FastifyInstance,
  organizationId: string,
  query: GetEventsQuery,
) {
  const page = query.page
  const limit = query.limit
  const skip = (page - 1) * limit

  const where: Prisma.SecurityEventWhereInput = {
    organizationId,
  }

  if (query.serverId) {
    where.serverId = query.serverId
  }

  if (query.decision) {
    where.decision = query.decision
  }

  if (query.ipAddress) {
    where.ipAddress = {
      contains: query.ipAddress,
      mode: 'insensitive',
    }
  }

  if (query.countryCode) {
    where.countryCode = query.countryCode
  }

  if (query.ipType) {
    where.ipType = query.ipType
  }

  if (query.method) {
    where.method = query.method
  }

  if (query.path) {
    where.path = {
      contains: query.path,
      mode: 'insensitive',
    }
  }

  if (
    query.minRiskScore !== undefined ||
    query.maxRiskScore !== undefined
  ) {
    where.riskScore = {}

    if (query.minRiskScore !== undefined) {
      where.riskScore.gte = query.minRiskScore
    }

    if (query.maxRiskScore !== undefined) {
      where.riskScore.lte = query.maxRiskScore
    }
  }

  if (query.isChallenged !== undefined) {
    where.isChallenged = query.isChallenged
  }

  if (query.challengePassed !== undefined) {
    where.challengePassed = query.challengePassed
  }

  if (query.reputationEntryId) {
    where.reputationEntryId = query.reputationEntryId
  }

  if (query.startDate || query.endDate) {
    where.createdAt = {}

    if (query.startDate) {
      where.createdAt.gte = new Date(query.startDate)
    }

    if (query.endDate) {
      where.createdAt.lte = new Date(query.endDate)
    }
  }

  if (query.search) {
    where.OR = [
      {
        ipAddress: {
          contains: query.search,
          mode: 'insensitive',
        },
      },
      {
        path: {
          contains: query.search,
          mode: 'insensitive',
        },
      },
      {
        userAgent: {
          contains: query.search,
          mode: 'insensitive',
        },
      },
      {
        referer: {
          contains: query.search,
          mode: 'insensitive',
        },
      },
      {
        requestId: {
          contains: query.search,
          mode: 'insensitive',
        },
      },
      {
        reasonSummary: {
          contains: query.search,
          mode: 'insensitive',
        },
      },
    ]
  }

  const sortFieldMap = {
    createdAt: 'createdAt',
    riskScore: 'riskScore',
    ipAddress: 'ipAddress',
    decision: 'decision',
    serverId: 'serverId',
  } as const

  const sortField = sortFieldMap[query.sortBy]

  const orderBy: Prisma.SecurityEventOrderByWithRelationInput = {
    [sortField]: query.sortOrder,
  }

  const [events, total, aggregate] = await Promise.all([
    fastify.prisma.securityEvent.findMany({
      where,
      skip,
      take: limit,
      orderBy,
      include: {
        server: {
          select: {
            id: true,
            domain: true,
          },
        },
      },
    }),

    fastify.prisma.securityEvent.count({
      where,
    }),

    fastify.prisma.securityEvent.aggregate({
      where,
      _avg: {
        riskScore: true,
      },
    }),
  ])

  const summary = {
    totalEvents: total,
    averageRiskScore: aggregate._avg.riskScore ?? 0,
  }

  return {
    success: true,

    events,

    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
      hasNextPage: page < Math.ceil(total / limit),
      hasPreviousPage: page > 1,
    },

    summary,
  }
}

// ------------------------------------------------------------------
// GET EVENT BY ID
// ------------------------------------------------------------------



export async function getEventById(
  fastify: FastifyInstance,
  organizationId: string,
  eventId: string,
) {
  const event = await fastify.prisma.securityEvent.findFirst({
    where: {
      id: eventId,
      organizationId,
    },
    include: {
      server: {
        select: {
          id: true,
          domain: true,
        },
      },

      reputationEntry: {
        select: {
          id: true,
          ipAddress: true,
          score: true,
          banStatus: true,
          ipType: true,
          countryCode: true,
          asn: true,
        },
      },
    },
  })

  return event
}
// ------------------------------------------------------------------
// CREATE EVENT (من الـ Gateway) — بيدعم كل حقول السكيما
// ------------------------------------------------------------------

export async function createGatewayEvent(
  fastify: FastifyInstance,
  data: GatewayEventInput,
) {
  const { organizationId } = data

  const server = await fastify.prisma.server.findFirst({
    where: { id: data.serverId, organizationId },
    select: { id: true },
  })

  if (!server) {
    throw new EventServiceError(
      'السيرفر غير موجود أو لا ينتمي إلى هذه المؤسسة',
      404,
    )
  }

  if (data.reputationEntryId) {
    const entry = await fastify.prisma.reputationEntry.findFirst({
      where: { id: data.reputationEntryId, organizationId },
      select: { id: true },
    })

    if (!entry) {
      throw new EventServiceError(
        'Reputation Entry غير موجود أو لا ينتمي إلى هذه المؤسسة',
        404,
      )
    }
  }

  const event = await fastify.prisma.securityEvent.create({
    data: {
      organizationId,
      serverId: data.serverId,

      ipAddress: data.ipAddress,
      path: data.path,
      method: data.method,
      userAgent: data.userAgent ?? null,
      referer: data.referer ?? null,
      requestId: data.requestId ?? null,

      riskScore: data.riskScore,
      anomalyScore: data.anomalyScore ?? null,
      confidence: data.confidence ?? null,
      decision: data.decision,
      decidedAtStage: data.decidedAtStage ?? null,
      reasonSummary: data.reasonSummary ?? null,
      reasonDetails: data.reasonDetails
        ? (data.reasonDetails as Prisma.InputJsonObject)
        : Prisma.JsonNull,
      processingTimeMs: data.processingTimeMs ?? null,

      surgeDetected: data.surgeDetected ?? false,
      pathSensitive: data.pathSensitive ?? false,
      recommendation: data.recommendation ?? null,

      countryCode: data.countryCode ?? null,
      asn: data.asn ?? null,
      ipType: data.ipType ?? null,

      isChallenged: data.isChallenged ?? false,
      challengeType: data.challengeType ?? null,
      challengePassed: data.challengePassed ?? null,

      reputationEntryId: data.reputationEntryId ?? null,
    },
  })

  emitSecurityEvent(fastify, organizationId, toRealtimePayload(event))

  return event
}