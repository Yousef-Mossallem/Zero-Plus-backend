// backend/src/modules/events/events.service.ts

import type { FastifyInstance } from 'fastify';
import { Prisma } from '@prisma/client';

import type {
  CreateEventInput,
  GetEventsQuery,
} from './events.schema.js';

class EventServiceError extends Error {
  public readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = 'EventServiceError';
    this.statusCode = statusCode;
  }
}

/**
 * ================================================================
 * CREATE EVENT
 * ================================================================
 */
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
  });

  if (!server) {
    throw new EventServiceError(
      'السيرفر غير موجود أو لا ينتمي إلى هذه المؤسسة',
      404,
    );
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
      });

    if (!reputationEntry) {
      throw new EventServiceError(
        'Reputation Entry غير موجود أو لا ينتمي إلى هذه المؤسسة',
        404,
      );
    }
  }

  const event = await fastify.prisma.securityEvent.create({
    data: {
      serverId: data.serverId,
      organizationId,

      ipAddress: data.ipAddress,
      path: data.path,
      method: data.method,

      // استخدام ?? null لتفادي تعارض TypeScript مع Prisma
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
  });

  return event;
}

/**
 * ================================================================
 * GET EVENTS
 * ================================================================
 */
export async function getEvents(
  fastify: FastifyInstance,
  organizationId: string,
  query: GetEventsQuery,
) {
  const page = query.page;
  const limit = query.limit;
  const skip = (page - 1) * limit;

  const where: Prisma.SecurityEventWhereInput = {
    organizationId,
  };

  if (query.serverId) {
    where.serverId = query.serverId;
  }

  if (query.decision) {
    where.decision = query.decision;
  }

  if (query.ipAddress) {
    where.ipAddress = {
      contains: query.ipAddress,
      mode: 'insensitive',
    };
  }

  if (query.countryCode) {
    where.countryCode = query.countryCode;
  }

  if (query.ipType) {
    where.ipType = query.ipType;
  }

  if (query.method) {
    where.method = query.method;
  }

  if (query.path) {
    where.path = {
      contains: query.path,
      mode: 'insensitive',
    };
  }

  if (
    query.minRiskScore !== undefined ||
    query.maxRiskScore !== undefined
  ) {
    where.riskScore = {};

    if (query.minRiskScore !== undefined) {
      where.riskScore.gte = query.minRiskScore;
    }

    if (query.maxRiskScore !== undefined) {
      where.riskScore.lte = query.maxRiskScore;
    }
  }

  if (query.isChallenged !== undefined) {
    where.isChallenged = query.isChallenged;
  }

  if (query.challengePassed !== undefined) {
    where.challengePassed = query.challengePassed;
  }

  if (query.reputationEntryId) {
    where.reputationEntryId = query.reputationEntryId;
  }

  if (query.startDate || query.endDate) {
    where.createdAt = {};

    if (query.startDate) {
      where.createdAt.gte = new Date(query.startDate);
    }

    if (query.endDate) {
      where.createdAt.lte = new Date(query.endDate);
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
    ];
  }

  const sortFieldMap = {
    createdAt: 'createdAt',
    riskScore: 'riskScore',
    ipAddress: 'ipAddress',
    decision: 'decision',
    serverId: 'serverId',
  } as const;

  const sortField = sortFieldMap[query.sortBy];

  const orderBy: Prisma.SecurityEventOrderByWithRelationInput = {
    [sortField]: query.sortOrder,
  };

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
  ]);

  const summary = {
    totalEvents: total,
    averageRiskScore: aggregate._avg.riskScore ?? 0,
  };

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
  };
}

/**
 * ================================================================
 * GET EVENT BY ID
 * ================================================================
 */
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
  });

  return event;
}
