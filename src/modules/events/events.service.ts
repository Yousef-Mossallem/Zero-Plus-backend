// backend/src/modules/events/events.service.ts

import type { FastifyInstance } from 'fastify';
import { Prisma } from '@prisma/client';

import type {
  CreateEventInput,
  GetEventsQuery,
} from './events.schema.js';

/**
 * ================================================================
 * Zero Plus - Events Service
 * ================================================================
 *
 * مسؤول عن:
 * - إنشاء Security Events
 * - التأكد أن الـ Server تابع لنفس الـ Organization
 * - التأكد أن Reputation Entry تابع لنفس الـ Organization
 * - جلب الـ Events مع Filtering / Pagination / Sorting
 * - جلب Event واحد بالتفصيل
 *
 * ملاحظة:
 * الـ Events تعتبر Audit/Security Logs لذلك لا يوجد هنا:
 * - updateEvent
 * - deleteEvent
 *
 * لأنها في النظام المفروض تكون immutable.
 * ================================================================
 */

/**
 * Error مخصص نستخدمه مع Fastify
 * حتى يرجع HTTP status مناسب بدل 500.
 */
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
  /**
   * --------------------------------------------------------------
   * 1. التأكد أن الـ Server موجود وتابع لنفس الـ Organization
   * --------------------------------------------------------------
   *
   * مهم جدًا لمنع شركة من تسجيل Event على Server
   * تابع لشركة أخرى.
   */
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

  /**
   * --------------------------------------------------------------
   * 2. لو فيه Reputation Entry نتأكد أنه تابع لنفس المؤسسة
   * --------------------------------------------------------------
   */
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

  /**
   * --------------------------------------------------------------
   * 3. إنشاء الـ Event
   * --------------------------------------------------------------
   *
   * ممنوع استخدام:
   *
   *   ...data
   *
   * لأننا نريد التحكم في الـ fields التي تدخل قاعدة البيانات
   * وعدم السماح لأي field غير متوقع بالدخول.
   */
  const event = await fastify.prisma.securityEvent.create({
    data: {
      serverId: data.serverId,
      organizationId,

      ipAddress: data.ipAddress,
      path: data.path,
      method: data.method,

      userAgent: data.userAgent,
      referer: data.referer,
      requestId: data.requestId,

      riskScore: data.riskScore,
      anomalyScore: data.anomalyScore,
      confidence: data.confidence,

      decision: data.decision,

      reasonSummary: data.reasonSummary,

      /**
       * Prisma Json يحتاج InputJsonValue.
       * الـ schema عندنا يسمح Record<string, unknown>
       * لذلك نعمل cast هنا بعد التحقق بواسطة Zod.
       */
      reasonDetails: data.reasonDetails
        ? (data.reasonDetails as Prisma.InputJsonObject)
        : undefined,

      countryCode: data.countryCode,
      asn: data.asn,
      ipType: data.ipType,

      isChallenged: data.isChallenged ?? false,
      challengePassed: data.challengePassed,

      reputationEntryId: data.reputationEntryId,
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
  /**
   * --------------------------------------------------------------
   * Pagination
   * --------------------------------------------------------------
   *
   * page و limit تم تحويلهم بالفعل إلى numbers
   * داخل Zod schema.
   */
  const page = query.page;
  const limit = query.limit;

  const skip = (page - 1) * limit;

  /**
   * --------------------------------------------------------------
   * Base WHERE
   * --------------------------------------------------------------
   *
   * أهم نقطة في Events:
   *
   * كل Query لازم يبدأ بـ organizationId
   * حتى لا يرى المستخدم Events الخاصة بمؤسسة أخرى.
   */
  const where: Prisma.SecurityEventWhereInput = {
    organizationId,
  };

  /**
   * --------------------------------------------------------------
   * Server Filter
   * --------------------------------------------------------------
   */
  if (query.serverId) {
    where.serverId = query.serverId;
  }

  /**
   * --------------------------------------------------------------
   * Decision Filter
   * --------------------------------------------------------------
   */
  if (query.decision) {
    where.decision = query.decision;
  }

  /**
   * --------------------------------------------------------------
   * IP Address Filter
   * --------------------------------------------------------------
   */
  if (query.ipAddress) {
    where.ipAddress = {
      contains: query.ipAddress,
      mode: 'insensitive',
    };
  }

  /**
   * --------------------------------------------------------------
   * Country
   * --------------------------------------------------------------
   */
  if (query.countryCode) {
    where.countryCode = query.countryCode;
  }

  /**
   * --------------------------------------------------------------
   * IP Type
   * --------------------------------------------------------------
   */
  if (query.ipType) {
    where.ipType = query.ipType;
  }

  /**
   * --------------------------------------------------------------
   * HTTP Method
   * --------------------------------------------------------------
   */
  if (query.method) {
    where.method = query.method;
  }

  /**
   * --------------------------------------------------------------
   * Path
   * --------------------------------------------------------------
   */
  if (query.path) {
    where.path = {
      contains: query.path,
      mode: 'insensitive',
    };
  }

  /**
   * --------------------------------------------------------------
   * Risk Score Range
   * --------------------------------------------------------------
   */
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

  /**
   * --------------------------------------------------------------
   * Challenge Filters
   * --------------------------------------------------------------
   */
  if (query.isChallenged !== undefined) {
    where.isChallenged = query.isChallenged;
  }

  if (query.challengePassed !== undefined) {
    where.challengePassed = query.challengePassed;
  }

  /**
   * --------------------------------------------------------------
   * Reputation Entry Filter
   * --------------------------------------------------------------
   */
  if (query.reputationEntryId) {
    where.reputationEntryId = query.reputationEntryId;
  }

  /**
   * --------------------------------------------------------------
   * Date Range
   * --------------------------------------------------------------
   */
  if (query.startDate || query.endDate) {
    where.createdAt = {};

    if (query.startDate) {
      where.createdAt.gte = new Date(query.startDate);
    }

    if (query.endDate) {
      where.createdAt.lte = new Date(query.endDate);
    }
  }

  /**
   * --------------------------------------------------------------
   * Global Search
   * --------------------------------------------------------------
   *
   * يبحث في أهم الحقول النصية.
   */
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
        method: {
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

  /**
   * --------------------------------------------------------------
   * Sorting
   * --------------------------------------------------------------
   *
   * الـ schema يمنع أي field غير الموجود في القائمة.
   * هنا فقط نربطه بحقول Prisma.
   */
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

  /**
   * --------------------------------------------------------------
   * Query Database
   * --------------------------------------------------------------
   */
  const [events, total, aggregate] = await Promise.all([
    fastify.prisma.securityEvent.findMany({
      where,
      skip,
      take: limit,
      orderBy,

      /**
       * نجيب الـ server كـ summary بسيط
       * بدل ما نرجع كل بياناته.
       */
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

  /**
   * --------------------------------------------------------------
   * Summary
   * --------------------------------------------------------------
   *
   * أرقام إضافية مفيدة للـ dashboard.
   */
  const summary = {
    totalEvents: total,
    averageRiskScore: aggregate._avg.riskScore ?? 0,
  };

  /**
   * --------------------------------------------------------------
   * Response
   * --------------------------------------------------------------
   */
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
  /**
   * organizationId جزء أساسي من الـ where
   * حتى لو المستخدم يعرف ID Event خاص بشركة أخرى
   * لن يستطيع الوصول إليه.
   */
  const event = await fastify.prisma.securityEvent.findFirst({
    where: {
      id: eventId,
      organizationId,
    },

    /**
     * صفحة التفاصيل تحتاج معلومات الـ Server
     * والـ Reputation المرتبطة بالحدث.
     */
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
