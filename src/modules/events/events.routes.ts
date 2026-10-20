// backend/src/modules/events/events.routes.ts

import type {
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
} from 'fastify';

import * as eventsService from './events.service.js';

import {
  createEventSchema,
  getEventByIdSchema,
  getEventsQuerySchema,
} from './events.schema.js';

/**
 * ================================================================
 * Zero Plus - Events Routes
 * ================================================================
 *
 * Routes:
 *
 * POST   /api/events
 * GET    /api/events
 * GET    /api/events/:id
 *
 * مسؤولية الـRoutes:
 * - Authentication
 * - استخراج organizationId من JWT
 * - Validation بواسطة Zod
 * - استدعاء Events Service
 * - إرجاع HTTP Responses منظمة
 *
 * الـRoutes لا تحتوي على business logic خاص بالـEvents.
 * الـbusiness logic موجود داخل events.service.ts
 * ================================================================
 */

/**
 * ================================================================
 * Helpers
 * ================================================================
 */

/**
 * استخراج organizationId من JWT
 *
 * مهم:
 * organizationId لا يأتي من الـBody أو Query.
 * يأتي فقط من الـJWT لمنع المستخدم من تحديد مؤسسة أخرى يدويًا.
 */
function getOrganizationId(request: FastifyRequest): string | null {
  const organizationId = request.user?.organizationId;

  if (!organizationId || typeof organizationId !== 'string') {
    return null;
  }

  return organizationId;
}

/**
 * معالجة أخطاء الـService بشكل آمن.
 *
 * أخطاء 4xx:
 * نرجع الرسالة لأنها أخطاء متوقعة مثل:
 * - Server غير موجود
 * - Reputation Entry غير موجود
 *
 * أخطاء 5xx:
 * لا نرجع تفاصيل الخطأ الداخلية للعميل.
 */
function handleRouteError(
  request: FastifyRequest,
  reply: FastifyReply,
  error: unknown,
) {
  request.log.error(
    {
      err: error,
    },
    'Events route error',
  );

  const statusCode =
    typeof error === 'object' &&
    error !== null &&
    'statusCode' in error &&
    typeof error.statusCode === 'number'
      ? error.statusCode
      : 500;

  const message =
    statusCode >= 500
      ? 'حدث خطأ داخلي أثناء معالجة طلب الـ Security Event'
      : error instanceof Error
        ? error.message
        : 'حدث خطأ أثناء معالجة الطلب';

  return reply.code(statusCode).send({
    success: false,
    message,
  });
}

/**
 * ================================================================
 * EVENTS ROUTES
 * ================================================================
 */
export default async function eventRoutes(fastify: FastifyInstance) {
  /**
   * ==============================================================
   * POST /api/events
   * ==============================================================
   *
   * إنشاء Security Event جديد.
   *
   * Authentication:
   * JWT Required
   *
   * organizationId:
   * يتم أخذه من JWT وليس من Body.
   */
  fastify.post(
    '/',
    {
      preHandler: fastify.authenticate,
    },
    async (
      request: FastifyRequest,
      reply: FastifyReply,
    ) => {
      try {
        /**
         * --------------------------------------------------------
         * 1. Get Organization ID
         * --------------------------------------------------------
         */
        const organizationId = getOrganizationId(request);

        if (!organizationId) {
          return reply.code(403).send({
            success: false,
            message: 'معرف المؤسسة غير موجود في التوكن',
          });
        }

        /**
         * --------------------------------------------------------
         * 2. Validate Body
         * --------------------------------------------------------
         */
        const validationResult = createEventSchema.safeParse(
          request.body,
        );

        if (!validationResult.success) {
          return reply.code(400).send({
            success: false,
            message: 'بيانات إنشاء الـ Security Event غير صالحة',
            details: validationResult.error.format(),
          });
        }

        /**
         * --------------------------------------------------------
         * 3. Create Event
         * --------------------------------------------------------
         */
        const newEvent = await eventsService.createEvent(
          fastify,
          organizationId,
          validationResult.data,
        );

        /**
         * --------------------------------------------------------
         * 4. Response
         * --------------------------------------------------------
         */
        return reply.code(201).send({
          success: true,
          message: 'تم إنشاء الـ Security Event بنجاح',
          data: newEvent,
        });
      } catch (error) {
        return handleRouteError(request, reply, error);
      }
    },
  );

  /**
   * ==============================================================
   * GET /api/events
   * ==============================================================
   *
   * جلب Security Events الخاصة بالمؤسسة الحالية.
   *
   * يدعم:
   * - Pagination
   * - Filtering
   * - Search
   * - Risk Score Range
   * - Date Range
   * - Challenge Filters
   * - Sorting
   */
  fastify.get(
    '/',
    {
      preHandler: fastify.authenticate,
    },
    async (
      request: FastifyRequest,
      reply: FastifyReply,
    ) => {
      try {
        /**
         * --------------------------------------------------------
         * 1. Get Organization ID
         * --------------------------------------------------------
         */
        const organizationId = getOrganizationId(request);

        if (!organizationId) {
          return reply.code(403).send({
            success: false,
            message: 'معرف المؤسسة غير موجود في التوكن',
          });
        }

        /**
         * --------------------------------------------------------
         * 2. Validate Query Parameters
         * --------------------------------------------------------
         */
        const validationResult = getEventsQuerySchema.safeParse(
          request.query,
        );

        if (!validationResult.success) {
          return reply.code(400).send({
            success: false,
            message: 'معلمات الاستعلام غير صالحة',
            details: validationResult.error.format(),
          });
        }

        /**
         * --------------------------------------------------------
         * 3. Get Events
         * --------------------------------------------------------
         */
        const result = await eventsService.getEvents(
          fastify,
          organizationId,
          validationResult.data,
        );

        /**
         * --------------------------------------------------------
         * 4. Response
         * --------------------------------------------------------
         */
        return reply.code(200).send(result);
      } catch (error) {
        return handleRouteError(request, reply, error);
      }
    },
  );

  /**
   * ==============================================================
   * GET /api/events/:id
   * ==============================================================
   *
   * جلب Security Event واحد بالتفصيل.
   *
   * مهم:
   * الـEvent يجب أن يكون تابعًا لنفس organizationId
   * الموجود في JWT.
   */
  fastify.get(
    '/:id',
    {
      preHandler: fastify.authenticate,
    },

    async (
      request,
      reply: FastifyReply,
    ) => {
      try {
        /**
         * --------------------------------------------------------
         * 1. Get Organization ID
         * --------------------------------------------------------
         */
        const organizationId = getOrganizationId(request);

        if (!organizationId) {
          return reply.code(403).send({
            success: false,
            message: 'معرف المؤسسة غير موجود في التوكن',
          });
        }

        /**
         * --------------------------------------------------------
         * 2. Validate Event ID
         * --------------------------------------------------------
         */
        const validationResult = getEventByIdSchema.safeParse(
          request.params,
        );

        if (!validationResult.success) {
          return reply.code(400).send({
            success: false,
            message: 'معرف الـ Security Event غير صالح',
            details: validationResult.error.format(),
          });
        }

        /**
         * --------------------------------------------------------
         * 3. Get Event
         * --------------------------------------------------------
         */
        const event = await eventsService.getEventById(
          fastify,
          organizationId,
          validationResult.data.id,
        );

        /**
         * --------------------------------------------------------
         * 4. Event Not Found
         * --------------------------------------------------------
         */
        if (!event) {
          return reply.code(404).send({
            success: false,
            message:
              'الـ Security Event غير موجود أو ليس لديك صلاحية الوصول إليه',
          });
        }

        /**
         * --------------------------------------------------------
         * 5. Response
         * --------------------------------------------------------
         */
        return reply.code(200).send({
          success: true,
          data: event,
        });
      } catch (error) {
        return handleRouteError(request, reply, error);
      }
    },
  );
}
