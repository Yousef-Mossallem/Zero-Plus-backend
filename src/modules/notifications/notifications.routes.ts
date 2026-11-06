// backend/src/modules/notifications/notifications.routes.ts
// ==================================================================
// Zero Plus - Notifications Routes
// كل الـ Endpoints الخاصة بإشعارات الداشبورد
// ==================================================================

import type {
  FastifyInstance,
  FastifyRequest,
  FastifyReply,
} from 'fastify'

import {
  listNotificationsQuerySchema,
  markAllReadBodySchema,
  notificationIdParamsSchema,
  unreadCountQuerySchema,
} from './notifications.schema.js'

import {
  NotificationServiceError,
  NotificationsService,
} from './notifications.service.js'

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function getOrganizationId(request: FastifyRequest): string {
  const orgId = request.user?.organizationId
  if (!orgId) {
    throw new NotificationServiceError(
      'Unauthorized',
      401,
      'UNAUTHORIZED',
    )
  }
  return orgId
}

function sendServiceError(
  error: unknown,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  if (error instanceof NotificationServiceError) {
    return reply.status(error.statusCode).send({
      success: false,
      message: error.message,
      code: error.code,
      ...(error.details !== undefined ? { details: error.details } : {}),
    })
  }

  request.log.error(error)
  return reply.status(500).send({
    success: false,
    message: 'Internal server error',
  })
}

// ------------------------------------------------------------------
// Routes
// ------------------------------------------------------------------

export async function notificationsRoutes(fastify: FastifyInstance) {
  const service = new NotificationsService(fastify)

  // ================================================================
  // GET /notifications
  // قائمة إشعارات الشركة + pagination + summary.unreadCount
  // ================================================================

  fastify.get(
    '/',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const organizationId = getOrganizationId(request)

        const parsed = listNotificationsQuerySchema.safeParse(
          request.query ?? {},
        )

        if (!parsed.success) {
          return reply.status(400).send({
            success: false,
            message: 'Invalid query parameters',
            errors: parsed.error.flatten(),
          })
        }

        const result = await service.list(organizationId, parsed.data)

        return reply.status(200).send({
          success: true,
          data: result.data,
          pagination: result.pagination,
          summary: result.summary,
        })
      } catch (error: unknown) {
        return sendServiceError(error, request, reply)
      }
    },
  )

  // ================================================================
  // GET /notifications/unread-count
  // عداد الجرس (خفيف)
  // ================================================================

  fastify.get(
    '/unread-count',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const organizationId = getOrganizationId(request)

        const parsed = unreadCountQuerySchema.safeParse(
          request.query ?? {},
        )

        if (!parsed.success) {
          return reply.status(400).send({
            success: false,
            message: 'Invalid query parameters',
            errors: parsed.error.flatten(),
          })
        }

        const result = await service.getUnreadCount(
          organizationId,
          parsed.data,
        )

        return reply.status(200).send({
          success: true,
          data: result,
        })
      } catch (error: unknown) {
        return sendServiceError(error, request, reply)
      }
    },
  )

  // ================================================================
  // GET /notifications/:id
  // ================================================================

  fastify.get(
    '/:id',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const organizationId = getOrganizationId(request)

        const params = notificationIdParamsSchema.safeParse(
          request.params,
        )

        if (!params.success) {
          return reply.status(400).send({
            success: false,
            message: 'Invalid notification id',
            errors: params.error.flatten(),
          })
        }

        const notification = await service.getById(
          organizationId,
          params.data.id,
        )

        return reply.status(200).send({
          success: true,
          data: notification,
        })
      } catch (error: unknown) {
        return sendServiceError(error, request, reply)
      }
    },
  )

  // ================================================================
  // POST /notifications/:id/read
  // تعليم إشعار واحد كمقروء
  // ================================================================

  fastify.post(
    '/:id/read',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const organizationId = getOrganizationId(request)

        const params = notificationIdParamsSchema.safeParse(
          request.params,
        )

        if (!params.success) {
          return reply.status(400).send({
            success: false,
            message: 'Invalid notification id',
            errors: params.error.flatten(),
          })
        }

        const result = await service.markRead(
          organizationId,
          params.data.id,
        )

        return reply.status(200).send({
          success: true,
          data: result,
        })
      } catch (error: unknown) {
        return sendServiceError(error, request, reply)
      }
    },
  )

  // ================================================================
  // POST /notifications/read-all
  // تعليم الكل (أو حسب types / minSeverity) كمقروء
  // ================================================================

  fastify.post(
    '/read-all',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const organizationId = getOrganizationId(request)

        const parsed = markAllReadBodySchema.safeParse(
          request.body ?? {},
        )

        if (!parsed.success) {
          return reply.status(400).send({
            success: false,
            message: 'Invalid body',
            errors: parsed.error.flatten(),
          })
        }

        const result = await service.markAllRead(
          organizationId,
          parsed.data,
        )

        return reply.status(200).send({
          success: true,
          data: result,
        })
      } catch (error: unknown) {
        return sendServiceError(error, request, reply)
      }
    },
  )

  // ================================================================
  // DELETE /notifications/:id
  // حذف إشعار (اختياري — مقيد بصلاحية أعلى لو حابب)
  // ================================================================

  fastify.delete(
    '/:id',
    {
      preHandler: [
        fastify.authenticate,
        // لو عندك requireRole:
        // fastify.requireRole(['OWNER', 'ADMIN']),
      ],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const organizationId = getOrganizationId(request)

        const params = notificationIdParamsSchema.safeParse(
          request.params,
        )

        if (!params.success) {
          return reply.status(400).send({
            success: false,
            message: 'Invalid notification id',
            errors: params.error.flatten(),
          })
        }

        const result = await service.delete(
          organizationId,
          params.data.id,
        )

        return reply.status(200).send({
          success: true,
          data: result,
        })
      } catch (error: unknown) {
        return sendServiceError(error, request, reply)
      }
    },
  )
}

export default notificationsRoutes