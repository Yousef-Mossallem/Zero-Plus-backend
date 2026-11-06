// backend/src/modules/dashboard/dashboard.routes.ts
// ==================================================================
// Zero Plus - Dashboard Routes (Dashboard / JWT)
// ------------------------------------------------------------------
// prefix: /dashboard  (متسجل في app.ts)
//
//   GET /overview      ?range=24h&serverId=
//   GET /timeline      ?range=24h&serverId=
//   GET /top           ?by=path&range=24h&limit=10&serverId=
//   GET /servers
//   GET /threat-map    ?range=24h
//
// قواعد:
//   1) قراءة فقط — مفيش POST/PATCH/DELETE
//   2) organizationId من JWT فقط
//   3) الأدوار: OWNER | ADMIN | ANALYST  (مش VIEWER)
// ==================================================================

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { ZodError } from 'zod'

import {
  DashboardService,
  DashboardServiceError,
} from './dashboard.service.js'
import {
  overviewQuerySchema,
  timelineQuerySchema,
  topQuerySchema,
  threatMapQuerySchema,
} from './dashboard.schema.js'

const DASHBOARD_ROLES: string[] = ['OWNER', 'ADMIN', 'ANALYST']

// ==================================================================
// Helpers
// ==================================================================

function formatZodIssues(error: ZodError) {
  return error.issues.map((issue) => ({
    field: issue.path.map(String).join('.') || '(query)',
    message: issue.message,
  }))
}

function sendValidationError(
  reply: FastifyReply,
  message: string,
  error: ZodError,
) {
  return reply.status(400).send({
    success: false,
    code: 'VALIDATION_ERROR',
    message,
    errors: formatZodIssues(error),
  })
}

function handleRouteError(
  request: FastifyRequest,
  reply: FastifyReply,
  error: unknown,
) {
  if (error instanceof DashboardServiceError) {
    return reply.status(error.statusCode).send({
      success: false,
      code: error.code,
      message: error.message,
      ...(error.details !== undefined && { details: error.details }),
    })
  }

  request.log.error({ err: error }, 'Dashboard route error')

  return reply.status(500).send({
    success: false,
    code: 'INTERNAL_ERROR',
    message: 'Internal server error',
  })
}

// ==================================================================
// Routes
// ==================================================================

export async function dashboardRoutes(fastify: FastifyInstance) {
  const service = new DashboardService(fastify)

  const access = {
    preHandler: [
      fastify.authenticate,
      fastify.requireRole(DASHBOARD_ROLES),
    ],
  }

  // ================================================================
  // GET /dashboard/overview
  // ================================================================
  fastify.get('/overview', access, async (request, reply) => {
    const parsed = overviewQuerySchema.safeParse(request.query)

    if (!parsed.success) {
      return sendValidationError(
        reply,
        'معلمات الاستعلام غير صالحة',
        parsed.error,
      )
    }

    try {
      const { organizationId } = request.user
      const data = await service.getOverview(
        organizationId,
        parsed.data.range,
        parsed.data.serverId,
      )

      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /dashboard/timeline
  // ================================================================
  fastify.get('/timeline', access, async (request, reply) => {
    const parsed = timelineQuerySchema.safeParse(request.query)

    if (!parsed.success) {
      return sendValidationError(
        reply,
        'معلمات الاستعلام غير صالحة',
        parsed.error,
      )
    }

    try {
      const { organizationId } = request.user
      const data = await service.getTimeline(
        organizationId,
        parsed.data.range,
        parsed.data.serverId,
      )

      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /dashboard/top
  // ================================================================
  fastify.get('/top', access, async (request, reply) => {
    const parsed = topQuerySchema.safeParse(request.query)

    if (!parsed.success) {
      return sendValidationError(
        reply,
        'معلمات الاستعلام غير صالحة',
        parsed.error,
      )
    }

    try {
      const { organizationId } = request.user
      const data = await service.getTop(
        organizationId,
        parsed.data.by,
        parsed.data.range,
        parsed.data.limit,
        parsed.data.serverId,
      )

      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /dashboard/servers
  // ================================================================
  fastify.get('/servers', access, async (request, reply) => {
    try {
      const { organizationId } = request.user
      const data = await service.getServersSummary(organizationId)

      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /dashboard/threat-map
  // ================================================================
  fastify.get('/threat-map', access, async (request, reply) => {
    const parsed = threatMapQuerySchema.safeParse(request.query)

    if (!parsed.success) {
      return sendValidationError(
        reply,
        'معلمات الاستعلام غير صالحة',
        parsed.error,
      )
    }

    try {
      const { organizationId } = request.user
      const data = await service.getThreatMap(
        organizationId,
        parsed.data.range,
      )

      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })
}

export default dashboardRoutes