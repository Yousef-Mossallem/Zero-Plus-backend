// backend/src/modules/reports/reports.routes.ts
// ==================================================================
// Zero Plus - Reports Routes (Dashboard / JWT)
// ------------------------------------------------------------------
// prefix: /reports  (متسجل في app.ts)
//
//   POST   /                 إنشاء تقرير → 201 (PENDING + توليد بالخلفية)
//   GET    /                 قائمة + فلاتر + pagination
//   GET    /:id              تفاصيل تقرير (content كامل)
//   DELETE /:id              حذف                              (OWNER, ADMIN)
//   POST   /chat             محادثة Gemini
//
// قواعد:
//   1) organizationId من JWT فقط
//   2) الحذف للـ OWNER/ADMIN فقط
//   3) الإنشاء والقراءة والـ chat لأي مستخدم مصادَق (عدّل الأدوار لو حابب)
// ==================================================================

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { ZodError } from 'zod'

import { ReportServiceError, ReportsService } from './reports.service.js'
import {
  chatSchema,
  createReportSchema,
  listReportsQuerySchema,
  reportIdParamsSchema,
} from './reports.schema.js'

const REPORT_MANAGE_ROLES: string[] = ['OWNER', 'ADMIN']

// ==================================================================
// Helpers
// ==================================================================

function formatZodIssues(error: ZodError) {
  return error.issues.map((issue) => ({
    field: issue.path.map(String).join('.') || '(body)',
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
  if (error instanceof ReportServiceError) {
    if (error.statusCode === 429) {
      const retry = (error.details as { retryAfterSec?: number } | undefined)
        ?.retryAfterSec
      if (retry) reply.header('Retry-After', String(retry))
    }

    return reply.status(error.statusCode).send({
      success: false,
      code: error.code,
      message: error.message,
      ...(error.details !== undefined && { details: error.details }),
    })
  }

  request.log.error({ err: error }, 'Reports route error')

  return reply.status(500).send({
    success: false,
    code: 'INTERNAL_ERROR',
    message: 'Internal server error',
  })
}

// ==================================================================
// Routes
// ==================================================================

export async function reportRoutes(fastify: FastifyInstance) {
  const service = new ReportsService(fastify)

  const auth = { preHandler: [fastify.authenticate] }

  const manage = {
    preHandler: [
      fastify.authenticate,
      fastify.requireRole(REPORT_MANAGE_ROLES),
    ],
  }

  // ================================================================
  // POST /reports
  // Body: { type, periodStart, periodEnd, serverId?, title?, securityEventId? }
  // ================================================================
  fastify.post('/', auth, async (request, reply) => {
    const parsed = createReportSchema.safeParse(request.body)

    if (!parsed.success) {
      return sendValidationError(reply, 'بيانات التقرير غير صالحة', parsed.error)
    }

    try {
      const { organizationId } = request.user
      const report = await service.createReport(organizationId, parsed.data)

      return reply.status(201).send({
        success: true,
        message:
          'تم إنشاء التقرير وهو قيد التوليد. ستصلك نتيجة عند الانتهاء.',
        data: {
          id: report.id,
          title: report.title,
          type: report.type,
          status: report.status,
          periodStart: report.periodStart,
          periodEnd: report.periodEnd,
          serverId: report.serverId,
          createdAt: report.createdAt,
        },
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /reports
  // ================================================================
  fastify.get('/', auth, async (request, reply) => {
    const parsed = listReportsQuerySchema.safeParse(request.query)

    if (!parsed.success) {
      return sendValidationError(
        reply,
        'معلمات الاستعلام غير صالحة',
        parsed.error,
      )
    }

    try {
      const { organizationId } = request.user
      const result = await service.getReports(organizationId, parsed.data)

      return reply.status(200).send({
        success: true,
        data: result.reports,
        pagination: result.pagination,
        summary: result.summary,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // POST /reports/chat
  // مهم: قبل /:id عشان "chat" متتتفسرش كـ id
  // Body: { message, messages?, includeContext?, serverId? }
  // ================================================================
  fastify.post('/chat', auth, async (request, reply) => {
    const parsed = chatSchema.safeParse(request.body)

    if (!parsed.success) {
      return sendValidationError(reply, 'بيانات المحادثة غير صالحة', parsed.error)
    }

    try {
      const { organizationId } = request.user
      const result = await service.chat(organizationId, parsed.data)

      return reply.status(200).send({
        success: true,
        data: {
          reply: result.reply,
          model: result.model,
          tokensUsed: result.tokensUsed,
        },
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /reports/:id
  // ================================================================
  fastify.get('/:id', auth, async (request, reply) => {
    const params = reportIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف التقرير غير صالح', params.error)
    }

    try {
      const { organizationId } = request.user
      const report = await service.getReportById(
        organizationId,
        params.data.id,
      )

      return reply.status(200).send({
        success: true,
        data: report,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // DELETE /reports/:id  (OWNER, ADMIN)
  // ================================================================
  fastify.delete('/:id', manage, async (request, reply) => {
    const params = reportIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف التقرير غير صالح', params.error)
    }

    try {
      const { organizationId } = request.user
      const result = await service.deleteReport(
        organizationId,
        params.data.id,
      )

      return reply.status(200).send({
        success: true,
        message: 'تم حذف التقرير',
        data: result,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })
}

export default reportRoutes