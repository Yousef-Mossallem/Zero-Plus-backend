// backend/src/modules/servers/servers.routes.ts
// ==================================================================
// Zero Plus - Servers Routes (Dashboard / JWT)
// ------------------------------------------------------------------
// prefix: /servers  (متسجل في app.ts)
//
//   POST   /                         إنشاء سيرفر + تعليمات DNS      (OWNER, ADMIN)
//   GET    /                         قائمة + فلاتر + pagination       (أي مستخدم)
//   GET    /:id                      تفاصيل سيرفر                     (أي مستخدم)
//   GET    /:id/dns                  تعليمات الـ DNS                  (أي مستخدم)
//   PATCH  /:id                      تعديل                            (OWNER, ADMIN)
//   POST   /:id/verify               فحص الـ DNS (ملكية / توجيه)      (OWNER, ADMIN)
//   POST   /:id/probe                إعادة قياس السعة (Origin Probe)  (OWNER, ADMIN)
//   POST   /:id/maintenance          تشغيل/إيقاف الصيانة              (OWNER, ADMIN)
//   DELETE /:id?confirmDomain=       حذف بتأكيد الدومين               (OWNER, ADMIN)
//
// قواعد:
//   1) organizationId بييجي من JWT فقط (مش من body/query/params)
//   2) السيرفر بيأثر على توجيه الترافيك، فالتعديل للـ OWNER/ADMIN فقط
//   3) كل الـ Validation بـ Zod، وكل أخطاء الـ Service بتتحول لـ HTTP هنا
// ==================================================================

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { ZodError } from 'zod'

import { ServerServiceError, ServersService } from './servers.service.js'

import {
  createServerSchema,
  deleteServerQuerySchema,
  listServersQuerySchema,
  maintenanceSchema,
  serverIdParamsSchema,
  updateServerSchema,
  verifyServerSchema,
} from './servers.schema.js'

const SERVER_MANAGE_ROLES: string[] = ['OWNER', 'ADMIN']

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
  if (error instanceof ServerServiceError) {
    // Retry-After للتحقق المتكرر / تبريد القياس
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

  request.log.error({ err: error }, 'Servers route error')

  return reply.status(500).send({
    success: false,
    code: 'INTERNAL_ERROR',
    message: 'Internal server error',
  })
}

// ==================================================================
// Routes
// ==================================================================

export async function serverRoutes(fastify: FastifyInstance) {
  const service = new ServersService(fastify)

  const manage = {
    preHandler: [
      fastify.authenticate,
      fastify.requireRole(SERVER_MANAGE_ROLES),
    ],
  }

  const read = { preHandler: [fastify.authenticate] }

  // ================================================================
  // POST /servers
  // Body: { domain, originIp, originPort?, sslEnabled?, mode? }
  // ================================================================
  fastify.post('/', manage, async (request, reply) => {
    const parsed = createServerSchema.safeParse(request.body)

    if (!parsed.success) {
      return sendValidationError(reply, 'بيانات السيرفر غير صالحة', parsed.error)
    }

    try {
      const { organizationId } = request.user

      const { server, dns } = await service.createServer(
        organizationId,
        parsed.data,
      )

      return reply.status(201).send({
        success: true,
        message: 'تم إضافة السيرفر. اتبع تعليمات الـ DNS لتفعيل الحماية',
        data: server,
        dns,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /servers?page=&limit=&status=&mode=&dnsVerified=&search=&sortBy=&sortOrder=
  // ================================================================
  fastify.get('/', read, async (request, reply) => {
    const parsed = listServersQuerySchema.safeParse(request.query)

    if (!parsed.success) {
      return sendValidationError(reply, 'معلمات الاستعلام غير صالحة', parsed.error)
    }

    try {
      const { organizationId } = request.user

      const result = await service.listServers(organizationId, parsed.data)

      return reply.status(200).send({
        success: true,
        data: result.servers,
        pagination: result.pagination,
        summary: result.summary,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /servers/:id
  // ================================================================
  fastify.get('/:id', read, async (request, reply) => {
    const params = serverIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف السيرفر غير صالح', params.error)
    }

    try {
      const { organizationId } = request.user

      const server = await service.getServerById(organizationId, params.data.id)

      return reply.status(200).send({ success: true, data: server })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /servers/:id/dns
  // ================================================================
  fastify.get('/:id/dns', read, async (request, reply) => {
    const params = serverIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف السيرفر غير صالح', params.error)
    }

    try {
      const { organizationId } = request.user

      const { server, dns } = await service.getDnsInstructions(
        organizationId,
        params.data.id,
      )

      return reply.status(200).send({
        success: true,
        data: {
          serverId: server.id,
          status: server.status,
          dnsVerified: server.dnsVerified,
          dnsVerifiedAt: server.dnsVerifiedAt,
          gatewayReachable: server.gatewayReachable,
        },
        dns,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // PATCH /servers/:id
  // Body (واحد على الأقل): { domain?, originIp?, originPort?, sslEnabled?, mode? }
  // ================================================================
  fastify.patch('/:id', manage, async (request, reply) => {
    const params = serverIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف السيرفر غير صالح', params.error)
    }

    const body = updateServerSchema.safeParse(request.body)

    if (!body.success) {
      return sendValidationError(reply, 'بيانات التعديل غير صالحة', body.error)
    }

    try {
      const { organizationId } = request.user

      const result = await service.updateServer(
        organizationId,
        params.data.id,
        body.data,
      )

      return reply.status(200).send({
        success: true,
        message:
          result.changes.length === 0
            ? 'لا يوجد تغيير: القيم المبعوتة مطابقة للحالية'
            : result.dns
              ? 'تم التعديل. الدومين اتغير فلازم تعيد التحقق بسجل TXT الجديد'
              : 'تم تعديل السيرفر',
        data: result.server,
        changes: result.changes,
        resets: result.resets,
        ...(result.dns && { dns: result.dns }),
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // POST /servers/:id/verify
  // Body (اختياري): { "step": "ownership" | "routing" | "all" }  (الافتراضي all)
  // ================================================================
  fastify.post('/:id/verify', manage, async (request, reply) => {
    const params = serverIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف السيرفر غير صالح', params.error)
    }

    const body = verifyServerSchema.safeParse(request.body ?? {})

    if (!body.success) {
      return sendValidationError(reply, 'بيانات التحقق غير صالحة', body.error)
    }

    try {
      const { organizationId } = request.user

      const result = await service.verifyServer(
        organizationId,
        params.data.id,
        body.data,
      )

      const ownershipOk = result.ownership?.verified ?? result.server.dnsVerified
      const routingOk = result.routing?.verified ?? result.server.gatewayReachable

      return reply.status(200).send({
        success: true,
        message:
          ownershipOk && routingOk
            ? 'تم التحقق: الدومين مملوك لك وموجّه للـ Gateway'
            : ownershipOk
              ? 'تم إثبات الملكية. الخطوة الجاية: وجّه الدومين للـ Gateway'
              : 'لم يتم التحقق بعد. راجع نتيجة الفحص',
        data: result,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // POST /servers/:id/probe
  // إعادة قياس السعة (Origin Probe) — OWNER, ADMIN
  // يرد 202 فورًا؛ النتيجة توصل عبر Socket بعد انتهاء القياس
  // ================================================================
  fastify.post('/:id/probe', manage, async (request, reply) => {
    const params = serverIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف السيرفر غير صالح', params.error)
    }

    try {
      await service.requestProbe(request.user.organizationId, params.data.id)

      return reply.status(202).send({
        success: true,
        message: 'تم بدء القياس. النتيجة هتوصل خلال دقيقتين تقريباً',
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // POST /servers/:id/maintenance
  // Body: { "enabled": true | false }
  // ================================================================
  fastify.post('/:id/maintenance', manage, async (request, reply) => {
    const params = serverIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف السيرفر غير صالح', params.error)
    }

    const body = maintenanceSchema.safeParse(request.body)

    if (!body.success) {
      return sendValidationError(
        reply,
        'enabled مطلوب (true أو false)',
        body.error,
      )
    }

    try {
      const { organizationId } = request.user

      const server = await service.setMaintenance(
        organizationId,
        params.data.id,
        body.data.enabled,
      )

      return reply.status(200).send({
        success: true,
        message: body.data.enabled
          ? 'تم تشغيل وضع الصيانة'
          : 'تم إيقاف وضع الصيانة',
        data: server,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // DELETE /servers/:id?confirmDomain=shop.example.com
  // ================================================================
  fastify.delete('/:id', manage, async (request, reply) => {
    const params = serverIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف السيرفر غير صالح', params.error)
    }

    const query = deleteServerQuerySchema.safeParse(request.query)

    if (!query.success) {
      return sendValidationError(
        reply,
        'confirmDomain مطلوب لتأكيد الحذف',
        query.error,
      )
    }

    try {
      const { organizationId } = request.user

      const result = await service.deleteServer(
        organizationId,
        params.data.id,
        query.data.confirmDomain,
      )

      return reply.status(200).send({
        success: true,
        message: 'تم حذف السيرفر',
        data: result,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })
}

export default serverRoutes