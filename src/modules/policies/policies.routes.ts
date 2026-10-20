// backend/src/modules/policies/policies.routes.ts
// ==================================================================
// Zero Plus - Policies Routes
// ------------------------------------------------------------------
// Dashboard (JWT)  → prefix: /api/policies
//   GET   /defaults          القيم الافتراضية (أي مستخدم)
//   GET   /me                Policy شركتي (أي مستخدم)
//   PATCH /me                تعديل (OWNER / ADMIN / ANALYST)
//   POST  /me/reset          رجوع للافتراضي (OWNER / ADMIN / ANALYST)
//
// Gateway (X-Gateway-Key) → prefix: /internal/gateway
//   GET /policies/resolve?host=shop.example.com    ⭐ الأساسي
//   GET /policies/by-server/:serverId
//   GET /policies/by-org/:organizationId
//   GET /policies/version/:organizationId          (رد خفيف للـ cache)
//
// قواعد:
//   1) organizationId في الـ Dashboard بييجي من JWT فقط (مش من body/query)
//   2) الـ Gateway بيحدد الشركة من Host أو serverId
//   3) كل الـ Validation بـ Zod، وكل أخطاء الـ Service بتتحول لـ HTTP هنا
//   4) كل ردود الـ Gateway بـ Cache-Control: no-store
//
// تسجيل في app.ts:
//   await app.register(policiesRoutes,         { prefix: '/api/policies' })
//   await app.register(policiesInternalRoutes, { prefix: '/internal/gateway' })
// ==================================================================

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { ZodError } from 'zod'

import { PoliciesService, PolicyServiceError } from './policies.service.js'

import {
  gatewayPolicyByOrgParamsSchema,
  gatewayPolicyByServerParamsSchema,
  gatewayResolveQuerySchema,
  resetPolicySchema,
  updatePolicySchema,
} from './policies.schema.js'

// ------------------------------------------------------------------
// الأدوار المسموح لها بتعديل الـ Policy (VIEWER مشاهدة فقط)
// ------------------------------------------------------------------
const POLICY_EDIT_ROLES: string[] = ['OWNER', 'ADMIN', 'ANALYST']

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

/**
 * تحويل أي خطأ لرد HTTP منظم:
 *  - PolicyServiceError → نفس الـ status والـ code والتفاصيل
 *  - غير كده → 500 من غير تسريب تفاصيل داخلية
 */
function handleRouteError(
  request: FastifyRequest,
  reply: FastifyReply,
  error: unknown,
) {
  if (error instanceof PolicyServiceError) {
    return reply.status(error.statusCode).send({
      success: false,
      code: error.code,
      message: error.message,
      ...(error.details !== undefined && { details: error.details }),
    })
  }

  request.log.error({ err: error }, 'Policies route error')

  return reply.status(500).send({
    success: false,
    code: 'INTERNAL_ERROR',
    message: 'Internal server error',
  })
}

// ==================================================================
// DASHBOARD ROUTES  (JWT)
// ==================================================================

async function policiesRoutes(fastify: FastifyInstance) {
  const service = new PoliciesService(fastify)

  // ================================================================
  // GET /api/policies/defaults
  // ================================================================
  fastify.get(
    '/defaults',
    { preHandler: [fastify.authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        return reply.status(200).send({
          success: true,
          data: service.getDefaults(),
        })
      } catch (error) {
        return handleRouteError(request, reply, error)
      }
    },
  )

  // ================================================================
  // GET /api/policies/me
  // ================================================================
  fastify.get(
    '/me',
    { preHandler: [fastify.authenticate] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        // organizationId من الـ JWT فقط
        const { organizationId } = request.user

        const policy = await service.getPolicyByOrganization(organizationId)

        return reply.status(200).send({
          success: true,
          data: policy,
        })
      } catch (error) {
        return handleRouteError(request, reply, error)
      }
    },
  )

  // ================================================================
  // PATCH /api/policies/me
  // ================================================================
  fastify.patch(
    '/me',
    {
      preHandler: [
        fastify.authenticate,
        fastify.requireRole(POLICY_EDIT_ROLES),
      ],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = updatePolicySchema.safeParse(request.body)

      if (!parsed.success) {
        return sendValidationError(
          reply,
          'بيانات تعديل الـ Policy غير صالحة',
          parsed.error,
        )
      }

      try {
        const { organizationId, id: userId, email } = request.user

        const { policy, changes } = await service.updatePolicy(
          organizationId,
          parsed.data,
          { userId, email },
        )

        return reply.status(200).send({
          success: true,
          message:
            changes.length > 0
              ? 'تم تحديث إعدادات الحماية'
              : 'لا يوجد تغيير: القيم المبعوتة مطابقة للإعدادات الحالية',
          data: policy,
          changes,
        })
      } catch (error) {
        return handleRouteError(request, reply, error)
      }
    },
  )

  // ================================================================
  // POST /api/policies/me/reset
  // body: { "confirm": true }
  // body: { "confirm": true, "fields": ["temporaryBanMinutes", ...] }
  // ================================================================
  fastify.post(
    '/me/reset',
    {
      preHandler: [
        fastify.authenticate,
        fastify.requireRole(POLICY_EDIT_ROLES),
      ],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = resetPolicySchema.safeParse(request.body)

      if (!parsed.success) {
        return sendValidationError(
          reply,
          'بيانات إعادة الضبط غير صالحة (confirm: true مطلوب)',
          parsed.error,
        )
      }

      try {
        const { organizationId, id: userId, email } = request.user

        const { policy, changes } = await service.resetPolicy(
          organizationId,
          parsed.data,
          { userId, email },
        )

        return reply.status(200).send({
          success: true,
          message:
            changes.length > 0
              ? 'تمت إعادة الإعدادات للقيم الافتراضية'
              : 'الإعدادات المطلوبة مطابقة للافتراضي بالفعل',
          data: policy,
          changes,
        })
      } catch (error) {
        return handleRouteError(request, reply, error)
      }
    },
  )
}

// ==================================================================
// GATEWAY ROUTES  (X-Gateway-Key)
// ==================================================================

async function policiesInternalRoutes(fastify: FastifyInstance) {
  const service = new PoliciesService(fastify)

  // الـ Gateway لازم دايمًا ياخد أحدث نسخة (الـ cache عنده هو، مش في HTTP)
  fastify.addHook('onRequest', async (_request, reply) => {
    reply.header('Cache-Control', 'no-store')
  })

  // ================================================================
  // GET /internal/gateway/policies/resolve?host=shop.example.com
  // ⭐ من الـ Host → السيرفر + الشركة + الـ Policy في رد واحد
  // ================================================================
  fastify.get(
    '/policies/resolve',
    { preHandler: [fastify.authenticateGateway] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = gatewayResolveQuerySchema.safeParse(request.query)

      if (!parsed.success) {
        return sendValidationError(reply, 'host غير صالح', parsed.error)
      }

      try {
        const data = await service.resolveByHost(parsed.data.host)
        return reply.status(200).send({ success: true, data })
      } catch (error) {
        return handleRouteError(request, reply, error)
      }
    },
  )

  // ================================================================
  // GET /internal/gateway/policies/by-server/:serverId
  // ================================================================
  fastify.get(
    '/policies/by-server/:serverId',
    { preHandler: [fastify.authenticateGateway] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = gatewayPolicyByServerParamsSchema.safeParse(request.params)

      if (!parsed.success) {
        return sendValidationError(reply, 'serverId غير صالح', parsed.error)
      }

      try {
        const data = await service.resolveByServerId(parsed.data.serverId)
        return reply.status(200).send({ success: true, data })
      } catch (error) {
        return handleRouteError(request, reply, error)
      }
    },
  )

  // ================================================================
  // GET /internal/gateway/policies/by-org/:organizationId
  // (الـ Policy فقط، من غير بيانات سيرفر)
  // ================================================================
  fastify.get(
    '/policies/by-org/:organizationId',
    { preHandler: [fastify.authenticateGateway] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = gatewayPolicyByOrgParamsSchema.safeParse(request.params)

      if (!parsed.success) {
        return sendValidationError(
          reply,
          'organizationId غير صالح',
          parsed.error,
        )
      }

      try {
        const data = await service.getGatewayPolicy(parsed.data.organizationId)
        return reply.status(200).send({ success: true, data })
      } catch (error) {
        return handleRouteError(request, reply, error)
      }
    },
  )

  // ================================================================
  // GET /internal/gateway/policies/version/:organizationId
  // رد خفيف: الـ Gateway يسأل عنه كل شوية، ولو policyVersion اتغيرت
  // يطلب resolve كامل
  // ================================================================
  fastify.get(
    '/policies/version/:organizationId',
    { preHandler: [fastify.authenticateGateway] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = gatewayPolicyByOrgParamsSchema.safeParse(request.params)

      if (!parsed.success) {
        return sendValidationError(
          reply,
          'organizationId غير صالح',
          parsed.error,
        )
      }

      try {
        const data = await service.getPolicyVersion(parsed.data.organizationId)
        return reply.status(200).send({ success: true, data })
      } catch (error) {
        return handleRouteError(request, reply, error)
      }
    },
  )
}

export default policiesRoutes
export { policiesRoutes, policiesInternalRoutes }