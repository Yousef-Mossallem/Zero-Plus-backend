// backend/src/modules/reputation/reputation.routes.ts
// ==================================================================
// Zero Plus - Reputation Routes
// ------------------------------------------------------------------
// Dashboard (JWT) → prefix: /reputation
//   GET   /                      قائمة + فلاتر + pagination           (أي مستخدم)
//   GET   /stats                 ملخص (حسب الحظر والتصنيف اللوني)      (أي مستخدم)
//   GET   /:id                   تفاصيل سجل                           (أي مستخدم)
//   GET   /:id/challenges        سجل الاختبارات                        (أي مستخدم)
//   POST  /:id/ban               حظر يدوي                              (OWNER, ADMIN, ANALYST)
//   POST  /:id/unban             رفع الحظر                             (OWNER, ADMIN, ANALYST)
//   POST  /:id/allowlist         جهاز موثوق                            (OWNER, ADMIN, ANALYST)
//   POST  /:id/reset             تصفير السمعة                          (OWNER, ADMIN, ANALYST)
//
// Gateway (x-gateway-key) → prefix: /internal/gateway
//   GET   /reputation/lookup       الاستعلام قبل القرار
//   POST  /reputation/apply        تسجيل أدلة تقرير واحد
//   POST  /reputation/apply-batch  دفعة تقارير
//   GET   /reputation/bans         مزامنة الحظر (للـ Redis)
//
// قواعد:
//   1) organizationId في الـ Dashboard بييجي من JWT فقط (مش من body/query/params)
//   2) الـ Gateway بيبعت organizationId اللي حدده من الـ Host (servers/resolve)،
//      والـ Service بيتأكد إنه موجود ونشط، وإن serverId تابع له
//   3) كل الـ Validation بـ Zod (safeParse)، وأخطاء الـ Service بتتحول لـ HTTP هنا
//   4) ردود الـ Gateway بـ Cache-Control: no-store
//
// تسجيل في app.ts:
//   await app.register(reputationRoutes,         { prefix: '/reputation' })
//   await app.register(reputationInternalRoutes, { prefix: '/internal/gateway' })
// ==================================================================

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { ZodError } from 'zod'

import {
  ReputationService,
  ReputationServiceError,
} from './reputation.service.js'

import type { ReputationActor } from './reputation.service.js'

import {
  allowlistBodySchema,
  applyReputationBatchBodySchema,
  applyReputationBodySchema,
  gatewayBansQuerySchema,
  listReputationQuerySchema,
  lookupReputationQuerySchema,
  manualBanBodySchema,
  reputationChallengesQuerySchema,
  reputationIdParamsSchema,
  resetReputationBodySchema,
  unbanBodySchema,
} from './reputation.schema.js'

// ------------------------------------------------------------------
// الأدوار المسموح لها بالإجراءات اليدوية (VIEWER مشاهدة فقط)
// ------------------------------------------------------------------
const REPUTATION_ACTION_ROLES: string[] = ['OWNER', 'ADMIN', 'ANALYST']

// دفعة الـ Gateway لحد 200 تقرير، فنرفع حد الـ body لـ 2MB على الراوت ده بس
const BATCH_BODY_LIMIT = 2 * 1024 * 1024

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
 *  - ReputationServiceError → نفس الـ status والـ code والتفاصيل
 *  - غير كده → 500 من غير تسريب تفاصيل داخلية
 */
function handleRouteError(
  request: FastifyRequest,
  reply: FastifyReply,
  error: unknown,
) {
  if (error instanceof ReputationServiceError) {
    return reply.status(error.statusCode).send({
      success: false,
      code: error.code,
      message: error.message,
      ...(error.details !== undefined && { details: error.details }),
    })
  }

  request.log.error({ err: error }, 'Reputation route error')

  return reply.status(500).send({
    success: false,
    code: 'INTERNAL_ERROR',
    message: 'Internal server error',
  })
}

/** مين عمل الإجراء (من الـ JWT) */
function getActor(request: FastifyRequest): ReputationActor {
  return { userId: request.user.id, email: request.user.email }
}

// ==================================================================
// DASHBOARD ROUTES (JWT)
// ==================================================================

export async function reputationRoutes(fastify: FastifyInstance) {
  const service = new ReputationService(fastify)

  const read = { preHandler: [fastify.authenticate] }

  const act = {
    preHandler: [
      fastify.authenticate,
      fastify.requireRole(REPUTATION_ACTION_ROLES),
    ],
  }

  // ================================================================
  // GET /reputation
  // ?page=&limit=&banStatus=&ipType=&countryCode=&asn=&minScore=&maxScore=
  //  &isAllowlisted=&isManualBan=&isKnownBotnet=&search=
  //  &lastSeenAfter=&lastSeenBefore=&sortBy=&sortOrder=
  // ================================================================
  fastify.get('/', read, async (request, reply) => {
    const query = listReputationQuerySchema.safeParse(request.query)

    if (!query.success) {
      return sendValidationError(reply, 'معلمات الاستعلام غير صالحة', query.error)
    }

    try {
      const { organizationId } = request.user

      const result = await service.list(organizationId, query.data)

      return reply.status(200).send({
        success: true,
        data: result.data,
        pagination: result.pagination,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /reputation/stats
  // لازم قبل /:id (Fastify بيقدّم المسار الثابت، بس بنوضحها للقارئ)
  // ================================================================
  fastify.get('/stats', read, async (request, reply) => {
    try {
      const { organizationId } = request.user

      const data = await service.getStats(organizationId)

      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /reputation/:id
  // ================================================================
  fastify.get('/:id', read, async (request, reply) => {
    const params = reputationIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف سجل السمعة غير صالح', params.error)
    }

    try {
      const { organizationId } = request.user

      const data = await service.getById(organizationId, params.data.id)

      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /reputation/:id/challenges?page=&limit=&passed=
  // ================================================================
  fastify.get('/:id/challenges', read, async (request, reply) => {
    const params = reputationIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف سجل السمعة غير صالح', params.error)
    }

    const query = reputationChallengesQuerySchema.safeParse(request.query)

    if (!query.success) {
      return sendValidationError(reply, 'معلمات الاستعلام غير صالحة', query.error)
    }

    try {
      const { organizationId } = request.user

      const result = await service.listChallenges(
        organizationId,
        params.data.id,
        query.data,
      )

      return reply.status(200).send({
        success: true,
        data: result.data,
        pagination: result.pagination,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // POST /reputation/:id/ban
  // Body: { "type": "TEMPORARY", "minutes": 120, "reason": "..." }
  //       { "type": "PERMANENT", "reason": "..." }
  // ================================================================
  fastify.post('/:id/ban', act, async (request, reply) => {
    const params = reputationIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف سجل السمعة غير صالح', params.error)
    }

    const body = manualBanBodySchema.safeParse(request.body)

    if (!body.success) {
      return sendValidationError(reply, 'بيانات الحظر غير صالحة', body.error)
    }

    try {
      const { organizationId } = request.user

      const { entry } = await service.manualBan(
        organizationId,
        params.data.id,
        body.data,
        getActor(request),
      )

      return reply.status(200).send({
        success: true,
        message:
          body.data.type === 'PERMANENT'
            ? 'تم الحظر الدائم'
            : `تم الحظر لمدة ${body.data.minutes} دقيقة`,
        data: entry,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // POST /reputation/:id/unban
  // Body (اختياري): { "reason": "...", "resetScore": true }
  // ================================================================
  fastify.post('/:id/unban', act, async (request, reply) => {
    const params = reputationIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف سجل السمعة غير صالح', params.error)
    }

    const body = unbanBodySchema.safeParse(request.body ?? {})

    if (!body.success) {
      return sendValidationError(reply, 'بيانات رفع الحظر غير صالحة', body.error)
    }

    try {
      const { organizationId } = request.user

      const { entry, changed } = await service.unban(
        organizationId,
        params.data.id,
        body.data,
        getActor(request),
      )

      return reply.status(200).send({
        success: true,
        message: changed
          ? 'تم رفع الحظر'
          : 'لا يوجد حظر على هذا السجل (ما اتغيرش شيء)',
        data: entry,
        changed,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // POST /reputation/:id/allowlist
  // Body: { "enabled": true, "reason": "..." }
  // التفعيل بيرفع الحظر الحالي وبيمنع أي حظر جاي
  // ================================================================
  fastify.post('/:id/allowlist', act, async (request, reply) => {
    const params = reputationIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف سجل السمعة غير صالح', params.error)
    }

    const body = allowlistBodySchema.safeParse(request.body)

    if (!body.success) {
      return sendValidationError(reply, 'enabled مطلوب (true أو false)', body.error)
    }

    try {
      const { organizationId } = request.user

      const { entry, changed } = await service.setAllowlist(
        organizationId,
        params.data.id,
        body.data,
        getActor(request),
      )

      return reply.status(200).send({
        success: true,
        message: !changed
          ? 'الحالة المطلوبة موجودة بالفعل (ما اتغيرش شيء)'
          : body.data.enabled
            ? 'تم توثيق الجهاز'
            : 'تم إلغاء توثيق الجهاز',
        data: entry,
        changed,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // POST /reputation/:id/reset
  // Body: { "confirm": true, "reason": "..." }
  // ================================================================
  fastify.post('/:id/reset', act, async (request, reply) => {
    const params = reputationIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف سجل السمعة غير صالح', params.error)
    }

    const body = resetReputationBodySchema.safeParse(request.body)

    if (!body.success) {
      return sendValidationError(
        reply,
        'بيانات التصفير غير صالحة (confirm: true مطلوب)',
        body.error,
      )
    }

    try {
      const { organizationId } = request.user

      const { entry } = await service.resetReputation(
        organizationId,
        params.data.id,
        body.data,
        getActor(request),
      )

      return reply.status(200).send({
        success: true,
        message: 'تم تصفير السمعة ورفع الحظر',
        data: entry,
      })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })
}

// ==================================================================
// GATEWAY ROUTES (x-gateway-key)
// ==================================================================

export async function reputationInternalRoutes(fastify: FastifyInstance) {
  const service = new ReputationService(fastify)

  const gateway = { preHandler: [fastify.authenticateGateway] }

  // الـ cache عند الـ Gateway نفسه، مش في HTTP
  fastify.addHook('onRequest', async (_request, reply) => {
    reply.header('Cache-Control', 'no-store')
  })

  // ================================================================
  // GET /internal/gateway/reputation/lookup
  // ?organizationId=&ipAddress=&deviceFingerprint=&ja3Fingerprint=&ja4Fingerprint=
  // قبل القرار: هل المصدر محظور؟ سمعته كام؟
  // ================================================================
  fastify.get('/reputation/lookup', gateway, async (request, reply) => {
    const query = lookupReputationQuerySchema.safeParse(request.query)

    if (!query.success) {
      return sendValidationError(reply, 'معلمات الاستعلام غير صالحة', query.error)
    }

    try {
      const data = await service.lookup(query.data)

      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // POST /internal/gateway/reputation/apply
  // Body: { organizationId, serverId?, ipAddress, signals[], challenge?, requestCount, ... }
  // ================================================================
  fastify.post('/reputation/apply', gateway, async (request, reply) => {
    const body = applyReputationBodySchema.safeParse(request.body)

    if (!body.success) {
      return sendValidationError(reply, 'تقرير السمعة غير صالح', body.error)
    }

    try {
      const data = await service.apply(body.data)

      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // POST /internal/gateway/reputation/apply-batch
  // Body: { reports: [ ...نفس body الـ apply... ] }  (من 1 لـ 200)
  // الرد 200 دايمًا، ونتيجة كل تقرير في results[index] (ok / code / message)
  // ================================================================
  fastify.post(
    '/reputation/apply-batch',
    { ...gateway, bodyLimit: BATCH_BODY_LIMIT },
    async (request, reply) => {
      const body = applyReputationBatchBodySchema.safeParse(request.body)

      if (!body.success) {
        return sendValidationError(reply, 'دفعة التقارير غير صالحة', body.error)
      }

      try {
        const data = await service.applyBatch(body.data)

        return reply.status(200).send({ success: true, data })
      } catch (error) {
        return handleRouteError(request, reply, error)
      }
    },
  )

  // ================================================================
  // GET /internal/gateway/reputation/bans
  // ?limit=&cursor=&updatedSince=&organizationId=
  // ================================================================
  fastify.get('/reputation/bans', gateway, async (request, reply) => {
    const query = gatewayBansQuerySchema.safeParse(request.query)

    if (!query.success) {
      return sendValidationError(reply, 'معلمات المزامنة غير صالحة', query.error)
    }

    try {
      const data = await service.listBansForGateway(query.data)

      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })
}

export default reputationRoutes