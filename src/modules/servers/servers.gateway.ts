// backend/src/modules/servers/servers.gateway.ts
// ==================================================================
// Zero Plus - Servers Gateway Routes (X-Gateway-Key)
// ------------------------------------------------------------------
// prefix: /internal/gateway  (متسجل في app.ts)
//
//   GET  /servers                  مزامنة كل السيرفرات (cursor + updatedSince)
//   GET  /servers/resolve?host=    سيرفر واحد من الـ Host
//   POST /servers/:id/health       الـ Gateway يبلّغ بصحة السيرفر
// ==================================================================

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { ZodError } from 'zod'

import { ServerServiceError, ServersService } from './servers.service.js'

import {
  gatewayHealthReportSchema,
  gatewayServerResolveQuerySchema,
  gatewayServersQuerySchema,
  serverIdParamsSchema,
} from './servers.schema.js'

function sendValidationError(
  reply: FastifyReply,
  message: string,
  error: ZodError,
) {
  return reply.status(400).send({
    success: false,
    code: 'VALIDATION_ERROR',
    message,
    errors: error.issues.map((issue) => ({
      field: issue.path.map(String).join('.') || '(body)',
      message: issue.message,
    })),
  })
}

function handleRouteError(
  request: FastifyRequest,
  reply: FastifyReply,
  error: unknown,
) {
  if (error instanceof ServerServiceError) {
    return reply.status(error.statusCode).send({
      success: false,
      code: error.code,
      message: error.message,
      ...(error.details !== undefined && { details: error.details }),
    })
  }

  request.log.error({ err: error }, 'Servers gateway route error')

  return reply.status(500).send({
    success: false,
    code: 'INTERNAL_ERROR',
    message: 'Internal server error',
  })
}

export async function serversInternalRoutes(fastify: FastifyInstance) {
  const service = new ServersService(fastify)

  const gateway = { preHandler: [fastify.authenticateGateway] }

  // الـ cache عند الـ Gateway نفسه، مش في HTTP
  fastify.addHook('onRequest', async (_request, reply) => {
    reply.header('Cache-Control', 'no-store')
  })

  // ================================================================
  // GET /internal/gateway/servers?limit=&cursor=&updatedSince=
  // ================================================================
  fastify.get('/servers', gateway, async (request, reply) => {
    const query = gatewayServersQuerySchema.safeParse(request.query)

    if (!query.success) {
      return sendValidationError(reply, 'معلمات المزامنة غير صالحة', query.error)
    }

    try {
      const data = await service.listForGateway(query.data)
      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // GET /internal/gateway/servers/resolve?host=shop.example.com
  // ================================================================
  fastify.get('/servers/resolve', gateway, async (request, reply) => {
    const query = gatewayServerResolveQuerySchema.safeParse(request.query)

    if (!query.success) {
      return sendValidationError(reply, 'host غير صالح', query.error)
    }

    try {
      const data = await service.resolveForGateway(query.data.host)
      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })

  // ================================================================
  // POST /internal/gateway/servers/:id/health
  // Body: { originReachable?, gatewayReachable?, avgResponseTimeMs?,
  //         currentLoadPercent?, lastError? }  (قيمة واحدة على الأقل)
  // ================================================================
  fastify.post('/servers/:id/health', gateway, async (request, reply) => {
    const params = serverIdParamsSchema.safeParse(request.params)

    if (!params.success) {
      return sendValidationError(reply, 'معرف السيرفر غير صالح', params.error)
    }

    const body = gatewayHealthReportSchema.safeParse(request.body)

    if (!body.success) {
      return sendValidationError(reply, 'تقرير الصحة غير صالح', body.error)
    }

    try {
      const data = await service.reportHealth(params.data.id, body.data)
      return reply.status(200).send({ success: true, data })
    } catch (error) {
      return handleRouteError(request, reply, error)
    }
  })
}

export default serversInternalRoutes