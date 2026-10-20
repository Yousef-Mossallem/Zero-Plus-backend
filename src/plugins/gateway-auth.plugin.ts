// backend/src/plugins/gateway-auth.plugin.ts
// ==================================================================
// Zero Plus - Gateway Auth Plugin
// الـ Gateway بيثبت هويته للـ Backend بالـ Header:
//   X-Gateway-Key: <GATEWAY_SECRET>
//
// الاستخدام في أي route داخلي:
//   fastify.get('/x', { preHandler: [fastify.authenticateGateway] }, handler)
// ==================================================================

import fp from 'fastify-plugin'
import { timingSafeEqual } from 'node:crypto'
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'

declare module 'fastify' {
  interface FastifyInstance {
    authenticateGateway: (
      request: FastifyRequest,
      reply: FastifyReply
    ) => Promise<void>
  }
}

async function gatewayAuthPlugin(fastify: FastifyInstance) {
  const secret = process.env.GATEWAY_SECRET

  // نوقف السيرفر من أول لحظة لو المفتاح ناقص أو ضعيف،
  // بدل ما الـ Gateway يفضل ياخد 500 من غير ما حد يلاحظ
  if (!secret || secret.length < 32) {
    throw new Error(
      '❌ GATEWAY_SECRET is missing or too short (min 32 chars). ' +
        'Generate one with: openssl rand -hex 32'
    )
  }

  const expected = Buffer.from(secret)

  fastify.decorate(
    'authenticateGateway',
    async (request: FastifyRequest, reply: FastifyReply) => {
      const header = request.headers['x-gateway-key']

      if (!header || typeof header !== 'string') {
        return reply.status(401).send({
          success: false,
          message: 'Missing X-Gateway-Key header',
        })
      }

      // مقارنة ثابتة الزمن: تمنع تسريب معلومات عن المفتاح من توقيت الرد
      const provided = Buffer.from(header)
      const valid =
        provided.length === expected.length &&
        timingSafeEqual(provided, expected)

      if (!valid) {
        request.log.warn({ ip: request.ip }, 'Invalid Gateway key attempt')
        return reply.status(403).send({
          success: false,
          message: 'Invalid Gateway key',
        })
      }
    }
  )

  fastify.log.info('✅ Gateway auth plugin registered successfully')
}

export default fp(gatewayAuthPlugin, { name: 'gateway-auth-plugin' })