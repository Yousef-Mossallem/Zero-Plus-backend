// backend/src/plugins/jwt.plugin.ts
// ==================================================================
// Zero Plus - JWT Plugin
// مسؤول عن المصادقة والتوكنات (لوحة التحكم فقط)
// الـ Gateway له plugin منفصل: gateway-auth.plugin.ts
//
// التوكن بعد Passkeys يحتوي:
//   id · email · role · organizationId · passkeyId? (اختياري)
// ==================================================================

import fp from 'fastify-plugin'
import fjwt from '@fastify/jwt'
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify'

// ------------------------------------------------------------------
// TypeScript Declaration Merging
// ------------------------------------------------------------------

declare module '@fastify/jwt' {
  interface FastifyJWT {
    /** الشكل اللي بيتحط جوه التوكن عند sign */
    payload: {
      id: string
      email: string
      role: string
      organizationId: string
      /** معرف صف PasskeyCredential المستخدم في هذا الدخول (اختياري) */
      passkeyId?: string
    }

    /** الشكل اللي بيظهر في request.user بعد jwtVerify */
    user: {
      id: string
      email: string
      role: string
      organizationId: string
      passkeyId?: string
    }
  }
}

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * يحمي الـ route — لازم توكن صالح
     * الاستخدام: preHandler: [fastify.authenticate]
     */
    authenticate: (
      request: FastifyRequest,
      reply: FastifyReply
    ) => Promise<void>

    /**
     * يفحص الدور بعد authenticate
     * الاستخدام: preHandler: [fastify.authenticate, fastify.requireRole(['OWNER', 'ADMIN'])]
     */
    requireRole: (
      roles: string[]
    ) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>
  }
}

// ------------------------------------------------------------------
// Plugin
// ------------------------------------------------------------------

const jwtPlugin: FastifyPluginAsync = async (fastify) => {
  const secret = process.env.JWT_SECRET

  if (!secret) {
    throw new Error('❌ JWT_SECRET is missing in environment variables')
  }

  await fastify.register(fjwt, {
    secret,
    sign: {
      // مناسب للـ MVP — للإنتاج ممكن تقصّرها + refresh tokens
      expiresIn: '7d',
    },
  })

  // ------------------------------------------------------------------
  // authenticate
  // ------------------------------------------------------------------

  fastify.decorate(
    'authenticate',
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        await request.jwtVerify()
      } catch {
        // return ضروري عشان الـ handler ما يكملش بعد الرد
        return reply.status(401).send({
          success: false,
          message: 'Unauthorized - Invalid or missing token',
        })
      }
    }
  )

  // ------------------------------------------------------------------
  // requireRole — يُستخدم بعد authenticate
  // ------------------------------------------------------------------

  fastify.decorate('requireRole', (roles: string[]) => {
    return async (request: FastifyRequest, reply: FastifyReply) => {
      if (!request.user || !roles.includes(request.user.role)) {
        return reply.status(403).send({
          success: false,
          message: 'ليس لديك صلاحية لتنفيذ هذا الإجراء',
        })
      }
    }
  })

  fastify.log.info('✅ JWT plugin registered successfully')
}

export default fp(jwtPlugin, {
  name: 'jwt',
})