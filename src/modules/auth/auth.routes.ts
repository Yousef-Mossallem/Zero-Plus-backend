// ==================================================================
// Zero Plus - Auth Routes
// WebAuthn / Passkeys (بصمة إصبع أو وجه)
// ==================================================================

import type {
  FastifyInstance,
  FastifyRequest,
  FastifyReply,
} from 'fastify'

import {
  registerStartSchema,
  registerFinishSchema,
  loginStartSchema,
  loginFinishSchema,
  addPasskeyFinishSchema,
  revokePasskeySchema,
  updateProfileSchema,
  setPasswordSchema,
} from './auth.schema.js'

import {
  registerStart,
  registerFinish,
  loginStart,
  loginFinish,
  addPasskeyStart,
  addPasskeyFinish,
  revokePasskey,
  listPasskeys,
  getMe,
  updateProfile,
  setPassword,
} from './auth.service.js'

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function isZodError(
  error: unknown
): error is { name: string; issues: unknown[] } {
  return (
    !!error &&
    typeof error === 'object' &&
    'name' in error &&
    (error as { name: string }).name === 'ZodError'
  )
}

function sendZodError(reply: FastifyReply, error: { issues: unknown[] }) {
  return reply.status(400).send({
    success: false,
    message: 'Validation failed',
    errors: error.issues,
  })
}

function mapAuthError(
  message: string
): { status: number; message: string } | null {
  const table: Record<string, { status: number; message: string }> = {
    EMAIL_ALREADY_EXISTS: {
      status: 409,
      message: 'Email is already registered',
    },
    PASSKEY_ALREADY_REGISTERED: {
      status: 409,
      message: 'This passkey is already registered',
    },
    CHALLENGE_EXPIRED: {
      status: 400,
      message: 'Challenge expired — please try again',
    },
    WEBAUTHN_VERIFICATION_FAILED: {
      status: 401,
      message: 'Biometric verification failed',
    },
    INVALID_CREDENTIALS: {
      status: 401,
      message: 'Invalid credentials',
    },
    ACCOUNT_DISABLED: {
      status: 401,
      message: 'Your account has been disabled',
    },
    ORGANIZATION_DISABLED: {
      status: 401,
      message: 'Your organization has been disabled',
    },
    PASSKEY_NOT_FOUND: {
      status: 404,
      message: 'Passkey not found',
    },
    CANNOT_REVOKE_LAST_PASSKEY: {
      status: 400,
      message: 'Cannot revoke your last passkey',
    },
    USER_NOT_FOUND: {
      status: 404,
      message: 'User not found',
    },
  }
  return table[message] ?? null
}

async function handleError(
  error: unknown,
  request: FastifyRequest,
  reply: FastifyReply
) {
  if (error instanceof Error) {
    const mapped = mapAuthError(error.message)
    if (mapped) {
      return reply.status(mapped.status).send({
        success: false,
        message: mapped.message,
      })
    }
  }

  if (isZodError(error)) {
    return sendZodError(reply, error)
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

export async function authRoutes(fastify: FastifyInstance) {
  // ================================================================
  // POST /auth/register/start
  // بيانات الشركة + المستخدم → WebAuthn registration options
  // ================================================================

  fastify.post(
    '/register/start',
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = registerStartSchema.parse(request.body)
        const result = await registerStart(fastify, body)

        return reply.status(200).send({
          success: true,
          data: result,
        })
      } catch (error: unknown) {
        return handleError(error, request, reply)
      }
    }
  )

  // ================================================================
  // POST /auth/register/finish
  // بعد ما المستخدم حط بصمته → إنشاء الحساب + حفظ Public Key + JWT
  // ================================================================

  fastify.post(
    '/register/finish',
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = registerFinishSchema.parse(request.body)
        const result = await registerFinish(fastify, body)

        return reply.status(201).send({
          success: true,
          message: 'Account created successfully',
          data: result,
        })
      } catch (error: unknown) {
        return handleError(error, request, reply)
      }
    }
  )

  // ================================================================
  // POST /auth/login/start
  // email → WebAuthn authentication options
  // ================================================================

  fastify.post(
    '/login/start',
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = loginStartSchema.parse(request.body)
        const result = await loginStart(fastify, body)

        return reply.status(200).send({
          success: true,
          data: result,
        })
      } catch (error: unknown) {
        return handleError(error, request, reply)
      }
    }
  )

  // ================================================================
  // POST /auth/login/finish
  // بعد البصمة → تحقق من التوقيع + JWT
  // ================================================================

  fastify.post(
    '/login/finish',
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = loginFinishSchema.parse(request.body)
        const result = await loginFinish(fastify, body)

        return reply.status(200).send({
          success: true,
          message: 'Logged in successfully',
          data: result,
        })
      } catch (error: unknown) {
        return handleError(error, request, reply)
      }
    }
  )

  // ================================================================
  // GET /auth/me
  // ================================================================

  fastify.get(
    '/me',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const user = await getMe(fastify, request.user.id)

        return reply.status(200).send({
          success: true,
          data: user,
        })
      } catch (error: unknown) {
        return handleError(error, request, reply)
      }
    }
  )

  // ================================================================
  // PATCH /auth/profile
  // ================================================================

  fastify.patch(
    '/profile',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = updateProfileSchema.parse(request.body)
        const user = await updateProfile(fastify, request.user.id, body)

        return reply.status(200).send({
          success: true,
          message: 'Profile updated',
          data: user,
        })
      } catch (error: unknown) {
        return handleError(error, request, reply)
      }
    }
  )

  // ================================================================
  // GET /auth/passkeys
  // ================================================================

  fastify.get(
    '/passkeys',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const passkeys = await listPasskeys(fastify, request.user.id)

        return reply.status(200).send({
          success: true,
          data: passkeys,
        })
      } catch (error: unknown) {
        return handleError(error, request, reply)
      }
    }
  )

  // ================================================================
  // POST /auth/passkeys/register/start
  // إضافة Passkey لجهاز جديد (مسجّل دخول)
  // ================================================================

  fastify.post(
    '/passkeys/register/start',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const result = await addPasskeyStart(fastify, request.user.id)

        return reply.status(200).send({
          success: true,
          data: result,
        })
      } catch (error: unknown) {
        return handleError(error, request, reply)
      }
    }
  )

  // ================================================================
  // POST /auth/passkeys/register/finish
  // ================================================================

  fastify.post(
    '/passkeys/register/finish',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = addPasskeyFinishSchema.parse(request.body)
        const passkey = await addPasskeyFinish(
          fastify,
          request.user.id,
          body
        )

        return reply.status(201).send({
          success: true,
          message: 'Passkey added',
          data: passkey,
        })
      } catch (error: unknown) {
        return handleError(error, request, reply)
      }
    }
  )

  // ================================================================
  // DELETE /auth/passkeys
  // body: { passkeyId }
  // ================================================================

  fastify.delete(
    '/passkeys',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = revokePasskeySchema.parse(request.body)
        await revokePasskey(fastify, request.user.id, body.passkeyId)

        return reply.status(200).send({
          success: true,
          message: 'Passkey revoked',
        })
      } catch (error: unknown) {
        return handleError(error, request, reply)
      }
    }
  )

  // ================================================================
  // POST /auth/password
  // باسورد اختياري — مش للدخول الأساسي
  // ================================================================

  fastify.post(
    '/password',
    {
      preHandler: [fastify.authenticate],
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const body = setPasswordSchema.parse(request.body)
        await setPassword(fastify, request.user.id, body)

        return reply.status(200).send({
          success: true,
          message: 'Password set successfully',
        })
      } catch (error: unknown) {
        return handleError(error, request, reply)
      }
    }
  )
}