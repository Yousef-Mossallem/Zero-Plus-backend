// backend/src/modules/events/events.internal.routes.ts
// ==================================================================
// Zero Plus - Events Internal Routes (Gateway → Backend)
// ------------------------------------------------------------------
// POST /internal/gateway/events          إنشاء حدث واحد
// POST /internal/gateway/events/batch    إنشاء مجموعة أحداث (حتى 100)
//
// الحماية: X-Gateway-Key (fastify.authenticateGateway)
// organizationId بييجي في الـ Body لأن الـ Gateway مفيهوش JWT،
// والـ Service بتتأكد إن serverId تابع لنفس الـ organizationId.
// ==================================================================

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { z } from 'zod'

import { createGatewayEvent } from './events.service.js'

// ------------------------------------------------------------------
// Enums (مطابقة للـ Prisma schema)
// ------------------------------------------------------------------

const httpMethod = z.enum([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
  'HEAD',
])

const decision = z.enum(['ALLOW', 'MONITOR', 'RATE_LIMIT', 'CHALLENGE', 'BLOCK'])

const ipType = z.enum([
  'RESIDENTIAL',
  'MOBILE',
  'DATACENTER',
  'VPN_PROXY',
  'TOR',
  'UNKNOWN',
])

const challengeType = z.enum([
  'JS_SILENT',
  'TLS_FINGERPRINT',
  'RATE_LIMIT_SOFT',
  'CAPTCHA_FALLBACK',
])

const detectionStage = z.enum([
  'BAN_LIST',
  'PASS_TOKEN',
  'IP_LOOKUP',
  'JS_CHALLENGE',
  'HISTORY_MATCH',
  'DEEP_COMPARISON',
  'TLS_FINGERPRINT',
  'AI_ANOMALY',
  'HARD_LIMIT',
  'POLICY',
  'SURGE_DETECTED',
  'CLEARANCE_REVOKED',
])

// ------------------------------------------------------------------
// Body schema
// ------------------------------------------------------------------

export const gatewayEventSchema = z.object({
  organizationId: z.string().min(1, 'organizationId مطلوب'),
  serverId: z.string().min(1, 'serverId مطلوب'),

  // الطلب
  ipAddress: z.string().trim().min(1, 'ipAddress مطلوب').max(64),
  path: z.string().trim().min(1, 'path مطلوب').max(2048),
  method: httpMethod,
  userAgent: z.string().trim().max(1024).optional(),
  referer: z.string().trim().max(2048).optional(),
  requestId: z.string().trim().max(128).optional(),

  // المخاطر والقرار
  riskScore: z.number().int().min(0).max(100),
  anomalyScore: z.number().min(0).max(1).optional(),
  confidence: z.number().min(0).max(1).optional(),
  decision,
  decidedAtStage: detectionStage.optional(),
  reasonSummary: z.string().trim().min(1).max(1000).optional(),
  reasonDetails: z.record(z.string(), z.unknown()).optional(),
  processingTimeMs: z.number().int().min(0).max(600000).optional(),

  // إشارات الـ AI
  surgeDetected: z.boolean().optional(),
  pathSensitive: z.boolean().optional(),
  recommendation: z.string().trim().max(500).optional(),

  // الشبكة
  countryCode: z
    .string()
    .trim()
    .length(2, 'كود الدولة يجب أن يكون حرفين')
    .transform((v) => v.toUpperCase())
    .optional(),
  asn: z.number().int().positive().optional(),
  ipType: ipType.optional(),

  // التحدي
  isChallenged: z.boolean().optional(),
  challengeType: challengeType.optional(),
  challengePassed: z.boolean().optional(),

  // السمعة
  reputationEntryId: z.string().min(1).optional(),
})

export const gatewayEventBatchSchema = z.object({
  events: z.array(gatewayEventSchema).min(1).max(100),
})

export type GatewayEventInput = z.infer<typeof gatewayEventSchema>

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function statusOf(error: unknown): number {
  if (
    typeof error === 'object' &&
    error !== null &&
    'statusCode' in error &&
    typeof (error as { statusCode: unknown }).statusCode === 'number'
  ) {
    return (error as { statusCode: number }).statusCode
  }
  return 500
}

function fail(
  request: FastifyRequest,
  reply: FastifyReply,
  error: unknown,
) {
  const statusCode = statusOf(error)
  request.log.error({ err: error }, 'Internal event route error')

  return reply.code(statusCode).send({
    success: false,
    message:
      statusCode >= 500
        ? 'حدث خطأ داخلي أثناء معالجة الـ Security Event'
        : (error as Error).message,
  })
}

// ------------------------------------------------------------------
// Routes
// ------------------------------------------------------------------

export default async function internalEventRoutes(fastify: FastifyInstance) {
  // ---------------- POST /  (حدث واحد) ----------------
  fastify.post(
    '/',
    { preHandler: fastify.authenticateGateway },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = gatewayEventSchema.safeParse(request.body)

      if (!parsed.success) {
        return reply.code(400).send({
          success: false,
          message: 'بيانات الـ Security Event غير صالحة',
          details: parsed.error.format(),
        })
      }

      try {
        const event = await createGatewayEvent(fastify, parsed.data)

        return reply.code(201).send({
          success: true,
          message: 'تم إنشاء الـ Security Event بنجاح',
          data: { id: event.id, createdAt: event.createdAt },
        })
      } catch (error) {
        return fail(request, reply, error)
      }
    },
  )

  // ---------------- POST /batch  (مجموعة أحداث) ----------------
  fastify.post(
    '/batch',
    { preHandler: fastify.authenticateGateway },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const parsed = gatewayEventBatchSchema.safeParse(request.body)

      if (!parsed.success) {
        return reply.code(400).send({
          success: false,
          message: 'بيانات الـ batch غير صالحة',
          details: parsed.error.format(),
        })
      }

      const results: Array<
        | { index: number; ok: true; id: string }
        | { index: number; ok: false; code: number; message: string }
      > = []

      // بالتتابع عشان نحافظ على الترتيب ونتجنب ضغط الـ DB
      for (const [index, item] of parsed.data.events.entries()) {
        try {
          const event = await createGatewayEvent(fastify, item)
          results.push({ index, ok: true, id: event.id })
        } catch (error) {
          const code = statusOf(error)
          request.log.warn({ err: error, index }, 'Batch event failed')
          results.push({
            index,
            ok: false,
            code,
            message:
              code >= 500 ? 'Internal error' : (error as Error).message,
          })
        }
      }

      const succeeded = results.filter((r) => r.ok).length

      return reply.code(207).send({
        success: succeeded > 0,
        summary: {
          total: results.length,
          succeeded,
          failed: results.length - succeeded,
        },
        results,
      })
    },
  )
}