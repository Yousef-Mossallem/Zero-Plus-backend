// ==================================================================
// Zero Plus - Simulations Routes
// ------------------------------------------------------------------
// REST متوافق مع عقد الفرونت (Simulation Lab):
//   POST   /simulations              → Start
//   POST   /simulations/:id/stop     → Stop
//   GET    /simulations/:id          → تفاصيل + totals
//   GET    /simulations              → قائمة
//   GET    /simulations/:id/events   → أحداث الـ Run
//
// الكل: JWT + عزل organizationId من التوكن
// ==================================================================

import type {
  FastifyInstance,
  FastifyRequest,
  FastifyReply,
} from 'fastify'

import {
  createSimulationSchema,
  listSimulationsQuerySchema,
  simulationIdParamsSchema,
  simulationEventsQuerySchema,
} from './simulations.schema.js'
import {
  SimulationsService,
  SimulationServiceError,
} from './simulations.service.js'

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function getOrgAndUser(request: FastifyRequest): {
  organizationId: string
  userId: string
} {
  const user = request.user as {
    id: string
    organizationId: string
  }
  return {
    organizationId: user.organizationId,
    userId: user.id,
  }
}

function handleError(
  error: unknown,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  if (error instanceof SimulationServiceError) {
    return reply.status(error.statusCode).send({
      success: false,
      code: error.code,
      message: error.message,
    })
  }

  // Zod / Fastify validation
  if (
    error &&
    typeof error === 'object' &&
    'name' in error &&
    (error as { name: string }).name === 'ZodError'
  ) {
    return reply.status(400).send({
      success: false,
      code: 'VALIDATION_ERROR',
      message: 'Invalid request',
      errors: (error as { issues?: unknown }).issues,
    })
  }

  request.log.error(error)
  return reply.status(500).send({
    success: false,
    code: 'INTERNAL_ERROR',
    message: 'Internal server error',
  })
}

// ------------------------------------------------------------------
// Register
// ------------------------------------------------------------------

export async function simulationsRoutes(fastify: FastifyInstance) {
  const service = new SimulationsService(fastify)

  // ================================================================
  // POST /simulations — Start
  // ================================================================
  fastify.post(
    '/',
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      try {
        const { organizationId, userId } = getOrgAndUser(request)
        const body = createSimulationSchema.parse(request.body)

        const result = await service.start(organizationId, userId, body)

        return reply.status(201).send({
          success: true,
          data: result.run,
        })
      } catch (error) {
        return handleError(error, request, reply)
      }
    },
  )

  // ================================================================
  // POST /simulations/:id/stop
  // ================================================================
  fastify.post(
    '/:id/stop',
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      try {
        const { organizationId } = getOrgAndUser(request)
        const { id } = simulationIdParamsSchema.parse(request.params)

        const run = await service.stop(organizationId, id)

        return reply.status(200).send({
          success: true,
          data: run,
        })
      } catch (error) {
        return handleError(error, request, reply)
      }
    },
  )

  // ================================================================
  // GET /simulations/:id
  // ================================================================
  fastify.get(
    '/:id',
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      try {
        const { organizationId } = getOrgAndUser(request)
        const { id } = simulationIdParamsSchema.parse(request.params)

        const run = await service.getById(organizationId, id)

        return reply.status(200).send({
          success: true,
          data: run,
        })
      } catch (error) {
        return handleError(error, request, reply)
      }
    },
  )

  // ================================================================
  // GET /simulations
  // ================================================================
  fastify.get(
    '/',
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      try {
        const { organizationId } = getOrgAndUser(request)
        const query = listSimulationsQuerySchema.parse(request.query)

        const result = await service.list(organizationId, query)

        return reply.status(200).send({
          success: true,
          data: result,
        })
      } catch (error) {
        return handleError(error, request, reply)
      }
    },
  )

  // ================================================================
  // GET /simulations/:id/events
  // ================================================================
  fastify.get(
    '/:id/events',
    {
      preHandler: [fastify.authenticate],
    },
    async (request, reply) => {
      try {
        const { organizationId } = getOrgAndUser(request)
        const { id } = simulationIdParamsSchema.parse(request.params)
        const query = simulationEventsQuerySchema.parse(request.query)

        const result = await service.listEvents(organizationId, id, query)

        return reply.status(200).send({
          success: true,
          data: result,
        })
      } catch (error) {
        return handleError(error, request, reply)
      }
    },
  )
}

export default simulationsRoutes