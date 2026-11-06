// backend/src/plugins/socket.plugin.ts
// ==================================================================
// Zero Plus - Socket.IO Plugin
// Real-time channel: Backend → Dashboard (per organization)
// NOT on the visitor/Gateway hot path
//
// يشمل: إشعارات، أحداث أمنية، سيرفرات، تقارير، **محاكاة (Simulation Lab)**
// ==================================================================

import fp from 'fastify-plugin'
import { Server as SocketIOServer, type Socket } from 'socket.io'
import type { FastifyPluginAsync, FastifyInstance } from 'fastify'

// ------------------------------------------------------------------
// Types
// ------------------------------------------------------------------

/** JWT payload shape (must match jwt.plugin.ts) */
export interface SocketAuthUser {
  id: string
  email: string
  role: string
  organizationId: string
  passkeyId?: string
}

/**
 * أسماء أحداث الـ realtime المستخدمة في التطبيق
 * الفرونت يشترك بنفس الأسماء حرفيًا
 */
export const SocketEvents = {
  // server → client
  NOTIFICATION_NEW: 'notification:new',
  SECURITY_EVENT_NEW: 'security_event:new',
  TRAFFIC_UPDATE: 'traffic:update',
  SERVER_STATUS: 'server:status',
  REPUTATION_UPDATE: 'reputation:update',
  /** تقارير Gemini: created / GENERATING / READY / FAILED / deleted */
  REPORT_STATUS: 'report:status',

  // ----- Simulation Lab -----
  /** تحديث دوري لعدادات/حالة Run (totals, status, avgLatencyMs) */
  SIMULATION_UPDATE: 'simulation:update',
  /** Run بدأ / توقف / اكتمل / فشل */
  SIMULATION_STATUS: 'simulation:status',

  // client → server
  PING: 'ping',
  SUBSCRIBE_TRAFFIC: 'subscribe:traffic',
  /** اختياري: متابعة Run معيّن (غرفة أضيق) */
  SUBSCRIBE_SIMULATION: 'subscribe:simulation',
  UNSUBSCRIBE_SIMULATION: 'unsubscribe:simulation',
} as const

export type SocketEventName =
  (typeof SocketEvents)[keyof typeof SocketEvents]

/** شكل مقترح لحمولة simulation:update (الفرونت يقدر يعتمد عليه) */
export interface SimulationUpdatePayload {
  runId: string
  organizationId: string
  status: string
  totals: {
    sent: number
    allowed: number
    challenged: number
    rateLimited: number
    blocked: number
    failed: number
  }
  avgLatencyMs?: number | null
  errorMessage?: string | null
  stoppedAt?: string | null
  /** ISO */
  at: string
}

declare module 'fastify' {
  interface FastifyInstance {
    io: SocketIOServer
    /**
     * Emit an event to every connected dashboard user in an organization.
     */
    broadcastToOrg: (
      organizationId: string,
      event: string,
      payload: unknown,
    ) => void
    /**
     * Emit to a single user (all their sockets, if multiple tabs).
     */
    broadcastToUser: (
      userId: string,
      event: string,
      payload: unknown,
    ) => void
    /**
     * بث تحديث محاكاة للمنظمة (+ غرفة الـ Run إن وُجدت)
     */
    broadcastSimulationUpdate: (
      organizationId: string,
      payload: SimulationUpdatePayload,
    ) => void
  }
}

// ------------------------------------------------------------------
// Room helpers
// ------------------------------------------------------------------

function orgRoom(organizationId: string): string {
  return `org:${organizationId}`
}

function userRoom(userId: string): string {
  return `user:${userId}`
}

function simulationRoom(runId: string): string {
  return `simulation:${runId}`
}

// ------------------------------------------------------------------
// Auth from handshake
// ------------------------------------------------------------------

function extractToken(socket: Socket): string | null {
  const fromAuth = socket.handshake.auth?.token
  if (typeof fromAuth === 'string' && fromAuth.trim()) {
    return fromAuth.replace(/^Bearer\s+/i, '').trim()
  }

  const header = socket.handshake.headers.authorization
  if (typeof header === 'string' && header.startsWith('Bearer ')) {
    return header.slice(7).trim()
  }

  const fromQuery = socket.handshake.query?.token
  if (typeof fromQuery === 'string' && fromQuery.trim()) {
    return fromQuery.trim()
  }

  return null
}

// ------------------------------------------------------------------
// Plugin
// ------------------------------------------------------------------

const socketPlugin: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  const frontendOrigin =
    process.env.FRONTEND_ORIGIN ??
    process.env.CORS_ORIGIN ??
    true

  const io = new SocketIOServer(fastify.server, {
    path: '/socket.io',
    cors: {
      origin: frontendOrigin,
      methods: ['GET', 'POST'],
      credentials: true,
    },
    transports: ['websocket', 'polling'],
    pingInterval: 25000,
    pingTimeout: 20000,
  })

  // ------------------------------------------------------------------
  // Connection auth + rooms
  // ------------------------------------------------------------------

  io.use(async (socket, next) => {
    try {
      const token = extractToken(socket)

      if (!token) {
        return next(new Error('UNAUTHORIZED'))
      }

      const payload = fastify.jwt.verify<SocketAuthUser>(token)

      if (!payload?.id || !payload?.organizationId) {
        return next(new Error('UNAUTHORIZED'))
      }

      socket.data.user = {
        id: payload.id,
        email: payload.email,
        role: payload.role,
        organizationId: payload.organizationId,
        ...(payload.passkeyId ? { passkeyId: payload.passkeyId } : {}),
      } satisfies SocketAuthUser

      return next()
    } catch {
      return next(new Error('UNAUTHORIZED'))
    }
  })

  io.on('connection', (socket: Socket) => {
    const user = socket.data.user as SocketAuthUser

    const oRoom = orgRoom(user.organizationId)
    const uRoom = userRoom(user.id)

    void socket.join(oRoom)
    void socket.join(uRoom)

    fastify.log.info(
      {
        socketId: socket.id,
        userId: user.id,
        organizationId: user.organizationId,
      },
      'Socket connected',
    )

    socket.on(SocketEvents.PING, (ack?: (ts: number) => void) => {
      if (typeof ack === 'function') {
        ack(Date.now())
      }
    })

    socket.on(SocketEvents.SUBSCRIBE_TRAFFIC, () => {
      void socket.join(`${oRoom}:traffic`)
    })

    /**
     * اشتراك في Run محاكاة معيّن
     * payload: { runId: string }
     */
    socket.on(
      SocketEvents.SUBSCRIBE_SIMULATION,
      (payload: { runId?: string } | string) => {
        const runId =
          typeof payload === 'string' ? payload : payload?.runId
        if (!runId || typeof runId !== 'string') return
        // الغرفة عامة بالـ runId؛ البيانات أصلًا معزولة لأن البث من الباك بعد التحقق
        void socket.join(simulationRoom(runId))
      },
    )

    socket.on(
      SocketEvents.UNSUBSCRIBE_SIMULATION,
      (payload: { runId?: string } | string) => {
        const runId =
          typeof payload === 'string' ? payload : payload?.runId
        if (!runId || typeof runId !== 'string') return
        void socket.leave(simulationRoom(runId))
      },
    )

    socket.on('disconnect', (reason) => {
      fastify.log.info(
        {
          socketId: socket.id,
          userId: user.id,
          reason,
        },
        'Socket disconnected',
      )
    })
  })

  // ------------------------------------------------------------------
  // Decorators
  // ------------------------------------------------------------------

  fastify.decorate('io', io)

  fastify.decorate(
    'broadcastToOrg',
    (organizationId: string, event: string, payload: unknown) => {
      io.to(orgRoom(organizationId)).emit(event, payload)
    },
  )

  fastify.decorate(
    'broadcastToUser',
    (userId: string, event: string, payload: unknown) => {
      io.to(userRoom(userId)).emit(event, payload)
    },
  )

  fastify.decorate(
    'broadcastSimulationUpdate',
    (organizationId: string, payload: SimulationUpdatePayload) => {
      const body = {
        ...payload,
        at: payload.at || new Date().toISOString(),
      }
      // كل أعضاء الشركة (صفحة المحاكاة / الداشبورد)
      io.to(orgRoom(organizationId)).emit(
        SocketEvents.SIMULATION_UPDATE,
        body,
      )
      // من اشترك صراحة في الـ Run
      if (payload.runId) {
        io.to(simulationRoom(payload.runId)).emit(
          SocketEvents.SIMULATION_UPDATE,
          body,
        )
      }
      // تغيير حالة نهائي/مهم
      if (
        payload.status === 'RUNNING' ||
        payload.status === 'STOPPED' ||
        payload.status === 'COMPLETED' ||
        payload.status === 'FAILED' ||
        payload.status === 'PENDING'
      ) {
        io.to(orgRoom(organizationId)).emit(
          SocketEvents.SIMULATION_STATUS,
          body,
        )
      }
    },
  )

  fastify.addHook('onClose', (_instance, done) => {
    void io.close()
    done()
  })

  fastify.log.info('✅ Socket.IO plugin registered successfully')
}

export default fp(socketPlugin, {
  name: 'socket',
  dependencies: ['jwt'],
})