// backend/src/modules/notifications/notifications.service.ts
// ==================================================================
// Zero Plus - Notifications Service
// ------------------------------------------------------------------
// - إنشاء إشعارات (داخلي من events / servers / reputation أو استدعاء مباشر)
// - قراءة / فلترة / ترقيم للداشبورد
// - تعليم مقروء (واحد / الكل)
// - عداد غير مقروء للجرس
// - بث Socket.IO: notification:new بعد الإنشاء الناجح
//
// الإشعارات على مستوى Organization (حسب Prisma) — isRead مشترك لكل أعضاء الشركة
// ==================================================================

import { Prisma, type Notification } from '@prisma/client'
import type { FastifyInstance } from 'fastify'

import { SocketEvents } from '../../plugins/socket.plugin.js'
import {
  resolveSeverity,
  type CreateNotificationInternalInput,
  type ListNotificationsQuery,
  type MarkAllReadInput,
  type NotificationPublic,
  type NotificationSocketPayload,
  type NotificationTypeValue,
  type UnreadCountQuery,
} from './notifications.schema.js'

// ==================================================================
// Errors
// ==================================================================

export class NotificationServiceError extends Error {
  public readonly statusCode: number
  public readonly code: string
  public readonly details?: unknown

  constructor(
    message: string,
    statusCode: number,
    code: string,
    details?: unknown,
  ) {
    super(message)
    this.name = 'NotificationServiceError'
    this.statusCode = statusCode
    this.code = code
    this.details = details
  }
}

const notFound = () =>
  new NotificationServiceError(
    'الإشعار غير موجود',
    404,
    'NOTIFICATION_NOT_FOUND',
  )

// ==================================================================
// Result types
// ==================================================================

export interface ListNotificationsResult {
  data: NotificationPublic[]
  pagination: {
    total: number
    page: number
    limit: number
    totalPages: number
    hasNextPage: boolean
    hasPreviousPage: boolean
  }
  summary: {
    unreadCount: number
  }
}

export interface UnreadCountResult {
  unreadCount: number
}

export interface MarkReadResult {
  id: string
  isRead: boolean
  /** false = كان مقروء أصلًا */
  changed: boolean
}

export interface MarkAllReadResult {
  updatedCount: number
}

export interface DeleteNotificationResult {
  id: string
  deleted: true
}

// ==================================================================
// Helpers
// ==================================================================

export function toPublic(row: Notification): NotificationPublic {
  return {
    id: row.id,
    type: row.type as NotificationTypeValue,
    title: row.title,
    message: row.message,
    severity: row.severity,
    isRead: row.isRead,
    metadata: row.metadata ?? null,
    organizationId: row.organizationId,
    createdAt: row.createdAt.toISOString(),
  }
}

function toSocketPayload(
  row: Notification,
  bumpUnread = true,
): NotificationSocketPayload {
  return {
    ...toPublic(row),
    bumpUnread,
  }
}

function isPrismaError(
  error: unknown,
  code: string,
): error is Prisma.PrismaClientKnownRequestError {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === code
  )
}

// ==================================================================
// Service
// ==================================================================

export class NotificationsService {
  constructor(private readonly fastify: FastifyInstance) {}

  // ================================================================
  // Socket
  // ================================================================

  private emitNotificationNew(payload: NotificationSocketPayload) {
    try {
      if (typeof this.fastify.broadcastToOrg === 'function') {
        this.fastify.broadcastToOrg(
          payload.organizationId,
          SocketEvents.NOTIFICATION_NEW,
          payload,
        )
      }
    } catch (err) {
      this.fastify.log.warn(
        { err, id: payload.id },
        'Failed to broadcast notification:new',
      )
    }
  }

  // ================================================================
  // Create (داخلي — بعد نجاح الـ insert → Socket)
  // ================================================================

  /**
   * أنشئ إشعارًا واحدًا وبثّه للداشبورد.
   * استدعِها من servers / reputation / events بدل prisma.notification.create المباشر.
   */
  async create(
    input: CreateNotificationInternalInput,
  ): Promise<NotificationPublic> {
    const severity = resolveSeverity(input.type, input.severity)

    const row = await this.fastify.prisma.notification.create({
      data: {
        organizationId: input.organizationId,
        type: input.type,
        title: input.title,
        message: input.message,
        severity,
        isRead: false,
        metadata:
          input.metadata === undefined || input.metadata === null
            ? Prisma.JsonNull
            : (input.metadata as Prisma.InputJsonObject),
      },
    })

    const publicRow = toPublic(row)
    this.emitNotificationNew(toSocketPayload(row, true))

    return publicRow
  }

  /**
   * إنشاء عدة إشعارات (مثلاً من reportHealth).
   * كل واحد بيتبعت Socket لوحده.
   */
  async createMany(
    items: CreateNotificationInternalInput[],
  ): Promise<NotificationPublic[]> {
    if (items.length === 0) return []

    const created: NotificationPublic[] = []

    // متتابع عشان نعرف الـ ids ونبث (createMany مش بيرجع الصفوف في كل الـ providers بنفس الشكل)
    for (const item of items) {
      created.push(await this.create(item))
    }

    return created
  }

  // ================================================================
  // List
  // ================================================================

  async list(
    organizationId: string,
    query: ListNotificationsQuery,
  ): Promise<ListNotificationsResult> {
    const where = this.buildListWhere(organizationId, query)

    const skip = (query.page - 1) * query.limit

    const orderBy: Prisma.NotificationOrderByWithRelationInput = {
      [query.sortBy]: query.sortOrder,
    }

    const [rows, total, unreadCount] = await Promise.all([
      this.fastify.prisma.notification.findMany({
        where,
        skip,
        take: query.limit,
        orderBy,
      }),
      this.fastify.prisma.notification.count({ where }),
      this.fastify.prisma.notification.count({
        where: { organizationId, isRead: false },
      }),
    ])

    const totalPages = Math.ceil(total / query.limit)

    return {
      data: rows.map(toPublic),
      pagination: {
        total,
        page: query.page,
        limit: query.limit,
        totalPages,
        hasNextPage: query.page < totalPages,
        hasPreviousPage: query.page > 1,
      },
      summary: {
        unreadCount,
      },
    }
  }

  private buildListWhere(
    organizationId: string,
    query: ListNotificationsQuery,
  ): Prisma.NotificationWhereInput {
    const where: Prisma.NotificationWhereInput = {
      organizationId,
    }

    if (query.unreadOnly === true) {
      where.isRead = false
    }

    if (query.type && query.type.length > 0) {
      where.type = { in: query.type }
    }

    if (
      query.minSeverity !== undefined ||
      query.maxSeverity !== undefined
    ) {
      where.severity = {
        ...(query.minSeverity !== undefined && {
          gte: query.minSeverity,
        }),
        ...(query.maxSeverity !== undefined && {
          lte: query.maxSeverity,
        }),
      }
    }

    if (query.search) {
      where.OR = [
        {
          title: {
            contains: query.search,
            mode: 'insensitive',
          },
        },
        {
          message: {
            contains: query.search,
            mode: 'insensitive',
          },
        },
      ]
    }

    if (query.createdAfter || query.createdBefore) {
      where.createdAt = {
        ...(query.createdAfter && {
          gte: new Date(query.createdAfter),
        }),
        ...(query.createdBefore && {
          lte: new Date(query.createdBefore),
        }),
      }
    }

    return where
  }

  // ================================================================
  // Get by id
  // ================================================================

  async getById(
    organizationId: string,
    id: string,
  ): Promise<NotificationPublic> {
    const row = await this.fastify.prisma.notification.findFirst({
      where: { id, organizationId },
    })

    if (!row) throw notFound()
    return toPublic(row)
  }

  // ================================================================
  // Unread count (للجرس)
  // ================================================================

  async getUnreadCount(
    organizationId: string,
    query: UnreadCountQuery = {
        type: undefined
    },
  ): Promise<UnreadCountResult> {
    const where: Prisma.NotificationWhereInput = {
      organizationId,
      isRead: false,
    }

    if (query.minSeverity !== undefined) {
      where.severity = { gte: query.minSeverity }
    }

    if (query.type && query.type.length > 0) {
      where.type = { in: query.type }
    }

    const unreadCount = await this.fastify.prisma.notification.count({
      where,
    })

    return { unreadCount }
  }

  // ================================================================
  // Mark read
  // ================================================================

  async markRead(
    organizationId: string,
    id: string,
  ): Promise<MarkReadResult> {
    const existing = await this.fastify.prisma.notification.findFirst({
      where: { id, organizationId },
      select: { id: true, isRead: true },
    })

    if (!existing) throw notFound()

    if (existing.isRead) {
      return { id, isRead: true, changed: false }
    }

    await this.fastify.prisma.notification.update({
      where: { id },
      data: { isRead: true },
    })

    return { id, isRead: true, changed: true }
  }

  async markAllRead(
    organizationId: string,
    input: MarkAllReadInput = {},
  ): Promise<MarkAllReadResult> {
    const where: Prisma.NotificationWhereInput = {
      organizationId,
      isRead: false,
    }

    if (input.types && input.types.length > 0) {
      where.type = { in: input.types }
    }

    if (input.minSeverity !== undefined) {
      where.severity = { gte: input.minSeverity }
    }

    const result = await this.fastify.prisma.notification.updateMany({
      where,
      data: { isRead: true },
    })

    return { updatedCount: result.count }
  }

  // ================================================================
  // Delete (اختياري — للـ routes لو فعّلتموه)
  // ================================================================

  async delete(
    organizationId: string,
    id: string,
  ): Promise<DeleteNotificationResult> {
    const existing = await this.fastify.prisma.notification.findFirst({
      where: { id, organizationId },
      select: { id: true },
    })

    if (!existing) throw notFound()

    try {
      await this.fastify.prisma.notification.delete({ where: { id } })
    } catch (error) {
      if (isPrismaError(error, 'P2025')) throw notFound()
      throw error
    }

    return { id, deleted: true }
  }
}

// ==================================================================
// Factory helper (لو بتحبوا instance واحد من الـ routes)
// ==================================================================

export function createNotificationsService(
  fastify: FastifyInstance,
): NotificationsService {
  return new NotificationsService(fastify)
}