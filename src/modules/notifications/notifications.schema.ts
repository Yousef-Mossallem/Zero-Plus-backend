// backend/src/modules/notifications/notifications.schema.ts
// ==================================================================
// Zero Plus - Notifications Validation Schemas (Zod)
// ------------------------------------------------------------------
// متوافق مع Prisma model Notification + enum NotificationType
// الإشعارات على مستوى Organization (مفيش userId في الجدول)
// ==================================================================

import { z } from 'zod'

// ==================================================================
// Constants — لازم تطابق prisma enum NotificationType
// ==================================================================

export const NOTIFICATION_TYPES = [
  'DDOS_START',
  'NEW_BLOCK',
  'CRITICAL_REPUTATION',
  'SERVER_CAPACITY_WARNING',
  'SERVER_RECOVERY',
  'POLICY_CHANGED',
  'SYSTEM',
] as const

export type NotificationTypeValue = (typeof NOTIFICATION_TYPES)[number]

/**
 * شدة العرض في الداشبورد (1–5)
 * 1 = معلوماتي | 2 = تنبيه خفيف | 3 = مهم | 4 = حرج | 5 = طارئ
 */
export const SEVERITY_MIN = 1
export const SEVERITY_MAX = 5

export const NOTIFICATION_TYPE_META: Record<
  NotificationTypeValue,
  { labelAr: string; labelEn: string; defaultSeverity: number }
> = {
  DDOS_START: {
    labelAr: 'بداية هجوم / ضغط غير طبيعي',
    labelEn: 'Attack / surge started',
    defaultSeverity: 4,
  },
  NEW_BLOCK: {
    labelAr: 'حظر جديد',
    labelEn: 'New block',
    defaultSeverity: 3,
  },
  CRITICAL_REPUTATION: {
    labelAr: 'سمعة حرجة',
    labelEn: 'Critical reputation',
    defaultSeverity: 4,
  },
  SERVER_CAPACITY_WARNING: {
    labelAr: 'اقتراب من سعة السيرفر',
    labelEn: 'Server capacity warning',
    defaultSeverity: 3,
  },
  SERVER_RECOVERY: {
    labelAr: 'استعادة السيرفر',
    labelEn: 'Server recovery',
    defaultSeverity: 1,
  },
  POLICY_CHANGED: {
    labelAr: 'تغيير في السياسات',
    labelEn: 'Policy changed',
    defaultSeverity: 2,
  },
  SYSTEM: {
    labelAr: 'نظام',
    labelEn: 'System',
    defaultSeverity: 2,
  },
}

// ==================================================================
// Shared field rules
// ==================================================================

const notificationTypeSchema = z.enum(NOTIFICATION_TYPES)

const severitySchema = z
  .number()
  .int('Severity must be an integer')
  .min(SEVERITY_MIN, `Severity must be at least ${SEVERITY_MIN}`)
  .max(SEVERITY_MAX, `Severity must be at most ${SEVERITY_MAX}`)

const titleSchema = z
  .string()
  .min(1, 'Title is required')
  .max(200, 'Title is too long')
  .transform((v) => v.trim())

const messageSchema = z
  .string()
  .min(1, 'Message is required')
  .max(2000, 'Message is too long')
  .transform((v) => v.trim())

/** metadata حرة من الـ Gateway/Services — object فقط مش array */
const metadataSchema = z
  .record(z.string(), z.unknown())
  .optional()
  .nullable()

const uuidSchema = z.string().uuid('Invalid id')

// ------------------------------------------------------------------
// Query helpers
// ------------------------------------------------------------------

const booleanQuery = z
  .union([z.boolean(), z.enum(['true', 'false', '1', '0'])])
  .transform((v) => {
    if (typeof v === 'boolean') return v
    return v === 'true' || v === '1'
  })
  .optional()

const pageSchema = z.coerce
  .number()
  .int()
  .min(1)
  .default(1)

const limitSchema = z.coerce
  .number()
  .int()
  .min(1)
  .max(100)
  .default(20)

const sortOrderSchema = z.enum(['asc', 'desc']).default('desc')

const dateTimeQuery = z
  .string()
  .datetime({ offset: true })
  .or(z.string().datetime())
  .optional()

// ==================================================================
// 1) Create Notification (داخلي: من events/servers/reputation/service)
//    مش لازم endpoint عام من الداشبورد في الـ MVP
// ==================================================================

export const createNotificationSchema = z
  .object({
    type: notificationTypeSchema,
    title: titleSchema,
    message: messageSchema,
    severity: severitySchema.optional(),
    metadata: metadataSchema,
    /**
     * organizationId بيتحط من الـ service/JWT/context
     * مش من body عام للعميل
     */
    organizationId: uuidSchema.optional(),
  })
  .strict()

export type CreateNotificationInput = z.infer<typeof createNotificationSchema>

/**
 * بعد ما الـ service يضيف organizationId إجباري
 */
export const createNotificationInternalSchema = createNotificationSchema
  .omit({ organizationId: true })
  .extend({
    organizationId: uuidSchema,
    severity: severitySchema.optional(),
  })
  .strict()

export type CreateNotificationInternalInput = z.infer<
  typeof createNotificationInternalSchema
>

// ==================================================================
// 2) List Notifications (Dashboard)
// ==================================================================

export const listNotificationsQuerySchema = z
  .object({
    page: pageSchema,
    limit: limitSchema,

    /** true = غير المقروء فقط */
    unreadOnly: booleanQuery,

    /** فلترة بنوع واحد أو أكثر (CSV أو تكرار في الـ query) */
    type: z
      .union([
        notificationTypeSchema,
        z.array(notificationTypeSchema),
        z
          .string()
          .transform((s) =>
            s
              .split(',')
              .map((x) => x.trim())
              .filter(Boolean),
          )
          .pipe(z.array(notificationTypeSchema).min(1)),
      ])
      .optional()
      .transform((v) => {
        if (v === undefined) return undefined
        return Array.isArray(v) ? v : [v]
      }),

    minSeverity: z.coerce
      .number()
      .int()
      .min(SEVERITY_MIN)
      .max(SEVERITY_MAX)
      .optional(),

    maxSeverity: z.coerce
      .number()
      .int()
      .min(SEVERITY_MIN)
      .max(SEVERITY_MAX)
      .optional(),

    /** بحث بسيط في title / message */
    search: z
      .string()
      .max(100)
      .transform((v) => v.trim())
      .optional(),

    createdAfter: dateTimeQuery,
    createdBefore: dateTimeQuery,

    sortBy: z
      .enum(['createdAt', 'severity', 'type', 'isRead'])
      .default('createdAt'),

    sortOrder: sortOrderSchema,
  })
  .strict()
  .superRefine((data, ctx) => {
    if (
      data.minSeverity !== undefined &&
      data.maxSeverity !== undefined &&
      data.minSeverity > data.maxSeverity
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'minSeverity must be <= maxSeverity',
        path: ['minSeverity'],
      })
    }

    if (data.createdAfter && data.createdBefore) {
      const a = new Date(data.createdAfter).getTime()
      const b = new Date(data.createdBefore).getTime()
      if (a > b) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'createdAfter must be before createdBefore',
          path: ['createdAfter'],
        })
      }
    }
  })

export type ListNotificationsQuery = z.infer<
  typeof listNotificationsQuerySchema
>

// ==================================================================
// 3) Get by id (path param)
// ==================================================================

export const notificationIdParamsSchema = z
  .object({
    id: uuidSchema,
  })
  .strict()

export type NotificationIdParams = z.infer<typeof notificationIdParamsSchema>

// ==================================================================
// 4) Mark one as read
// ==================================================================

export const markNotificationReadParamsSchema = notificationIdParamsSchema

export type MarkNotificationReadParams = z.infer<
  typeof markNotificationReadParamsSchema
>

// ==================================================================
// 5) Mark all as read (اختياري: فلتر نوع)
// ==================================================================

export const markAllReadBodySchema = z
  .object({
    /** لو اتبعت: علّم مقروء لأنواع دي بس */
    types: z.array(notificationTypeSchema).min(1).max(20).optional(),
    /** لو true: بس اللي severity >= القيمة */
    minSeverity: severitySchema.optional(),
  })
  .strict()

export type MarkAllReadInput = z.infer<typeof markAllReadBodySchema>

// ==================================================================
// 6) Unread count query (خفيف للجرس)
// ==================================================================

export const unreadCountQuerySchema = z
  .object({
    minSeverity: z.coerce
      .number()
      .int()
      .min(SEVERITY_MIN)
      .max(SEVERITY_MAX)
      .optional(),
    type: z
      .union([
        notificationTypeSchema,
        z.array(notificationTypeSchema),
      ])
      .optional()
      .transform((v) => {
        if (v === undefined) return undefined
        return Array.isArray(v) ? v : [v]
      }),
  })
  .strict()

export type UnreadCountQuery = z.infer<typeof unreadCountQuerySchema>

// ==================================================================
// 7) Delete (اختياري — OWNER/ADMIN لاحقًا)
// ==================================================================

export const deleteNotificationParamsSchema = notificationIdParamsSchema

export type DeleteNotificationParams = z.infer<
  typeof deleteNotificationParamsSchema
>

// ==================================================================
// Public DTO — شكل الرد للفرونت (متوافق مع Prisma + Socket payload)
// ==================================================================

export const notificationPublicSchema = z.object({
  id: z.string().uuid(),
  type: notificationTypeSchema,
  title: z.string(),
  message: z.string(),
  severity: z.number().int(),
  isRead: z.boolean(),
  metadata: z.unknown().nullable(),
  organizationId: z.string().uuid(),
  createdAt: z.string(), // ISO
})

export type NotificationPublic = z.infer<typeof notificationPublicSchema>

export const notificationsListResponseSchema = z.object({
  success: z.literal(true),
  data: z.array(notificationPublicSchema),
  pagination: z.object({
    total: z.number().int().nonnegative(),
    page: z.number().int().positive(),
    limit: z.number().int().positive(),
    totalPages: z.number().int().nonnegative(),
    hasNextPage: z.boolean(),
    hasPreviousPage: z.boolean(),
  }),
  summary: z
    .object({
      unreadCount: z.number().int().nonnegative(),
    })
    .optional(),
})

export type NotificationsListResponse = z.infer<
  typeof notificationsListResponseSchema
>

export const unreadCountResponseSchema = z.object({
  success: z.literal(true),
  data: z.object({
    unreadCount: z.number().int().nonnegative(),
  }),
})

export type UnreadCountResponse = z.infer<typeof unreadCountResponseSchema>

// ==================================================================
// Socket payload (server → client) — نفس الحقول تقريبًا
// ==================================================================

export const notificationSocketPayloadSchema = notificationPublicSchema.extend({
  /** للفرونت: هل يزود عداد الجرس */
  bumpUnread: z.boolean().default(true),
})

export type NotificationSocketPayload = z.infer<
  typeof notificationSocketPayloadSchema
>

// ==================================================================
// Helpers للاستخدام من الـ Service
// ==================================================================

/** لو severity مش متبعتة: خذ الافتراضي حسب النوع */
export function resolveSeverity(
  type: NotificationTypeValue,
  severity?: number,
): number {
  if (severity !== undefined) {
    return Math.min(SEVERITY_MAX, Math.max(SEVERITY_MIN, Math.round(severity)))
  }
  return NOTIFICATION_TYPE_META[type].defaultSeverity
}

export function isNotificationType(
  value: string,
): value is NotificationTypeValue {
  return (NOTIFICATION_TYPES as readonly string[]).includes(value)
}