// backend/src/modules/events/events.schema.ts

import { z } from 'zod';

// ==================================================================
// Zero Plus - Events Schemas
// Validation schemas for Security Events
// ==================================================================

// ------------------------------------------------------------------
// Shared enums
// ------------------------------------------------------------------

const httpMethodSchema = z.enum([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
  'HEAD',
]);

const decisionSchema = z.enum([
  'ALLOW',
  'RATE_LIMIT',
  'CHALLENGE',
  'BLOCK',
]);

const ipTypeSchema = z.enum([
  'RESIDENTIAL',
  'MOBILE',
  'DATACENTER',
  'VPN_PROXY',
  'TOR',
  'UNKNOWN',
]);

// ==================================================================
// CREATE SECURITY EVENT
// POST /api/events
// ==================================================================

export const createEventSchema = z.object({
  // ----------------------------------------------------------------
  // Server
  // ----------------------------------------------------------------

  // السيرفر المحمي الذي حصل عليه الـ Event
  // organizationId لا يأتي من الـ body، بل من JWT
  serverId: z
    .string()
    .min(1, 'معرف السيرفر مطلوب'),

  // ----------------------------------------------------------------
  // Request information
  // ----------------------------------------------------------------

  ipAddress: z
    .string()
    .trim()
    .min(1, 'عنوان IP مطلوب'),

  path: z
    .string()
    .trim()
    .min(1, 'المسار مطلوب'),

  method: httpMethodSchema,

  userAgent: z
    .string()
    .trim()
    .optional(),

  referer: z
    .string()
    .trim()
    .optional(),

  requestId: z
    .string()
    .trim()
    .optional(),

  // ----------------------------------------------------------------
  // Risk & AI signals
  // ----------------------------------------------------------------

  // 0 - 100
  riskScore: z
    .number()
    .int()
    .min(0, 'Risk Score لا يمكن أن يكون أقل من 0')
    .max(100, 'Risk Score لا يمكن أن يكون أكبر من 100'),

  // 0.0 - 1.0
  // مختلف عن riskScore الذي يعمل من 0 إلى 100
  anomalyScore: z
    .number()
    .min(0, 'Anomaly Score لا يمكن أن يكون أقل من 0')
    .max(1, 'Anomaly Score لا يمكن أن يكون أكبر من 1')
    .optional(),

  // 0.0 - 1.0
  confidence: z
    .number()
    .min(0, 'Confidence لا يمكن أن تكون أقل من 0')
    .max(1, 'Confidence لا يمكن أن تكون أكبر من 1')
    .optional(),

  // ----------------------------------------------------------------
  // Decision
  // ----------------------------------------------------------------

  decision: decisionSchema,

  reasonSummary: z
    .string()
    .trim()
    .min(1, 'ملخص السبب مطلوب')
    .optional(),

  // تفاصيل الإشارات التي أدت للقرار
  //
  // مثال:
  // {
  //   "highRequestRate": true,
  //   "dataCenterIp": true,
  //   "badReputation": true
  // }
  reasonDetails: z
    .record(z.string(), z.unknown())
    .optional(),

  // ----------------------------------------------------------------
  // IP / Network intelligence
  // ----------------------------------------------------------------

  countryCode: z
    .string()
    .trim()
    .length(2, 'كود الدولة يجب أن يكون حرفين')
    .transform((value) => value.toUpperCase())
    .optional(),

  asn: z
    .number()
    .int()
    .positive()
    .optional(),

  ipType: ipTypeSchema.optional(),

  // ----------------------------------------------------------------
  // Challenge
  // ----------------------------------------------------------------

  isChallenged: z
    .boolean()
    .optional(),

  challengePassed: z
    .boolean()
    .optional(),

  // ----------------------------------------------------------------
  // Reputation
  // ----------------------------------------------------------------

  reputationEntryId: z
    .string()
    .min(1, 'معرف السمعة غير صالح')
    .optional(),
});

// ==================================================================
// GET SECURITY EVENTS
// GET /api/events
// ==================================================================

export const getEventsQuerySchema = z.object({
  // ----------------------------------------------------------------
  // Pagination
  // ----------------------------------------------------------------

  page: z
    .string()
    .optional()
    .default('1')
    .transform((value) => Number(value))
    .pipe(
      z
        .number()
        .int('رقم الصفحة يجب أن يكون رقمًا صحيحًا')
        .min(1, 'رقم الصفحة يجب أن يكون 1 أو أكبر'),
    ),

  limit: z
    .string()
    .optional()
    .default('20')
    .transform((value) => Number(value))
    .pipe(
      z
        .number()
        .int('عدد النتائج يجب أن يكون رقمًا صحيحًا')
        .min(1, 'عدد النتائج يجب أن يكون 1 أو أكبر')
        .max(100, 'لا يمكن طلب أكثر من 100 Event في المرة الواحدة'),
    ),

  // ----------------------------------------------------------------
  // Basic filters
  // ----------------------------------------------------------------

  serverId: z
    .string()
    .min(1)
    .optional(),

  decision: decisionSchema.optional(),

  ipAddress: z
    .string()
    .trim()
    .min(1)
    .optional(),

  countryCode: z
    .string()
    .trim()
    .length(2, 'كود الدولة يجب أن يكون حرفين')
    .transform((value) => value.toUpperCase())
    .optional(),

  ipType: ipTypeSchema.optional(),

  method: httpMethodSchema.optional(),

  path: z
    .string()
    .trim()
    .min(1)
    .optional(),

  // ----------------------------------------------------------------
  // Risk filters
  // ----------------------------------------------------------------

  minRiskScore: z
    .string()
    .optional()
    .transform((value) => {
      if (value === undefined) return undefined;
      return Number(value);
    })
    .pipe(
      z
        .number()
        .int()
        .min(0)
        .max(100)
        .optional(),
    ),

  maxRiskScore: z
    .string()
    .optional()
    .transform((value) => {
      if (value === undefined) return undefined;
      return Number(value);
    })
    .pipe(
      z
        .number()
        .int()
        .min(0)
        .max(100)
        .optional(),
    ),

  // ----------------------------------------------------------------
  // Challenge filters
  // ----------------------------------------------------------------

  isChallenged: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => {
      if (value === undefined) return undefined;
      return value === 'true';
    }),

  challengePassed: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => {
      if (value === undefined) return undefined;
      return value === 'true';
    }),

  // ----------------------------------------------------------------
  // Reputation
  // ----------------------------------------------------------------

  reputationEntryId: z
    .string()
    .min(1)
    .optional(),

  // ----------------------------------------------------------------
  // Date filters
  // ----------------------------------------------------------------

  startDate: z
    .string()
    .datetime({
      message: 'startDate يجب أن يكون تاريخًا بصيغة ISO صحيحة',
    })
    .optional(),

  endDate: z
    .string()
    .datetime({
      message: 'endDate يجب أن يكون تاريخًا بصيغة ISO صحيحة',
    })
    .optional(),

  // ----------------------------------------------------------------
  // General search
  // ----------------------------------------------------------------

  search: z
    .string()
    .trim()
    .min(1)
    .max(200)
    .optional(),

  // ----------------------------------------------------------------
  // Sorting
  // ----------------------------------------------------------------

  sortBy: z
    .enum([
      'createdAt',
      'riskScore',
      'ipAddress',
      'decision',
      'serverId',
    ])
    .default('createdAt'),

  sortOrder: z
    .enum(['asc', 'desc'])
    .default('desc'),
})
  // ----------------------------------------------------------------
  // Cross-field validation
  // ----------------------------------------------------------------
  .refine(
    (data) => {
      if (
        data.minRiskScore !== undefined &&
        data.maxRiskScore !== undefined
      ) {
        return data.minRiskScore <= data.maxRiskScore;
      }

      return true;
    },
    {
      message: 'minRiskScore يجب أن يكون أقل من أو يساوي maxRiskScore',
      path: ['minRiskScore'],
    },
  )
  .refine(
    (data) => {
      if (data.startDate !== undefined && data.endDate !== undefined) {
        return new Date(data.startDate) <= new Date(data.endDate);
      }

      return true;
    },
    {
      message: 'startDate يجب أن يكون قبل endDate',
      path: ['startDate'],
    },
  );

// ==================================================================
// GET EVENT BY ID
// GET /api/events/:id
// ==================================================================

export const getEventByIdSchema = z.object({
  id: z
    .string()
    .trim()
    .min(1, 'معرف الـ Event مطلوب'),
});

// ==================================================================
// TYPES
// ==================================================================

export type CreateEventInput = z.infer<
  typeof createEventSchema
>;

export type GetEventsQuery = z.infer<
  typeof getEventsQuerySchema
>;

export type GetEventByIdParams = z.infer<
  typeof getEventByIdSchema
>;