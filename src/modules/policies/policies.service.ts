// backend/src/modules/policies/policies.service.ts
// ==================================================================
// Zero Plus - Policies Service
// ------------------------------------------------------------------
// مسؤول عن:
//   - قراءة/إنشاء Policy الشركة (سجل واحد لكل Organization)
//   - تعديل الإعدادات (كلها في إيد الشركة) مع فحص الترابط بين الحقول
//   - إعادة الإعدادات للافتراضي (كلها أو حقول محددة)
//   - تسجيل كل تعديل كـ Notification (POLICY_CHANGED) للمراجعة
//   - تحديد (Server + Organization + Policy) للـ Gateway من الـ Host
//
// قواعد أساسية:
//   1) organizationId للـ Dashboard بييجي من JWT فقط (الـ Routes مسؤولة)
//   2) الـ Gateway بيحدد الشركة من الـ Host/serverId، مش من body
//   3) الفحص الكامل للترابط بيتم على القيم بعد الدمج مع الحالية
//   4) التعديل داخل Transaction (Serializable) لمنع تعارض تعديلين مع بعض
// ==================================================================

import { Prisma, type Policy } from '@prisma/client'
import type { FastifyInstance } from 'fastify'

import {
  POLICY_DEFAULTS,
  POLICY_EDITABLE_FIELDS,
  findPolicyViolations,
  normalizeHost,
} from './policies.schema.js'

import type {
  GatewayPolicyPayload,
  GatewayResolveResult,
  PolicyFieldKey,
  PolicyValues,
  ResetPolicyInput,
  UpdatePolicyInput,
} from './policies.schema.js'

// ==================================================================
// Types & Errors
// ==================================================================

/** مين عمل التعديل (للـ Audit في الـ Notification) */
export interface PolicyActor {
  userId: string
  email?: string
}

export type PolicyFieldValue = number | boolean | null

/** تغيير واحد (قبل → بعد) */
export interface PolicyChange {
  field: PolicyFieldKey
  from: PolicyFieldValue
  to: PolicyFieldValue
}

export interface PolicyMutationResult {
  policy: Policy
  /** الحقول اللي اتغيرت فعليًا (فاضية لو مفيش تغيير حقيقي) */
  changes: PolicyChange[]
}

/**
 * Error مخصص بيتحول لـ HTTP status في الـ Routes.
 * details: تفاصيل مفيدة للعميل (مثلًا قائمة مخالفات الترابط).
 */
export class PolicyServiceError extends Error {
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
    this.name = 'PolicyServiceError'
    this.statusCode = statusCode
    this.code = code
    this.details = details
  }
}

// ==================================================================
// Helpers
// ==================================================================

/** تحويل صف Prisma لقيم الـ Policy فقط (من غير id ولا timestamps) */
function toPolicyValues(policy: Policy): PolicyValues {
  return {
    allowMaxScore: policy.allowMaxScore,
    rateLimitMaxScore: policy.rateLimitMaxScore,
    challengeMaxScore: policy.challengeMaxScore,

    enableJsChallenge: policy.enableJsChallenge,
    challengeAllVisitors: policy.challengeAllVisitors,
    passTokenTtlMinutes: policy.passTokenTtlMinutes,

    rateLimitRequests: policy.rateLimitRequests,
    rateLimitWindowSec: policy.rateLimitWindowSec,

    maxRequestsPerIp: policy.maxRequestsPerIp,
    maxRequestsWindowSec: policy.maxRequestsWindowSec,
    banOnMaxRequests: policy.banOnMaxRequests,
    maxServerRps: policy.maxServerRps,
    capacityWarnPercent: policy.capacityWarnPercent,

    autoBanAfterFails: policy.autoBanAfterFails,
    temporaryBanMinutes: policy.temporaryBanMinutes,
    permanentBanScore: policy.permanentBanScore,

    enableAiAnomaly: policy.enableAiAnomaly,
  }
}

/** شيل أي حقل قيمته undefined (عشان الدمج ما يمسحش قيمة حالية بالغلط) */
function stripUndefined(patch: Partial<PolicyValues>): Partial<PolicyValues> {
  return Object.fromEntries(
    Object.entries(patch).filter(([, value]) => value !== undefined),
  ) as Partial<PolicyValues>
}

/** المقارنة بين القيم الحالية والجديدة: بترجع الحقول اللي اتغيرت فقط */
function diffPolicy(current: PolicyValues, next: PolicyValues): PolicyChange[] {
  const changes: PolicyChange[] = []

  for (const field of POLICY_EDITABLE_FIELDS) {
    if (current[field] !== next[field]) {
      changes.push({ field, from: current[field], to: next[field] })
    }
  }

  return changes
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

// أعمدة السيرفر اللي الـ Gateway محتاجها (مش أكتر)
const SERVER_RESOLVE_SELECT = {
  id: true,
  domain: true,
  originIp: true,
  originPort: true,
  status: true,
  mode: true,
  maxRequestsPerSecond: true,
  organizationId: true,
  organization: {
    select: {
      isActive: true,
    },
  },
} satisfies Prisma.ServerSelect

type ServerResolveRow = Prisma.ServerGetPayload<{
  select: typeof SERVER_RESOLVE_SELECT
}>

// ==================================================================
// Service
// ==================================================================

export class PoliciesService {
  constructor(private readonly fastify: FastifyInstance) {}

  // ================================================================
  // إنشاء/قراءة (Lazy Creation)
  // ================================================================

  /**
   * بيرجّع Policy الشركة، ولو مش موجودة بيعملها بالقيم الافتراضية
   * (الافتراضي بييجي من @default في schema.prisma).
   *
   * مهم: بنستخدم createMany + skipDuplicates بدل create + catch،
   * لأن أي error جوه Transaction في Postgres بيبوّظ الـ Transaction كلها،
   * وskipDuplicates بيتعامل مع السباق (طلبين مع بعض) من غير error أصلًا.
   */
  private async ensurePolicy(
    db: Prisma.TransactionClient,
    organizationId: string,
  ): Promise<Policy> {
    const existing = await db.policy.findUnique({
      where: { organizationId },
    })

    if (existing) return existing

    try {
      await db.policy.createMany({
        data: [{ organizationId }],
        skipDuplicates: true,
      })
    } catch (error) {
      // P2003: organizationId مش موجود في جدول Organization
      if (isPrismaError(error, 'P2003')) {
        throw new PolicyServiceError(
          'المؤسسة غير موجودة',
          404,
          'ORGANIZATION_NOT_FOUND',
        )
      }
      throw error
    }

    return db.policy.findUniqueOrThrow({ where: { organizationId } })
  }

  /** Policy الشركة (للـ Dashboard) */
  async getPolicyByOrganization(organizationId: string): Promise<Policy> {
    return this.ensurePolicy(this.fastify.prisma, organizationId)
  }

  /** القيم الافتراضية (لزرار "Reset" وعرض الافتراضي في الـ Dashboard) */
  getDefaults() {
    return { ...POLICY_DEFAULTS }
  }

  // ================================================================
  // تعديل + Reset
  // ================================================================

  /**
   * تعديل الـ Policy (Partial).
   * ملاحظة: لو مفيش تغيير حقيقي (نفس القيم الحالية) مبيحصلش write
   * وpolicyVersion (updatedAt) بيفضل زي ما هو.
   */
  async updatePolicy(
    organizationId: string,
    input: UpdatePolicyInput,
    actor?: PolicyActor,
  ): Promise<PolicyMutationResult> {
    return this.applyPatch(organizationId, input, 'update', actor)
  }

  /**
   * رجوع للافتراضي:
   *   - من غير fields → كل الإعدادات
   *   - مع fields    → الحقول دي بس
   */
  async resetPolicy(
    organizationId: string,
    input: ResetPolicyInput,
    actor?: PolicyActor,
  ): Promise<PolicyMutationResult> {
    const fields: readonly PolicyFieldKey[] =
      input.fields ?? POLICY_EDITABLE_FIELDS

    const patch: Record<string, PolicyFieldValue> = {}

    for (const field of fields) {
      patch[field] = POLICY_DEFAULTS[field]
    }

    return this.applyPatch(
      organizationId,
      patch as Partial<PolicyValues>,
      'reset',
      actor,
    )
  }

  /**
   * المنطق المشترك للتعديل والـ Reset:
   *   1) جيب الحالية (أو اعملها)
   *   2) ادمج التعديل معاها
   *   3) افحص الترابط على القيم النهائية (مش على المبعوت بس)
   *   4) احسب التغييرات الفعلية
   *   5) update + Notification في نفس الـ Transaction
   */
  private async applyPatch(
    organizationId: string,
    patch: Partial<PolicyValues>,
    action: 'update' | 'reset',
    actor?: PolicyActor,
  ): Promise<PolicyMutationResult> {
    const result = await this.runSerializable(async (tx) => {
      const current = await this.ensurePolicy(tx, organizationId)
      const currentValues = toPolicyValues(current)

      // (2) الدمج
      const merged: PolicyValues = {
        ...currentValues,
        ...stripUndefined(patch),
      }

      // (3) فحص الترابط على القيم النهائية
      const violations = findPolicyViolations(merged)

      if (violations.length > 0) {
        throw new PolicyServiceError(
          violations[0]!.message,
          400,
          'INVALID_POLICY',
          violations,
        )
      }

      // (4) التغييرات الفعلية
      const changes = diffPolicy(currentValues, merged)

      if (changes.length === 0) {
        return { policy: current, changes }
      }

      // (5) الكتابة: الحقول اللي اتغيرت بس
      const data: Record<string, PolicyFieldValue> = {}

      for (const change of changes) {
        data[change.field] = change.to
      }

      const policy = await tx.policy.update({
        where: { organizationId },
        data: data as Prisma.PolicyUpdateInput,
      })

      // سجل المراجعة: مين غيّر إيه
      const changedNames = changes.map((c) => c.field).join('، ')

      await tx.notification.create({
        data: {
          organizationId,
          type: 'POLICY_CHANGED',
          title:
            action === 'reset'
              ? 'تمت إعادة إعدادات الحماية للافتراضي'
              : 'تم تعديل إعدادات الحماية',
          message: `${
            actor?.email ? `قام ${actor.email} ب` : 'تم '
          }${action === 'reset' ? 'إعادة ضبط' : 'تعديل'}: ${changedNames}`,
          severity: 2,
          metadata: {
            action,
            changedByUserId: actor?.userId ?? null,
            changedByEmail: actor?.email ?? null,
            changes: changes.map((c) => ({
              field: c.field,
              from: c.from,
              to: c.to,
            })),
          } as Prisma.InputJsonObject,
        },
      })

      return { policy, changes }
    })

    if (result.changes.length > 0) {
      this.fastify.log.info(
        {
          organizationId,
          action,
          actorUserId: actor?.userId,
          fields: result.changes.map((c) => c.field),
        },
        'Policy changed',
      )
    }

    return result
  }

  /**
   * Transaction بأعلى مستوى عزل (Serializable) مع إعادة محاولة:
   * بيمنع إن تعديلين متزامنين يعدّوا كل واحد لوحده بس مع بعض يكسروا الترتيب.
   */
  private async runSerializable<T>(
    fn: (tx: Prisma.TransactionClient) => Promise<T>,
  ): Promise<T> {
    const MAX_ATTEMPTS = 3

    for (let attempt = 1; ; attempt++) {
      try {
        return await this.fastify.prisma.$transaction(fn, {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
        })
      } catch (error) {
        // P2034: تعارض بين Transactions
        if (isPrismaError(error, 'P2034')) {
          if (attempt < MAX_ATTEMPTS) continue

          throw new PolicyServiceError(
            'حصل تعارض أثناء حفظ الإعدادات، حاول مرة أخرى',
            409,
            'CONFLICT',
          )
        }

        throw error
      }
    }
  }

  // ================================================================
  // Gateway
  // ================================================================

  /** Policy الشركة بالشكل اللي الـ Gateway بيستخدمه */
  async getGatewayPolicy(
    organizationId: string,
  ): Promise<GatewayPolicyPayload> {
    const policy = await this.getPolicyByOrganization(organizationId)

    return {
      organizationId: policy.organizationId,
      ...toPolicyValues(policy),
    }
  }

  /**
   * ⭐ الأساسي للـ Gateway:
   * من الـ Host (shop.example.com) يرجّع السيرفر + الشركة + الـ Policy في رد واحد.
   * الـ Gateway يعمل cache للنتيجة ويقارن policyVersion.
   */
  async resolveByHost(rawHost: string): Promise<GatewayResolveResult> {
    // الـ Route بتوحّد الشكل، وإحنا بنوحّده هنا كمان كحماية
    const host = normalizeHost(rawHost)

    const server = await this.fastify.prisma.server.findUnique({
      where: { domain: host },
      select: SERVER_RESOLVE_SELECT,
    })

    if (!server) {
      throw new PolicyServiceError(
        'لا يوجد سيرفر محمي بهذا الدومين',
        404,
        'SERVER_NOT_FOUND',
      )
    }

    return this.buildResolveResult(server)
  }

  /** نفس النتيجة بس من serverId (لو الـ Gateway عارفه) */
  async resolveByServerId(serverId: string): Promise<GatewayResolveResult> {
    const server = await this.fastify.prisma.server.findUnique({
      where: { id: serverId },
      select: SERVER_RESOLVE_SELECT,
    })

    if (!server) {
      throw new PolicyServiceError(
        'السيرفر غير موجود',
        404,
        'SERVER_NOT_FOUND',
      )
    }

    return this.buildResolveResult(server)
  }

  /**
   * نسخة الـ Policy فقط (رد خفيف):
   * الـ Gateway يسأل عنها كل شوية، ولو اتغيرت يطلب resolve كامل.
   */
  async getPolicyVersion(
    organizationId: string,
  ): Promise<{ organizationId: string; policyVersion: string }> {
    const policy = await this.getPolicyByOrganization(organizationId)

    return {
      organizationId: policy.organizationId,
      policyVersion: policy.updatedAt.toISOString(),
    }
  }

  private async buildResolveResult(
    server: ServerResolveRow,
  ): Promise<GatewayResolveResult> {
    // شركة موقوفة: الـ Gateway هو اللي يقرر يعمل إيه (غالبًا يمرّر أو يرفض)
    if (!server.organization.isActive) {
      throw new PolicyServiceError(
        'المؤسسة المالكة لهذا السيرفر غير مفعّلة',
        403,
        'ORGANIZATION_INACTIVE',
      )
    }

    const policy = await this.getPolicyByOrganization(server.organizationId)
    const values = toPolicyValues(policy)

    return {
      organizationId: server.organizationId,

      server: {
        id: server.id,
        domain: server.domain,
        originIp: server.originIp,
        originPort: server.originPort,
        status: server.status,
        mode: server.mode,
        maxRequestsPerSecond: server.maxRequestsPerSecond,
      },

      policy: {
        organizationId: policy.organizationId,
        ...values,
      },

      // الشركة هي اللي بتحدد السقف، ولو ما حددتش ناخد سعة السيرفر الفعلية
      effectiveMaxServerRps:
        values.maxServerRps ?? server.maxRequestsPerSecond ?? null,

      policyVersion: policy.updatedAt.toISOString(),
    }
  }
}