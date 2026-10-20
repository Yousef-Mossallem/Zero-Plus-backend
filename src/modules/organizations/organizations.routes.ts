// backend/src/modules/organizations/organizations.routes.ts
// ==================================================================
// Zero Plus - Organizations Routes
// ==================================================================

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify'
import { OrganizationsService } from './organizations.service.js'
import { updateOrganizationSchema } from './organizations.schema.js'

export async function organizationRoutes(fastify: FastifyInstance) {
  const service = new OrganizationsService(fastify)

  // ================================================================
  // GET /organizations/me
  // جلب بيانات شركتي
  // ================================================================
  /**
   * محتاج:
   * - Header: Authorization: Bearer <token>
   * - التوكن لازم يكون فيه: organizationId
   *
   * بيرجع:
   * - بيانات الشركة + عدد المستخدمين والسيرفرات
   */
  fastify.get(
    '/me',
    {
      preHandler: [fastify.authenticate], // الحماية عن طريق التوكن
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const { organizationId } = request.user

        const organization = await service.getMyOrganization(organizationId)

        return reply.status(200).send({
          success: true,
          data: organization,
        })
      } catch (error: any) {
        if (error.message === 'الشركة غير موجودة') {
          return reply.status(404).send({
            success: false,
            message: error.message,
          })
        }

        request.log.error(error)
        return reply.status(500).send({
          success: false,
          message: 'Internal server error',
        })
      }
    }
  )

  // ================================================================
  // PATCH /organizations/me
  // تعديل اسم الشركة أو الـ slug
  // ================================================================
  /**
   * محتاج:
   * - Header: Authorization: Bearer <token>
   * - Body (JSON):
   *   {
   *     "name": "اسم جديد"        // اختياري
   *     "slug": "new-slug"        // اختياري
   *   }
   * - لازم تبعت واحد منهم على الأقل
   *
   * بيرجع:
   * - بيانات الشركة بعد التعديل
   */
  fastify.patch(
    '/me',
    {
      preHandler: [fastify.authenticate], // الحماية عن طريق التوكن
    },
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        const { organizationId } = request.user
        const body = updateOrganizationSchema.parse(request.body)

        const updatedOrg = await service.updateOrganization(organizationId, body)

        return reply.status(200).send({
          success: true,
          message: 'تم تحديث البيانات بنجاح',
          data: updatedOrg,
        })
      } catch (error: any) {
        // خطأ من Zod
        if (error.name === 'ZodError') {
          return reply.status(400).send({
            success: false,
            message: 'Validation failed',
            errors: error.errors,
          })
        }

        // الـ slug مستخدم قبل كده
        if (error.message === 'الـ slug مستخدم بالفعل') {
          return reply.status(409).send({
            success: false,
            message: error.message,
          })
        }

        request.log.error(error)
        return reply.status(500).send({
          success: false,
          message: 'Internal server error',
        })
      }
    }
  )
}
