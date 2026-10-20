// backend/src/modules/organizations/organizations.service.ts
// ==================================================================
// Zero Plus - Organizations Service
// ==================================================================

import type { FastifyInstance } from 'fastify'
import type { UpdateOrganizationInput } from './organizations.schema.js'

export class OrganizationsService {
  constructor(private fastify: FastifyInstance) {}

  // ================================================================
  // جلب بيانات الشركة الخاصة بالمستخدم المسجل
  // ================================================================
  async getMyOrganization(organizationId: string) {
    const organization = await this.fastify.prisma.organization.findUnique({
      where: { id: organizationId },
      include: {
        _count: {
          select: {
            users: true,
            servers: true,
          },
        },
      },
    })

    if (!organization) {
      throw new Error('الشركة غير موجودة')
    }

    return organization
  }

  // ================================================================
  // تعديل اسم الشركة أو الـ slug
  // ================================================================
  async updateOrganization(organizationId: string, input: UpdateOrganizationInput) {
    // لو بيبعت slug، نتأكد إنه مش مستخدم من شركة تانية
    if (input.slug) {
      const existing = await this.fastify.prisma.organization.findFirst({
        where: {
          slug: input.slug,
          NOT: { id: organizationId },
        },
      })

      if (existing) {
        throw new Error('الـ slug مستخدم بالفعل')
      }
    }

    return await this.fastify.prisma.organization.update({
      where: { id: organizationId },
      data: {
        ...(input.name && { name: input.name }),
        ...(input.slug && { slug: input.slug }),
      },
    })
  }
}
