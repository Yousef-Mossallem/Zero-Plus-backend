
// ==================================================================
// Zero Plus - Prisma Plugin
// بيربط Fastify بقاعدة البيانات عن طريق Prisma Client
// ==================================================================

import fp from 'fastify-plugin'
import { PrismaClient } from '@prisma/client'
import { PrismaPg } from '@prisma/adapter-pg'
import type { FastifyPluginAsync } from 'fastify'

// ------------------------------------------------------------------
// TypeScript Declaration Merging
// عشان TypeScript يعرف إن fastify.prisma موجود
// ------------------------------------------------------------------

declare module 'fastify' {
  interface FastifyInstance {
    prisma: PrismaClient
  }
}

// ------------------------------------------------------------------
// الـ Plugin نفسه
// ------------------------------------------------------------------

const prismaPlugin: FastifyPluginAsync = async (fastify) => {
  // --------------------------------------------------------------
  // Prisma PostgreSQL Driver Adapter
  // Prisma 7 يحتاج Adapter عند الاتصال بـ PostgreSQL
  // --------------------------------------------------------------

  const adapter = new PrismaPg({
    connectionString: process.env.DATABASE_URL,
  })

  const prisma = new PrismaClient({
    adapter,

    // في مرحلة التطوير ممكن تفتح اللوج عشان تشوف الـ Queries
    // log:
    //   process.env.NODE_ENV === 'development'
    //     ? ['query', 'info', 'warn', 'error']
    //     : ['error'],
  })

  // --------------------------------------------------------------
  // نتأكد إن الاتصال بقاعدة البيانات شغال
  // --------------------------------------------------------------

  try {
    await prisma.$connect()

    fastify.log.info('✅ Prisma connected to database successfully')
  } catch (error) {
    fastify.log.error('❌ Failed to connect to database')

    // لو فشل الاتصال، السيرفر ميكملش
    throw error
  }

  // --------------------------------------------------------------
  // نضيف Prisma على الـ Fastify instance
  // --------------------------------------------------------------

  fastify.decorate('prisma', prisma)

  // --------------------------------------------------------------
  // لما السيرفر يقفل → نقفل اتصال قاعدة البيانات بشكل نظيف
  // --------------------------------------------------------------

  fastify.addHook('onClose', async (instance) => {
    await instance.prisma.$disconnect()

    instance.log.info('Prisma disconnected')
  })
}

// ------------------------------------------------------------------
// بنستخدم fastify-plugin عشان الـ decoration يبان
// في كل الـ plugins والـ routes
// ------------------------------------------------------------------

export default fp(prismaPlugin, {
  name: 'prisma',
})

