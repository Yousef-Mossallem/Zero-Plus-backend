// backend/src/app.ts
// ==================================================================
// Zero Plus - Fastify Application Builder
// هنا بنجمع كل الـ Plugins والـ Modules مع بعض
// ==================================================================

import Fastify from "fastify";
import type { FastifyError } from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import sensible from "@fastify/sensible";

// ------------------------------------------------------------------
// Plugins
// ------------------------------------------------------------------
import prismaPlugin from "./plugins/prisma.plugin.js";
import jwtPlugin from "./plugins/jwt.plugin.js";
import gatewayAuthPlugin from "./plugins/gateway-auth.plugin.js";

// ------------------------------------------------------------------
// Modules (Routes): مرة واحدة فقط لكل موديول
// ------------------------------------------------------------------
import * as authRoutes from "./modules/auth/auth.routes.js";

import policiesRoutes, {
  policiesInternalRoutes,
} from "./modules/policies/policies.routes.js";

import { serverRoutes } from "./modules/servers/servers.routes.js";
import { serversInternalRoutes } from "./modules/servers/servers.gateway.js";
import { readDnsConfig } from "./modules/servers/servers.schema.js";

import reputationRoutes, {
  reputationInternalRoutes,
} from "./modules/reputation/reputation.routes.js";

import { organizationRoutes } from "./modules/organizations/organizations.routes.js";
import eventRoutes from "./modules/events/events.routes.js";

// الموديولات الجاية (بتتفتح واحدة واحدة بعد ما تتكتب):
// import internalEventRoutes from "./modules/events/events.internal.routes.js";
// import { notificationRoutes } from "./modules/notifications/notifications.routes.js";
// import { reportRoutes } from "./modules/reports/reports.routes.js";
// import { simulationRoutes } from "./modules/simulation/simulation.routes.js";

// ------------------------------------------------------------------
// بناء التطبيق
// ------------------------------------------------------------------
export async function buildApp() {
  const app = Fastify({
    logger: {
      level: process.env.NODE_ENV === "development" ? "info" : "warn",
      ...(process.env.NODE_ENV === "development"
        ? {
            transport: {
              target: "pino-pretty",
              options: {
                colorize: true,
                translateTime: "HH:MM:ss",
                ignore: "pid,hostname",
              },
            },
          }
        : {}),
    },
  });

  // ================================================================
  // 1. Security & Core Plugins
  // ================================================================
  await app.register(helmet, {
    contentSecurityPolicy: false, // مفتوحة دلوقتي عشان التطوير
  });

  await app.register(cors, {
    origin: process.env.CORS_ORIGIN || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  });

  // @fastify/sensible in this version exposes the runtime option but not the
  // TypeScript type for it, so we cast here to avoid the duplicate error-handler
  // issue in Fastify 5 without changing runtime behavior.
  await app.register(sensible as any, { errorHandler: false } as any);

  // ================================================================
  // 2. Custom Plugins (Prisma + JWT + Gateway Auth)
  // الترتيب مهم: الـ Routes بتعتمد على decorators بتاعتهم
  //   - fastify.prisma
  //   - fastify.authenticate / fastify.requireRole
  //   - fastify.authenticateGateway
  // ================================================================
  await app.register(prismaPlugin);
  await app.register(jwtPlugin);
  await app.register(gatewayAuthPlugin);
  // await app.register(socketPlugin); // هنفعله لما نبدأ الـ Dashboard الحي

  // ================================================================
  // 2.1 فحص إعدادات الـ DNS وقت التشغيل (تحذير بس، مش بيوقف السيرفر)
  // من غيرهم: تعليمات التوجيه بتطلع فاضية، وخطوة routing بترجع 503
  // ================================================================
  const dnsConfig = readDnsConfig();

  if (!dnsConfig.cnameTarget && dnsConfig.gatewayIps.length === 0) {
    app.log.warn(
      "GATEWAY_CNAME_TARGET و GATEWAY_PUBLIC_IPS مش مضبوطين: تعليمات توجيه الـ DNS هتبقى فاضية وخطوة verify (routing) هترجع 503",
    );
  } else {
    app.log.info(
      {
        cnameTarget: dnsConfig.cnameTarget,
        gatewayIps: dnsConfig.gatewayIps,
      },
      "DNS routing config loaded",
    );
  }

  if (process.env.NODE_ENV === "production" && !process.env.PLATFORM_DOMAINS) {
    app.log.warn(
      "PLATFORM_DOMAINS مش مضبوط: أي شركة تقدر تسجّل دومينات المنصة نفسها",
    );
  }

  // ================================================================
  // 3. Error Handlers
  // لازم قبل تسجيل الـ Routes عشان يتورّثوا لكل الموديولات
  // ================================================================
  app.setErrorHandler((error, request, reply) => {
    const err = error as FastifyError;
    const statusCode =
      typeof err.statusCode === "number" ? err.statusCode : 500;

    if (statusCode >= 500) {
      request.log.error({ err }, "Unhandled error");
    } else {
      request.log.warn({ err }, "Request error");
    }

    return reply.status(statusCode).send({
      success: false,
      code:
        err.code ?? (statusCode >= 500 ? "INTERNAL_ERROR" : "REQUEST_ERROR"),
      // أخطاء السيرفر (5xx) ما بنسرّبش تفاصيلها للعميل
      message: statusCode >= 500 ? "Internal Server Error" : err.message,
    });
  });

  app.setNotFoundHandler((request, reply) => {
    return reply.status(404).send({
      success: false,
      code: "NOT_FOUND",
      message: "المسار غير موجود",
      method: request.method,
      path: request.url,
    });
  });

  // ================================================================
  // 4. Health Check (مفيد جدًا للـ Docker و Nginx)
  // ================================================================
  app.get("/health", async () => {
    return {
      status: "ok",
      service: "zero-plus-backend",
      timestamp: new Date().toISOString(),
    };
  });

  // ================================================================
  // 5. Register Modules (Routes)
  // ================================================================

  // Auth
  await app.register(authRoutes.authRoutes, { prefix: "/auth" });

  // Organizations
  await app.register(organizationRoutes, { prefix: "/organizations" });

  // Policies: Dashboard (JWT)
  await app.register(policiesRoutes, { prefix: "/policies" });
  // Policies: Gateway internal (X-Gateway-Key)
  await app.register(policiesInternalRoutes, { prefix: "/internal/gateway" });

  // Servers: Dashboard (JWT)
  await app.register(serverRoutes, { prefix: "/servers" });
  // Servers: Gateway internal (domain → organizationId)
  await app.register(serversInternalRoutes, { prefix: "/internal/gateway" });

  // Reputation: Dashboard (JWT)
  await app.register(reputationRoutes, { prefix: "/reputation" });
  // Reputation: Gateway internal (X-Gateway-Key)
  await app.register(reputationInternalRoutes, { prefix: "/internal/gateway" });

  // Events: Dashboard (JWT)
  await app.register(eventRoutes, { prefix: "/events" });
  // Events: Gateway internal (X-Gateway-Key): بيتفتح لما الملف يتكتب
  // await app.register(internalEventRoutes, { prefix: "/internal/gateway/events" });

  return app;
}