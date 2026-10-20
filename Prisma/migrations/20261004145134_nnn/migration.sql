-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('OWNER', 'ADMIN', 'ANALYST', 'VIEWER');

-- CreateEnum
CREATE TYPE "ServerStatus" AS ENUM ('PENDING', 'ONLINE', 'DEGRADED', 'OFFLINE', 'MAINTENANCE');

-- CreateEnum
CREATE TYPE "Decision" AS ENUM ('ALLOW', 'RATE_LIMIT', 'CHALLENGE', 'BLOCK');

-- CreateEnum
CREATE TYPE "BanStatus" AS ENUM ('NONE', 'TEMPORARY', 'PERMANENT');

-- CreateEnum
CREATE TYPE "IpType" AS ENUM ('RESIDENTIAL', 'MOBILE', 'DATACENTER', 'VPN_PROXY', 'TOR', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "ThreatCategory" AS ENUM ('DDOS_BURST', 'BOTNET', 'BRUTE_FORCE', 'SCRAPER', 'SUSPICIOUS_BEHAVIOR', 'KNOWN_MALICIOUS', 'SMOKESCREEN', 'OTHER');

-- CreateEnum
CREATE TYPE "NotificationType" AS ENUM ('DDOS_START', 'NEW_BLOCK', 'CRITICAL_REPUTATION', 'SERVER_CAPACITY_WARNING', 'SERVER_RECOVERY', 'POLICY_CHANGED', 'SYSTEM');

-- CreateEnum
CREATE TYPE "ReportStatus" AS ENUM ('PENDING', 'GENERATING', 'READY', 'FAILED');

-- CreateEnum
CREATE TYPE "ChallengeType" AS ENUM ('JS_SILENT', 'RATE_LIMIT_SOFT', 'CAPTCHA_FALLBACK');

-- CreateEnum
CREATE TYPE "SimulationPattern" AS ENUM ('NORMAL', 'SUSPICIOUS_BURST', 'REPEATED_REQUESTS', 'UNUSUAL_BEHAVIOR', 'KNOWN_TEST_SOURCE');

-- CreateTable
CREATE TABLE "Organization" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "plan" TEXT NOT NULL DEFAULT 'free',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "role" "UserRole" NOT NULL DEFAULT 'OWNER',
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "lastLoginAt" TIMESTAMP(3),
    "organizationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Server" (
    "id" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "originIp" TEXT NOT NULL,
    "originPort" INTEGER NOT NULL DEFAULT 443,
    "status" "ServerStatus" NOT NULL DEFAULT 'PENDING',
    "maxRequestsPerSecond" INTEGER,
    "cpuCores" INTEGER,
    "ramMb" INTEGER,
    "avgResponseTimeMs" INTEGER,
    "currentLoadPercent" DOUBLE PRECISION,
    "lastHealthCheckAt" TIMESTAMP(3),
    "dnsVerified" BOOLEAN NOT NULL DEFAULT false,
    "originReachable" BOOLEAN NOT NULL DEFAULT false,
    "sslEnabled" BOOLEAN NOT NULL DEFAULT true,
    "organizationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Server_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReputationEntry" (
    "id" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "deviceFingerprint" TEXT,
    "ja3Fingerprint" TEXT,
    "ja4Fingerprint" TEXT,
    "countryCode" TEXT,
    "asn" INTEGER,
    "asOrg" TEXT,
    "ipType" "IpType" NOT NULL DEFAULT 'UNKNOWN',
    "score" INTEGER NOT NULL DEFAULT 1,
    "banStatus" "BanStatus" NOT NULL DEFAULT 'NONE',
    "bannedUntil" TIMESTAMP(3),
    "failedChecksCount" INTEGER NOT NULL DEFAULT 0,
    "successfulChecks" INTEGER NOT NULL DEFAULT 0,
    "totalRequests" INTEGER NOT NULL DEFAULT 0,
    "lastPath" TEXT,
    "lastUserAgent" TEXT,
    "avgRequestRate" DOUBLE PRECISION,
    "isKnownBotnet" BOOLEAN NOT NULL DEFAULT false,
    "organizationId" TEXT NOT NULL,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ReputationEntry_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityEvent" (
    "id" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "userAgent" TEXT,
    "referer" TEXT,
    "requestId" TEXT,
    "riskScore" INTEGER NOT NULL,
    "anomalyScore" DOUBLE PRECISION,
    "confidence" DOUBLE PRECISION,
    "decision" "Decision" NOT NULL,
    "reasonSummary" TEXT,
    "reasonDetails" JSONB,
    "countryCode" TEXT,
    "asn" INTEGER,
    "ipType" "IpType",
    "isChallenged" BOOLEAN NOT NULL DEFAULT false,
    "challengePassed" BOOLEAN,
    "serverId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "reputationEntryId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecurityEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ChallengeLog" (
    "id" TEXT NOT NULL,
    "challengeType" "ChallengeType" NOT NULL,
    "passed" BOOLEAN NOT NULL,
    "durationMs" INTEGER,
    "failureReason" TEXT,
    "reputationEntryId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ChallengeLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Policy" (
    "id" TEXT NOT NULL,
    "allowMaxScore" INTEGER NOT NULL DEFAULT 30,
    "rateLimitMaxScore" INTEGER NOT NULL DEFAULT 60,
    "challengeMaxScore" INTEGER NOT NULL DEFAULT 80,
    "rateLimitRequests" INTEGER NOT NULL DEFAULT 30,
    "rateLimitWindowSec" INTEGER NOT NULL DEFAULT 60,
    "autoBanAfterFails" INTEGER NOT NULL DEFAULT 2,
    "temporaryBanMinutes" INTEGER NOT NULL DEFAULT 120,
    "permanentBanScore" INTEGER NOT NULL DEFAULT 9,
    "enableJsChallenge" BOOLEAN NOT NULL DEFAULT true,
    "enableAiAnomaly" BOOLEAN NOT NULL DEFAULT true,
    "organizationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Policy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Notification" (
    "id" TEXT NOT NULL,
    "type" "NotificationType" NOT NULL,
    "title" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "severity" INTEGER NOT NULL DEFAULT 1,
    "isRead" BOOLEAN NOT NULL DEFAULT false,
    "metadata" JSONB,
    "organizationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Notification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Report" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "status" "ReportStatus" NOT NULL DEFAULT 'PENDING',
    "periodStart" TIMESTAMP(3) NOT NULL,
    "periodEnd" TIMESTAMP(3) NOT NULL,
    "content" TEXT,
    "summary" TEXT,
    "eventCount" INTEGER NOT NULL DEFAULT 0,
    "blockedCount" INTEGER NOT NULL DEFAULT 0,
    "metadata" JSONB,
    "organizationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Report_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SimulationRun" (
    "id" TEXT NOT NULL,
    "pattern" "SimulationPattern" NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'running',
    "targetRps" INTEGER NOT NULL,
    "durationSec" INTEGER,
    "totalSent" INTEGER NOT NULL DEFAULT 0,
    "totalBlocked" INTEGER NOT NULL DEFAULT 0,
    "totalAllowed" INTEGER NOT NULL DEFAULT 0,
    "serverId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "stoppedAt" TIMESTAMP(3),

    CONSTRAINT "SimulationRun_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Organization_slug_key" ON "Organization"("slug");

-- CreateIndex
CREATE INDEX "Organization_slug_idx" ON "Organization"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_organizationId_idx" ON "User"("organizationId");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE INDEX "Server_organizationId_idx" ON "Server"("organizationId");

-- CreateIndex
CREATE INDEX "Server_status_idx" ON "Server"("status");

-- CreateIndex
CREATE UNIQUE INDEX "Server_organizationId_domain_key" ON "Server"("organizationId", "domain");

-- CreateIndex
CREATE INDEX "ReputationEntry_organizationId_idx" ON "ReputationEntry"("organizationId");

-- CreateIndex
CREATE INDEX "ReputationEntry_banStatus_idx" ON "ReputationEntry"("banStatus");

-- CreateIndex
CREATE INDEX "ReputationEntry_score_idx" ON "ReputationEntry"("score");

-- CreateIndex
CREATE INDEX "ReputationEntry_ja3Fingerprint_idx" ON "ReputationEntry"("ja3Fingerprint");

-- CreateIndex
CREATE INDEX "ReputationEntry_ja4Fingerprint_idx" ON "ReputationEntry"("ja4Fingerprint");

-- CreateIndex
CREATE INDEX "ReputationEntry_ipType_idx" ON "ReputationEntry"("ipType");

-- CreateIndex
CREATE UNIQUE INDEX "ReputationEntry_organizationId_ipAddress_key" ON "ReputationEntry"("organizationId", "ipAddress");

-- CreateIndex
CREATE INDEX "SecurityEvent_organizationId_idx" ON "SecurityEvent"("organizationId");

-- CreateIndex
CREATE INDEX "SecurityEvent_serverId_idx" ON "SecurityEvent"("serverId");

-- CreateIndex
CREATE INDEX "SecurityEvent_ipAddress_idx" ON "SecurityEvent"("ipAddress");

-- CreateIndex
CREATE INDEX "SecurityEvent_decision_idx" ON "SecurityEvent"("decision");

-- CreateIndex
CREATE INDEX "SecurityEvent_riskScore_idx" ON "SecurityEvent"("riskScore");

-- CreateIndex
CREATE INDEX "SecurityEvent_createdAt_idx" ON "SecurityEvent"("createdAt");

-- CreateIndex
CREATE INDEX "ChallengeLog_reputationEntryId_idx" ON "ChallengeLog"("reputationEntryId");

-- CreateIndex
CREATE INDEX "ChallengeLog_organizationId_idx" ON "ChallengeLog"("organizationId");

-- CreateIndex
CREATE INDEX "ChallengeLog_passed_idx" ON "ChallengeLog"("passed");

-- CreateIndex
CREATE UNIQUE INDEX "Policy_organizationId_key" ON "Policy"("organizationId");

-- CreateIndex
CREATE INDEX "Notification_organizationId_idx" ON "Notification"("organizationId");

-- CreateIndex
CREATE INDEX "Notification_isRead_idx" ON "Notification"("isRead");

-- CreateIndex
CREATE INDEX "Notification_createdAt_idx" ON "Notification"("createdAt");

-- CreateIndex
CREATE INDEX "Report_organizationId_idx" ON "Report"("organizationId");

-- CreateIndex
CREATE INDEX "Report_status_idx" ON "Report"("status");

-- CreateIndex
CREATE INDEX "SimulationRun_organizationId_idx" ON "SimulationRun"("organizationId");

-- CreateIndex
CREATE INDEX "SimulationRun_serverId_idx" ON "SimulationRun"("serverId");

-- CreateIndex
CREATE INDEX "SimulationRun_status_idx" ON "SimulationRun"("status");

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Server" ADD CONSTRAINT "Server_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ReputationEntry" ADD CONSTRAINT "ReputationEntry_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityEvent" ADD CONSTRAINT "SecurityEvent_serverId_fkey" FOREIGN KEY ("serverId") REFERENCES "Server"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityEvent" ADD CONSTRAINT "SecurityEvent_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityEvent" ADD CONSTRAINT "SecurityEvent_reputationEntryId_fkey" FOREIGN KEY ("reputationEntryId") REFERENCES "ReputationEntry"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChallengeLog" ADD CONSTRAINT "ChallengeLog_reputationEntryId_fkey" FOREIGN KEY ("reputationEntryId") REFERENCES "ReputationEntry"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Policy" ADD CONSTRAINT "Policy_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SimulationRun" ADD CONSTRAINT "SimulationRun_serverId_fkey" FOREIGN KEY ("serverId") REFERENCES "Server"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SimulationRun" ADD CONSTRAINT "SimulationRun_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
