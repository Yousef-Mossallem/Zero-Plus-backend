// ==================================================================
// Zero Plus - Simulations Token
// ------------------------------------------------------------------
// توكن محاكاة موقّع يصدره الـ Backend مع Start، ويتحقق منه:
//   1) الـ Worker (يمرّره كهيدر لكل طلب)
//   2) الـ Gateway (sim-auth) — بنفس السر والخوارزمية
//
// الشكل:
//   X-ZP-Simulation: <base64url(payloadJson)>.<base64url(hmacSha256)>
//   X-ZP-Sim-Run:    <runId>
//
// الأمان:
//   - HMAC-SHA256 بسر مشترك (SIMULATION_TOKEN_SECRET أو GATEWAY_SECRET)
//   - jti فريد + قائمة إبطال في الذاكرة (Redis اختياري لاحقًا)
//   - exp إلزامي
//   - ربط organizationId + serverId + domain
// ==================================================================

import {
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto'

// ------------------------------------------------------------------
// إعدادات
// ------------------------------------------------------------------

const TOKEN_VERSION = 1 as const
const DEFAULT_TTL_SEC = 30 * 60

/** بادئة الهيدر كما يرسلها الـ Worker */
export const SIM_HEADER_NAME = 'x-zp-simulation'
export const SIM_RUN_HEADER_NAME = 'x-zp-sim-run'

// ------------------------------------------------------------------
// أنواع
// ------------------------------------------------------------------

export interface SimulationTokenPayload {
  /** إصدار العقد */
  v: typeof TOKEN_VERSION
  /** JWT-like id — يُبطَّل عند Stop */
  jti: string
  runId: string
  organizationId: string
  serverId: string
  /** Host المتوقع على Gateway */
  domain: string
  /** unix seconds */
  iat: number
  /** unix seconds */
  exp: number
  /** سقف RPS استرشادي للـ Gateway/Worker */
  maxRps: number
}

export interface IssueSimulationTokenInput {
  runId: string
  organizationId: string
  serverId: string
  domain: string
  /** تاريخ انتهاء صريح — أولوية على ttlSec */
  exp?: Date
  ttlSec?: number
  maxRps?: number
}

export interface IssuedSimulationToken {
  jti: string
  runId: string
  /** القيمة الكاملة للهيدر X-ZP-Simulation */
  headerValue: string
  payload: SimulationTokenPayload
  expiresAt: Date
}

export type VerifySimulationTokenReason =
  | 'ok'
  | 'malformed'
  | 'bad_signature'
  | 'expired'
  | 'revoked'
  | 'version_mismatch'
  | 'payload_invalid'
  | 'run_mismatch'
  | 'org_mismatch'
  | 'domain_mismatch'

export interface VerifySimulationTokenResult {
  ok: boolean
  reason: VerifySimulationTokenReason
  payload?: SimulationTokenPayload
}

export interface VerifySimulationTokenOptions {
  /** لازم يطابق payload.runId إن وُجد */
  expectedRunId?: string
  expectedOrganizationId?: string
  /** Host من الطلب (بدون منفذ) */
  expectedDomain?: string
  /** تسامح ساعة (ثواني) — افتراضي 30s */
  clockSkewSec?: number
}

// ------------------------------------------------------------------
// إبطال jti (ذاكرة العملية)
// للـ multi-instance: انقل لنفس المفتاح في Redis
// ------------------------------------------------------------------

const revokedJti = new Map<string, number>() // jti → exp unix ms

function purgeRevoked(now = Date.now()): void {
  for (const [jti, expMs] of revokedJti) {
    if (expMs <= now) revokedJti.delete(jti)
  }
}

export async function revokeSimulationToken(jti: string): Promise<void> {
  if (!jti) return
  // احتفظ حتى انتهاء صلاحية منطقية (24h سقف)
  const expMs = Date.now() + 24 * 60 * 60 * 1000
  revokedJti.set(jti, expMs)
  purgeRevoked()
}

export function isSimulationTokenRevoked(jti: string): boolean {
  purgeRevoked()
  return revokedJti.has(jti)
}

/** للاختبارات */
export function clearRevokedSimulationTokens(): void {
  revokedJti.clear()
}

// ------------------------------------------------------------------
// سر التوقيع
// ------------------------------------------------------------------

function getSecret(): string {
  const secret =
    process.env.SIMULATION_TOKEN_SECRET ||
    process.env.GATEWAY_SECRET ||
    process.env.GATEWAY_INTERNAL_SECRET ||
    ''
  if (!secret || secret.length < 16) {
    throw new Error(
      '[simulation.token] Missing SIMULATION_TOKEN_SECRET or GATEWAY_SECRET (min 16 chars)',
    )
  }
  return secret
}

// ------------------------------------------------------------------
// Base64url
// ------------------------------------------------------------------

function b64urlEncode(buf: Buffer | string): string {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf, 'utf8')
  return b
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function b64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad
  return Buffer.from(b64, 'base64')
}

// ------------------------------------------------------------------
// HMAC
// ------------------------------------------------------------------

function signBody(bodyB64: string, secret: string): string {
  const mac = createHmac('sha256', secret).update(bodyB64).digest()
  return b64urlEncode(mac)
}

function safeEqualStr(a: string, b: string): boolean {
  const ba = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ba.length !== bb.length) return false
  return timingSafeEqual(ba, bb)
}

// ------------------------------------------------------------------
// بناء / قراءة
// ------------------------------------------------------------------

function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().split(':')[0] || ''
}

function newJti(): string {
  return randomBytes(16).toString('hex')
}

export function encodeSimulationToken(
  payload: SimulationTokenPayload,
  secret = getSecret(),
): string {
  const bodyB64 = b64urlEncode(JSON.stringify(payload))
  const sig = signBody(bodyB64, secret)
  return `${bodyB64}.${sig}`
}

export function parseSimulationTokenShape(
  headerValue: string,
): { bodyB64: string; sigB64: string } | null {
  if (!headerValue || typeof headerValue !== 'string') return null
  const parts = headerValue.trim().split('.')
  if (parts.length !== 2) return null
  const [bodyB64, sigB64] = parts
  if (!bodyB64 || !sigB64) return null
  return { bodyB64, sigB64 }
}

// ------------------------------------------------------------------
// Issue
// ------------------------------------------------------------------

export async function issueSimulationToken(
  input: IssueSimulationTokenInput,
): Promise<IssuedSimulationToken> {
  const secret = getSecret()
  const nowSec = Math.floor(Date.now() / 1000)
  const ttl = input.ttlSec ?? DEFAULT_TTL_SEC
  const expSec = input.exp
    ? Math.floor(input.exp.getTime() / 1000)
    : nowSec + ttl

  if (expSec <= nowSec) {
    throw new Error('[simulation.token] exp must be in the future')
  }

  const domain = normalizeDomain(input.domain)
  if (!domain) {
    throw new Error('[simulation.token] domain is required')
  }
  if (!input.runId || !input.organizationId || !input.serverId) {
    throw new Error('[simulation.token] runId, organizationId, serverId required')
  }

  const payload: SimulationTokenPayload = {
    v: TOKEN_VERSION,
    jti: newJti(),
    runId: input.runId,
    organizationId: input.organizationId,
    serverId: input.serverId,
    domain,
    iat: nowSec,
    exp: expSec,
    maxRps: Math.max(1, Math.floor(input.maxRps ?? 40)),
  }

  const headerValue = encodeSimulationToken(payload, secret)

  return {
    jti: payload.jti,
    runId: payload.runId,
    headerValue,
    payload,
    expiresAt: new Date(expSec * 1000),
  }
}

// ------------------------------------------------------------------
// Verify
// ------------------------------------------------------------------

export function verifySimulationToken(
  headerValue: string,
  options: VerifySimulationTokenOptions = {},
): VerifySimulationTokenResult {
  let secret: string
  try {
    secret = getSecret()
  } catch {
    return { ok: false, reason: 'payload_invalid' }
  }

  const shape = parseSimulationTokenShape(headerValue)
  if (!shape) return { ok: false, reason: 'malformed' }

  const expectedSig = signBody(shape.bodyB64, secret)
  if (!safeEqualStr(expectedSig, shape.sigB64)) {
    return { ok: false, reason: 'bad_signature' }
  }

  let payload: SimulationTokenPayload
  try {
    const json = b64urlDecode(shape.bodyB64).toString('utf8')
    payload = JSON.parse(json) as SimulationTokenPayload
  } catch {
    return { ok: false, reason: 'payload_invalid' }
  }

  if (
    !payload ||
    payload.v !== TOKEN_VERSION ||
    typeof payload.jti !== 'string' ||
    typeof payload.runId !== 'string' ||
    typeof payload.organizationId !== 'string' ||
    typeof payload.serverId !== 'string' ||
    typeof payload.domain !== 'string' ||
    typeof payload.iat !== 'number' ||
    typeof payload.exp !== 'number'
  ) {
    return { ok: false, reason: 'payload_invalid' }
  }

  if (payload.v !== TOKEN_VERSION) {
    return { ok: false, reason: 'version_mismatch' }
  }

  const skew = options.clockSkewSec ?? 30
  const nowSec = Math.floor(Date.now() / 1000)
  if (payload.exp + skew < nowSec) {
    return { ok: false, reason: 'expired', payload }
  }

  if (isSimulationTokenRevoked(payload.jti)) {
    return { ok: false, reason: 'revoked', payload }
  }

  if (options.expectedRunId && options.expectedRunId !== payload.runId) {
    return { ok: false, reason: 'run_mismatch', payload }
  }

  if (
    options.expectedOrganizationId &&
    options.expectedOrganizationId !== payload.organizationId
  ) {
    return { ok: false, reason: 'org_mismatch', payload }
  }

  if (options.expectedDomain) {
    if (normalizeDomain(options.expectedDomain) !== normalizeDomain(payload.domain)) {
      return { ok: false, reason: 'domain_mismatch', payload }
    }
  }

  return { ok: true, reason: 'ok', payload }
}

/**
 * استخراج من هيدرز Fastify / IncomingMessage
 */
export function verifySimulationFromHeaders(
  headers: Record<string, string | string[] | undefined>,
  options: VerifySimulationTokenOptions = {},
): VerifySimulationTokenResult {
  const raw = headers[SIM_HEADER_NAME] ?? headers['X-ZP-Simulation']
  const value = Array.isArray(raw) ? raw[0] : raw
  if (!value) return { ok: false, reason: 'malformed' }

  const runRaw = headers[SIM_RUN_HEADER_NAME] ?? headers['X-ZP-Sim-Run']
  const runHeader = Array.isArray(runRaw) ? runRaw[0] : runRaw

  const result = verifySimulationToken(value, {
    ...options,
    expectedRunId: options.expectedRunId ?? runHeader ?? undefined,
  })
  return result
}

// ------------------------------------------------------------------
// تصدير موحّد
// ------------------------------------------------------------------

export default {
  issueSimulationToken,
  verifySimulationToken,
  verifySimulationFromHeaders,
  revokeSimulationToken,
  isSimulationTokenRevoked,
  clearRevokedSimulationTokens,
  encodeSimulationToken,
  parseSimulationTokenShape,
  SIM_HEADER_NAME,
  SIM_RUN_HEADER_NAME,
  TOKEN_VERSION,
}