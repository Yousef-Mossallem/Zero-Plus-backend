// ==================================================================
// Zero Plus - Simulations Worker
// ------------------------------------------------------------------
// يرسل ترافيك HTTP حقيقي إلى الـ Gateway حسب SimulationRun:
//   - برك IP (شرعي ~40 / هجوم ~100)
//   - Personas + أوزان النمط
//   - مراحل زمنية (warm → mix → attack → cool)
//   - هيدرز: Host, X-Real-IP, UA, JA3/JA4, توكن المحاكاة, Sim-JS, Sim-AI
//   - يعدّل عدّادات الـ Run عبر SimulationsService
//   - يتوقف عند STOPPED / انتهاء المدة / فشل حرج
//
// لا يقرّر ALLOW/BLOCK — القرار كله عند الـ Gateway + Policy الشركة.
// ==================================================================

import { randomBytes } from 'node:crypto'
import type { FastifyInstance } from 'fastify'
import { SimulationsService } from './simulations.service.js'
import type { SimulationPersona } from './simulations.schema.js'

// ------------------------------------------------------------------
// أنواع الحمولة من الـ Service
// ------------------------------------------------------------------

export interface SimulationWorkerPayload {
  runId: string
  organizationId: string
  serverId: string
  domain: string
  tokenHeader: string
  tokenExpiresAt: Date
  durationSec: number
  targetRps: number
  maxRps: number
  options: Record<string, unknown>
}

interface PersonaWeights {
  legit_ok: number
  legit_sensitive: number
  rate_soft: number
  rate_hard: number
  bot_ua: number
  fail_js: number
  pass_js: number
  bad_ip: number
}

type AiMode = 'auto' | 'fixed' | 'off'

interface WorkerOptions {
  personaWeights: PersonaWeights
  ipPoolLegit: number
  ipPoolAttack: number
  enableJaHeaders: boolean
  aiMode: AiMode
  aiFixedScore: number
  paths: string[]
  seed: number | null
}

// ------------------------------------------------------------------
// RNG بذرة اختيارية (إعادة تشغيل نفس التوزيع)
// ------------------------------------------------------------------

function mulberry32(seed: number) {
  let t = seed >>> 0
  return function rand() {
    t += 0x6d2b79f5
    let r = Math.imul(t ^ (t >>> 15), 1 | t)
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r)
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296
  }
}

function createRng(seed: number | null) {
  if (seed == null || !Number.isFinite(seed)) {
    return Math.random
  }
  return mulberry32(Math.floor(seed))
}

// ------------------------------------------------------------------
// برك IP — نطاقات توثيقية (TEST-NET) مش عشوائية على الإنترنت
// ------------------------------------------------------------------

function buildIpPool(size: number, kind: 'legit' | 'attack', rand: () => number): string[] {
  const out: string[] = []
  // 203.0.113.0/24 (DOCUMENTATION) للشرعي · 198.51.100.0/24 للهجوم
  const base = kind === 'legit' ? [203, 0, 113] : [198, 51, 100]
  const count = Math.max(1, Math.min(size, 250))
  for (let i = 0; i < count; i++) {
    // وزّع على آخر أوكتيت + تنويع خفيف
    const last = 1 + Math.floor(rand() * 253)
    out.push(`${base[0]}.${base[1]}.${base[2]}.${last}`)
  }
  // تأكد من التفرد التقريبي
  return [...new Set(out)]
}

// ------------------------------------------------------------------
// UA / JA وهمية متسقة نسبيًا
// ------------------------------------------------------------------

const UA_BROWSER = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
]

const UA_BOT = [
  'curl/8.4.0',
  'python-requests/2.31.0',
  'Go-http-client/1.1',
  'Wget/1.21',
  'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
]

const JA4_BROWSER = [
  't13d1516h2_8daaf6152771_e5627efa2ab1',
  't13d1517h2_8daaf6152771_b6f405a00624',
  't12d3107h2_e5627efa2ab1_8daaf6152771',
]

const JA3_BROWSER = [
  '579ccef312d18482fc42e2b822ca2430',
  '773906b0efdefa24a7f2b8bb6749ae5c',
  '849d908c90ce395474bbb0bde9b1f4bc',
]

function pick<T>(arr: T[], rand: () => number): T {
  return arr[Math.floor(rand() * arr.length)]!
}

function deviceFp(rand: () => number, stableKey?: string): string {
  if (stableKey) {
    // ثابت لنفس “الجهاز”
    let h = 0
    for (let i = 0; i < stableKey.length; i++) h = (h * 31 + stableKey.charCodeAt(i)) >>> 0
    return `fp_${h.toString(16).padStart(8, '0')}`
  }
  return `fp_${randomBytes(8).toString('hex')}`
}

// ------------------------------------------------------------------
// اختيار Persona حسب الأوزان + مرحلة الزمن
// ------------------------------------------------------------------

function phaseWeights(
  base: PersonaWeights,
  progress: number, // 0..1
): PersonaWeights {
  // 0–20% warm: شرعي
  // 20–45% mix
  // 45–75% attack
  // 75–100% cool
  const w = { ...base }
  if (progress < 0.2) {
    return {
      legit_ok: w.legit_ok + 40,
      legit_sensitive: w.legit_sensitive + 10,
      rate_soft: Math.max(0, w.rate_soft * 0.2),
      rate_hard: 0,
      bot_ua: Math.max(0, w.bot_ua * 0.1),
      fail_js: 0,
      pass_js: w.pass_js + 5,
      bad_ip: 0,
    }
  }
  if (progress < 0.45) {
    return w
  }
  if (progress < 0.75) {
    return {
      legit_ok: Math.max(5, w.legit_ok * 0.4),
      legit_sensitive: w.legit_sensitive,
      rate_soft: w.rate_soft + 15,
      rate_hard: w.rate_hard + 20,
      bot_ua: w.bot_ua + 15,
      fail_js: w.fail_js + 15,
      pass_js: Math.max(0, w.pass_js * 0.5),
      bad_ip: w.bad_ip + 10,
    }
  }
  return {
    legit_ok: w.legit_ok + 30,
    legit_sensitive: w.legit_sensitive,
    rate_soft: Math.max(0, w.rate_soft * 0.3),
    rate_hard: 0,
    bot_ua: Math.max(0, w.bot_ua * 0.2),
    fail_js: 0,
    pass_js: w.pass_js + 5,
    bad_ip: Math.max(0, w.bad_ip * 0.3),
  }
}

function selectPersona(weights: PersonaWeights, rand: () => number): SimulationPersona {
  const entries = Object.entries(weights) as [SimulationPersona, number][]
  const total = entries.reduce((s, [, v]) => s + Math.max(0, v), 0)
  if (total <= 0) return 'legit_ok'
  let r = rand() * total
  for (const [k, v] of entries) {
    r -= Math.max(0, v)
    if (r <= 0) return k
  }
  return entries[entries.length - 1]![0]
}

// ------------------------------------------------------------------
// بناء طلب واحد
// ------------------------------------------------------------------

interface BuiltRequest {
  method: string
  path: string
  headers: Record<string, string>
  persona: SimulationPersona
}

function buildRequest(params: {
  persona: SimulationPersona
  domain: string
  tokenHeader: string
  runId: string
  paths: string[]
  legitIps: string[]
  attackIps: string[]
  enableJa: boolean
  aiMode: AiMode
  aiFixedScore: number
  rand: () => number
  /** جلسات شرعية ثابتة */
  sessionSlot: number
}): BuiltRequest {
  const { persona, domain, tokenHeader, runId, paths, rand } = params
  const sensitivePaths = paths.filter(
    (p) => p.includes('login') || p.includes('admin') || p.includes('api'),
  )
  const normalPaths = paths.length ? paths : ['/']

  let method = 'GET'
  let path = pick(normalPaths, rand)
  let ip = pick(params.legitIps, rand)
  let ua = pick(UA_BROWSER, rand)
  let simJs: string | undefined
  let ai = 0.08 + rand() * 0.12
  let fp = deviceFp(rand, `legit-${params.sessionSlot}`)
  let ja4: string | undefined = pick(JA4_BROWSER, rand)
  let ja3: string | undefined = pick(JA3_BROWSER, rand)

  switch (persona) {
    case 'legit_ok':
      simJs = 'pass'
      break
    case 'legit_sensitive':
      path = sensitivePaths.length ? pick(sensitivePaths, rand) : '/login'
      method = path.includes('login') ? 'POST' : 'GET'
      simJs = 'pass'
      ai = 0.15 + rand() * 0.15
      break
    case 'rate_soft':
      // نفس IP بقوة — الـ Worker يكرره في burst خارجي أيضًا
      ip = params.legitIps[params.sessionSlot % params.legitIps.length]!
      fp = deviceFp(rand, `rate-${ip}`)
      simJs = 'pass'
      break
    case 'rate_hard':
      ip = params.legitIps[0]!
      fp = deviceFp(rand, `rate-hard-${ip}`)
      simJs = 'skip'
      ai = 0.4 + rand() * 0.2
      break
    case 'bot_ua':
      ua = pick(UA_BOT, rand)
      ip = pick(params.attackIps, rand)
      fp = deviceFp(rand)
      ja4 = undefined
      ja3 = undefined
      simJs = 'fail'
      ai = 0.55 + rand() * 0.3
      break
    case 'fail_js':
      ip = pick(params.attackIps, rand)
      simJs = 'fail'
      ai = 0.45 + rand() * 0.25
      break
    case 'pass_js':
      simJs = 'pass'
      path = pick(normalPaths, rand)
      break
    case 'bad_ip':
      ip = pick(params.attackIps, rand)
      ua = pick(UA_BOT, rand)
      simJs = 'fail'
      ai = 0.7 + rand() * 0.25
      ja4 = 't13d0000h0_deadbeef0001_badc0ffee000'
      break
    default:
      simJs = 'pass'
  }

  if (params.aiMode === 'off') ai = 0
  if (params.aiMode === 'fixed') ai = params.aiFixedScore
  ai = Math.min(1, Math.max(0, ai))

  const headers: Record<string, string> = {
    Host: domain,
    'User-Agent': ua,
    Accept: 'text/html,application/json;q=0.9,*/*;q=0.8',
    'X-Real-IP': ip,
    'X-Forwarded-For': ip,
    'X-ZP-Simulation': tokenHeader,
    'X-ZP-Sim-Run': runId,
    'X-ZP-Sim-Persona': persona,
    'X-ZP-Sim-AI': ai.toFixed(3),
    'X-Device-Fingerprint': fp,
  }

  if (simJs) headers['X-ZP-Sim-JS'] = simJs

  if (params.enableJa && ja4) {
    headers['X-JA4'] = ja4
    if (ja3) headers['X-JA3'] = ja3
    headers['X-Edge-Server'] = process.env.ZP_EDGE_TOKEN || 'zeroplus-edge'
  }

  return { method, path, headers, persona }
}

// ------------------------------------------------------------------
// تصنيف رد Gateway للعدادات
// ------------------------------------------------------------------

function classifyStatus(status: number): {
  allowed?: number
  challenged?: number
  rateLimited?: number
  blocked?: number
  failed?: number
} {
  if (status >= 500) return { failed: 1 }
  if (status === 429) return { rateLimited: 1 }
  if (status === 403) return { blocked: 1 }
  if (status === 401) return { challenged: 1 }
  if (status >= 200 && status < 400) return { allowed: 1 }
  if (status >= 400) return { blocked: 1 }
  return { failed: 1 }
}

// ------------------------------------------------------------------
// إرسال طلب واحد
// ------------------------------------------------------------------

function gatewayBaseUrl(): string {
  return (
    process.env.GATEWAY_URL ||
    process.env.ZERO_PLUS_GATEWAY_URL ||
    'http://yousef.com:3000'
  ).replace(/\/$/, '')
}

async function sendOne(
  req: BuiltRequest,
  timeoutMs: number,
): Promise<{ status: number; ms: number; error?: string }> {
  const url = `${gatewayBaseUrl()}${req.path.startsWith('/') ? req.path : `/${req.path}`}`
  const t0 = Date.now()
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), timeoutMs)
  try {
    const res = await fetch(url, {
      method: req.method,
      headers: req.headers,
      signal: ac.signal,
      redirect: 'manual',
      // body بسيط لـ POST
      body: req.method === 'POST' ? '{}' : undefined,
    })
    return { status: res.status, ms: Date.now() - t0 }
  } catch (err) {
    return {
      status: 0,
      ms: Date.now() - t0,
      error: (err as Error).message,
    }
  } finally {
    clearTimeout(timer)
  }
}

// ------------------------------------------------------------------
// parse options
// ------------------------------------------------------------------

function parseOptions(raw: Record<string, unknown>): WorkerOptions {
  const w = (raw.personaWeights ?? {}) as Partial<PersonaWeights>
  return {
    personaWeights: {
      legit_ok: Number(w.legit_ok) || 0,
      legit_sensitive: Number(w.legit_sensitive) || 0,
      rate_soft: Number(w.rate_soft) || 0,
      rate_hard: Number(w.rate_hard) || 0,
      bot_ua: Number(w.bot_ua) || 0,
      fail_js: Number(w.fail_js) || 0,
      pass_js: Number(w.pass_js) || 0,
      bad_ip: Number(w.bad_ip) || 0,
    },
    ipPoolLegit: Math.max(1, Number(raw.ipPoolLegit) || 40),
    ipPoolAttack: Math.max(1, Number(raw.ipPoolAttack) || 100),
    enableJaHeaders: raw.enableJaHeaders !== false,
    aiMode: (raw.aiMode as AiMode) || 'auto',
    aiFixedScore:
      typeof raw.aiFixedScore === 'number' ? raw.aiFixedScore : 0.35,
    paths: Array.isArray(raw.paths)
      ? (raw.paths as string[]).filter((p) => typeof p === 'string')
      : ['/', '/login'],
    seed: typeof raw.seed === 'number' ? raw.seed : null,
  }
}

// ------------------------------------------------------------------
// الحلقة الرئيسية
// ------------------------------------------------------------------

export async function startSimulationWorker(
  fastify: FastifyInstance,
  payload: SimulationWorkerPayload,
): Promise<void> {
  const service = new SimulationsService(fastify)
  const opt = parseOptions(payload.options ?? {})
  const rand = createRng(opt.seed)

  const legitIps = buildIpPool(opt.ipPoolLegit, 'legit', rand)
  const attackIps = buildIpPool(opt.ipPoolAttack, 'attack', rand)

  const startedAt = Date.now()
  const endsAt = startedAt + payload.durationSec * 1000
  const timeoutMs = Number(process.env.SIM_REQUEST_TIMEOUT_MS) || 8000

  // جلسات شرعية ثابتة
  const sessionCount = Math.min(20, Math.max(5, Math.floor(legitIps.length / 2)))

  fastify.log.info(
    {
      runId: payload.runId,
      domain: payload.domain,
      targetRps: payload.targetRps,
      maxRps: payload.maxRps,
      durationSec: payload.durationSec,
      legitIps: legitIps.length,
      attackIps: attackIps.length,
    },
    'simulation worker started',
  )

  let consecutiveNetworkFails = 0

  while (Date.now() < endsAt) {
    const active = await service.isRunActive(
      payload.runId,
      payload.organizationId,
    )
    if (!active) {
      fastify.log.info({ runId: payload.runId }, 'simulation worker stop signal')
      break
    }

    if (payload.tokenExpiresAt.getTime() <= Date.now()) {
      await service.markFailed(
        payload.runId,
        payload.organizationId,
        'Simulation token expired during run',
      )
      break
    }

    const progress =
      (Date.now() - startedAt) / Math.max(1, payload.durationSec * 1000)
    const weights = phaseWeights(opt.personaWeights, progress)

    // RPS ديناميكي: هادئ → أعلى في وسط الهجوم → هدوء
    let rps = payload.targetRps
    if (progress >= 0.45 && progress < 0.75) {
      rps = Math.min(payload.maxRps, Math.round(payload.targetRps * 1.8))
    } else if (progress >= 0.75) {
      rps = Math.max(1, Math.round(payload.targetRps * 0.5))
    }
    rps = Math.min(payload.maxRps, Math.max(1, rps))

    // دفعات صغيرة مع jitter بدل sleep ثابت
    const batch = Math.min(10, Math.max(1, Math.round(rps / 5)))
    const batchStarted = Date.now()

    const tasks: Promise<void>[] = []
    for (let i = 0; i < batch; i++) {
      const persona = selectPersona(weights, rand)

      // rate_hard: رشقة من نفس البناء
      const repeats =
        persona === 'rate_hard' ? 3 + Math.floor(rand() * 4) : persona === 'rate_soft' ? 2 : 1

      for (let k = 0; k < repeats; k++) {
        const req = buildRequest({
          persona,
          domain: payload.domain,
          tokenHeader: payload.tokenHeader,
          runId: payload.runId,
          paths: opt.paths,
          legitIps,
          attackIps,
          enableJa: opt.enableJaHeaders,
          aiMode: opt.aiMode,
          aiFixedScore: opt.aiFixedScore,
          rand,
          sessionSlot: Math.floor(rand() * sessionCount),
        })

        tasks.push(
          (async () => {
            const result = await sendOne(req, timeoutMs)
            const delta =
              result.status === 0
                ? { sent: 1, failed: 1 }
                : { sent: 1, ...classifyStatus(result.status) }

            await service.applyCounters(payload.runId, payload.organizationId, {
              ...delta,
              latencyMsSample: result.ms,
            })

            if (result.status === 0) consecutiveNetworkFails++
            else consecutiveNetworkFails = 0
          })(),
        )
      }
    }

    await Promise.all(tasks)

    if (consecutiveNetworkFails >= 25) {
      await service.markFailed(
        payload.runId,
        payload.organizationId,
        'Too many network failures reaching Gateway — is GATEWAY_URL up?',
      )
      break
    }

    // اضبط الإيقاع ليقارب الـ RPS المستهدف
    const elapsed = Date.now() - batchStarted
    const expectedMs = (batch / rps) * 1000
    const sleepMs = Math.max(0, expectedMs - elapsed + (rand() * 40 - 20))
    if (sleepMs > 0) {
      await new Promise((r) => setTimeout(r, sleepMs))
    }
  }

  // إن لسه RUNNING → COMPLETED
  const still = await service.isRunActive(payload.runId, payload.organizationId)
  if (still) {
    await service.markCompleted(payload.runId, payload.organizationId)
  }

  fastify.log.info({ runId: payload.runId }, 'simulation worker finished')
}

export default {
  startSimulationWorker,
}