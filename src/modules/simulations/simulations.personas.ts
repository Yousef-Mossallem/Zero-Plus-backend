// ==================================================================
// Zero Plus - Simulations Personas
// ------------------------------------------------------------------
// بناء طلب محاكاة واحد: IP / UA / JA / path / Sim-JS / Sim-AI / device
// + برك IP تدعم Geo lookup حقيقي (ليس TEST-NET فقط)
// متوافق مع: simulations.schema · service.options · worker · الفرونت
// ==================================================================

import { randomBytes, createHash } from 'node:crypto'
import type { SimulationPersona } from './simulations.schema.js'
import type { PersonaWeights } from './simulations.schema.js'

// ------------------------------------------------------------------
// أنواع
// ------------------------------------------------------------------

export interface PersonaIpEntry {
  ip: string
  /** إن وُجد يُستخدم كتلميح؛ الـ Gateway يقدر يعتمد lookup الحقيقي */
  countryCode?: string
  label?: string
}

export interface PersonaRequestPlan {
  persona: SimulationPersona
  method: string
  path: string
  ip: string
  countryCode?: string
  userAgent: string
  deviceFingerprint: string
  ja4?: string
  ja3?: string
  /** pass | fail | skip — يُحترم في Gateway مع توكن المحاكاة فقط */
  simJs?: 'pass' | 'fail' | 'skip'
  /** 0..1 يمر كـ X-ZP-Sim-AI */
  aiScore: number
  headers: Record<string, string>
}

export interface BuildPersonaRequestInput {
  persona: SimulationPersona
  domain: string
  runId: string
  tokenHeader: string
  paths: string[]
  enableJaHeaders?: boolean
  aiMode?: 'auto' | 'fixed' | 'off'
  aiFixedScore?: number
  /** 0..1 تقدم الـ Run لتعديل بسيط */
  progress?: number
  sessionKey?: string
  rand?: () => number
  edgeToken?: string
}

// ------------------------------------------------------------------
// برك IP — عناوين عامة شائعة (lookup غالبًا ينجح)
// شرعي ≈ مزودي DNS/CDN معروفين · هجوم ≈ نطاقات سحابية شائعة
// يمكن توسيعها لاحقًا من ملف JSON
// ------------------------------------------------------------------

/** زوار “سكني/شرعي” تقريبي للديمو */
export const LEGIT_IP_POOL: PersonaIpEntry[] = [
  { ip: '1.1.1.1', countryCode: 'AU', label: 'cloudflare-dns' },
  { ip: '1.0.0.1', countryCode: 'AU', label: 'cloudflare-dns' },
  { ip: '8.8.8.8', countryCode: 'US', label: 'google-dns' },
  { ip: '8.8.4.4', countryCode: 'US', label: 'google-dns' },
  { ip: '9.9.9.9', countryCode: 'US', label: 'quad9' },
  { ip: '208.67.222.222', countryCode: 'US', label: 'opendns' },
  { ip: '208.67.220.220', countryCode: 'US', label: 'opendns' },
  { ip: '64.233.187.99', countryCode: 'US', label: 'google' },
  { ip: '142.250.185.78', countryCode: 'US', label: 'google' },
  { ip: '151.101.1.69', countryCode: 'US', label: 'fastly' },
  { ip: '104.16.132.229', countryCode: 'US', label: 'cloudflare' },
  { ip: '13.32.0.1', countryCode: 'US', label: 'amazon' },
  { ip: '20.54.0.1', countryCode: 'NL', label: 'azure' },
  { ip: '185.199.108.153', countryCode: 'US', label: 'github' },
  { ip: '140.82.121.4', countryCode: 'US', label: 'github' },
  { ip: '199.232.69.194', countryCode: 'US', label: 'fastly' },
  { ip: '41.128.0.1', countryCode: 'EG', label: 'eg-sample' },
  { ip: '156.208.0.1', countryCode: 'EG', label: 'eg-sample' },
  { ip: '197.135.0.1', countryCode: 'EG', label: 'eg-sample' },
  { ip: '102.41.0.1', countryCode: 'EG', label: 'eg-sample' },
  { ip: '5.10.0.1', countryCode: 'GB', label: 'ripee' },
  { ip: '81.2.69.144', countryCode: 'GB', label: 'uk' },
  { ip: '2.16.0.1', countryCode: 'IE', label: 'akamai' },
  { ip: '23.3.0.1', countryCode: 'US', label: 'akamai' },
  { ip: '31.13.64.1', countryCode: 'US', label: 'meta' },
  { ip: '157.240.0.1', countryCode: 'US', label: 'meta' },
  { ip: '17.253.0.1', countryCode: 'US', label: 'apple' },
  { ip: '36.3.0.1', countryCode: 'JP', label: 'jp' },
  { ip: '1.33.0.1', countryCode: 'JP', label: 'jp' },
  { ip: '101.44.0.1', countryCode: 'CN', label: 'cn' },
  { ip: '103.21.244.1', countryCode: 'AU', label: 'cf' },
  { ip: '188.114.96.1', countryCode: 'US', label: 'cf' },
  { ip: '216.58.211.14', countryCode: 'US', label: 'google' },
  { ip: '172.217.19.14', countryCode: 'US', label: 'google' },
  { ip: '104.244.42.1', countryCode: 'US', label: 'twitter' },
  { ip: '52.94.0.1', countryCode: 'US', label: 'aws' },
  { ip: '3.5.0.1', countryCode: 'US', label: 'aws' },
  { ip: '35.186.0.1', countryCode: 'US', label: 'gcp' },
  { ip: '34.64.0.1', countryCode: 'US', label: 'gcp' },
  { ip: '40.112.0.1', countryCode: 'IE', label: 'azure' },
]

/** مصادر “هجوم / سحابة / مركز بيانات” للديمو */
export const ATTACK_IP_POOL: PersonaIpEntry[] = [
  { ip: '45.33.32.1', countryCode: 'US', label: 'linode' },
  { ip: '45.79.0.1', countryCode: 'US', label: 'linode' },
  { ip: '139.162.0.1', countryCode: 'JP', label: 'linode' },
  { ip: '172.104.0.1', countryCode: 'US', label: 'linode' },
  { ip: '139.59.0.1', countryCode: 'IN', label: 'digitalocean' },
  { ip: '159.89.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '167.99.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '206.189.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '51.15.0.1', countryCode: 'FR', label: 'scaleway' },
  { ip: '163.172.0.1', countryCode: 'FR', label: 'scaleway' },
  { ip: '5.104.0.1', countryCode: 'DE', label: 'hetzner' },
  { ip: '78.46.0.1', countryCode: 'DE', label: 'hetzner' },
  { ip: '95.216.0.1', countryCode: 'FI', label: 'hetzner' },
  { ip: '135.181.0.1', countryCode: 'FI', label: 'hetzner' },
  { ip: '194.163.0.1', countryCode: 'DE', label: 'contabo' },
  { ip: '173.249.0.1', countryCode: 'DE', label: 'contabo' },
  { ip: '104.248.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '68.183.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '157.245.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '161.35.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '143.110.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '134.209.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '165.227.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '188.166.0.1', countryCode: 'NL', label: 'digitalocean' },
  { ip: '46.101.0.1', countryCode: 'GB', label: 'digitalocean' },
  { ip: '178.62.0.1', countryCode: 'GB', label: 'digitalocean' },
  { ip: '64.227.0.1', countryCode: 'IN', label: 'digitalocean' },
  { ip: '3.120.0.1', countryCode: 'DE', label: 'aws' },
  { ip: '18.184.0.1', countryCode: 'DE', label: 'aws' },
  { ip: '52.28.0.1', countryCode: 'DE', label: 'aws' },
  { ip: '35.156.0.1', countryCode: 'DE', label: 'aws' },
  { ip: '54.93.0.1', countryCode: 'DE', label: 'aws' },
  { ip: '13.48.0.1', countryCode: 'SE', label: 'aws' },
  { ip: '15.228.0.1', countryCode: 'BR', label: 'aws' },
  { ip: '43.205.0.1', countryCode: 'IN', label: 'aws' },
  { ip: '65.1.0.1', countryCode: 'IN', label: 'aws' },
  { ip: '34.93.0.1', countryCode: 'IN', label: 'gcp' },
  { ip: '35.244.0.1', countryCode: 'IN', label: 'gcp' },
  { ip: '47.88.0.1', countryCode: 'US', label: 'alibaba' },
  { ip: '47.74.0.1', countryCode: 'SG', label: 'alibaba' },
  { ip: '119.8.0.1', countryCode: 'HK', label: 'huawei' },
  { ip: '114.119.0.1', countryCode: 'SG', label: 'huawei' },
  { ip: '185.220.101.1', countryCode: 'DE', label: 'tor-like' },
  { ip: '185.220.102.1', countryCode: 'DE', label: 'tor-like' },
  { ip: '198.98.51.1', countryCode: 'US', label: 'vps' },
  { ip: '205.185.115.1', countryCode: 'US', label: 'vps' },
  { ip: '91.219.237.1', countryCode: 'NL', label: 'vps' },
  { ip: '45.9.148.1', countryCode: 'NL', label: 'vps' },
  { ip: '193.29.13.1', countryCode: 'RU', label: 'ru-vps' },
  { ip: '45.142.122.1', countryCode: 'RU', label: 'ru-vps' },
  { ip: '194.87.0.1', countryCode: 'RU', label: 'ru-vps' },
  { ip: '31.184.0.1', countryCode: 'RU', label: 'ru' },
  { ip: '103.149.0.1', countryCode: 'ID', label: 'id' },
  { ip: '103.75.0.1', countryCode: 'VN', label: 'vn' },
  { ip: '36.91.0.1', countryCode: 'ID', label: 'id' },
  { ip: '14.0.0.1', countryCode: 'HK', label: 'hk' },
  { ip: '112.133.0.1', countryCode: 'IN', label: 'in' },
  { ip: '27.0.0.1', countryCode: 'IN', label: 'in' },
  { ip: '223.27.0.1', countryCode: 'ID', label: 'id' },
  { ip: '118.99.0.1', countryCode: 'ID', label: 'id' },
  { ip: '103.10.0.1', countryCode: 'SG', label: 'sg' },
  { ip: '128.199.0.1', countryCode: 'SG', label: 'digitalocean' },
  { ip: '178.128.0.1', countryCode: 'SG', label: 'digitalocean' },
  { ip: '209.97.0.1', countryCode: 'SG', label: 'digitalocean' },
  { ip: '159.65.0.1', countryCode: 'SG', label: 'digitalocean' },
  { ip: '147.182.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '164.90.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '137.184.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '143.198.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '174.138.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '192.241.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '107.170.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '162.243.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '198.199.0.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '192.34.56.1', countryCode: 'US', label: 'digitalocean' },
  { ip: '37.139.0.1', countryCode: 'NL', label: 'digitalocean' },
  { ip: '5.189.0.1', countryCode: 'DE', label: 'contabo' },
  { ip: '213.136.0.1', countryCode: 'DE', label: 'contabo' },
  { ip: '80.241.0.1', countryCode: 'DE', label: 'contabo' },
  { ip: '185.2.0.1', countryCode: 'NL', label: 'vps' },
  { ip: '89.36.0.1', countryCode: 'RO', label: 'ro' },
  { ip: '94.177.0.1', countryCode: 'IT', label: 'it' },
  { ip: '185.125.0.1', countryCode: 'GB', label: 'canonical' },
  { ip: '91.189.0.1', countryCode: 'GB', label: 'canonical' },
]

const UA_BROWSER = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
]

const UA_BOT = [
  'curl/8.5.0',
  'python-requests/2.31.0',
  'Go-http-client/2.0',
  'Wget/1.21.4',
  'Java/17.0.9',
  'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
]

const JA4_OK = [
  't13d1516h2_8daaf6152771_e5627efa2ab1',
  't13d1517h2_8daaf6152771_b6f405a00624',
  't12d3107h2_e5627efa2ab1_8daaf6152771',
]

const JA3_OK = [
  '579ccef312d18482fc42e2b822ca2430',
  '773906b0efdefa24a7f2b8bb6749ae5c',
  '849d908c90ce395474bbb0bde9b1f4bc',
]

// ------------------------------------------------------------------
// Utils
// ------------------------------------------------------------------

function defaultRand(): number {
  return Math.random()
}

function pick<T>(arr: T[], rand: () => number): T {
  return arr[Math.floor(rand() * arr.length) % arr.length]!
}

function stableFp(key: string): string {
  return `fp_${createHash('sha256').update(key).digest('hex').slice(0, 16)}`
}

function randomFp(): string {
  return `fp_${randomBytes(8).toString('hex')}`
}

export function takeIpPool(
  kind: 'legit' | 'attack',
  size: number,
): PersonaIpEntry[] {
  const src = kind === 'legit' ? LEGIT_IP_POOL : ATTACK_IP_POOL
  if (size >= src.length) return [...src]
  return src.slice(0, Math.max(1, size))
}

export function selectPersonaByWeight(
  weights: PersonaWeights,
  rand: () => number = defaultRand,
): SimulationPersona {
  const entries = Object.entries(weights) as [SimulationPersona, number][]
  const total = entries.reduce((s, [, v]) => s + Math.max(0, v), 0)
  if (total <= 0) return 'legit_ok'
  let r = rand() * total
  for (const [k, v] of entries) {
    r -= Math.max(0, v)
    if (r <= 0) return k
  }
  return 'legit_ok'
}

// ------------------------------------------------------------------
// بناء خطة طلب كاملة
// ------------------------------------------------------------------

export function buildPersonaRequest(
  input: BuildPersonaRequestInput,
): PersonaRequestPlan {
  const rand = input.rand ?? defaultRand
  const paths =
    input.paths?.length > 0 ? input.paths : ['/', '/login', '/api/health']
  const sensitive = paths.filter(
    (p) =>
      /login|admin|signup|auth|checkout|password/i.test(p),
  )
  const aiMode = input.aiMode ?? 'auto'
  const fixed = input.aiFixedScore ?? 0.35

  const legit = LEGIT_IP_POOL
  const attack = ATTACK_IP_POOL

  let method = 'GET'
  let path = pick(paths, rand)
  let entry = pick(legit, rand)
  let userAgent = pick(UA_BROWSER, rand)
  let simJs: 'pass' | 'fail' | 'skip' | undefined = 'pass'
  let aiScore = 0.05 + rand() * 0.15
  let deviceFingerprint = input.sessionKey
    ? stableFp(input.sessionKey)
    : stableFp(`legit:${entry.ip}`)
  let ja4: string | undefined = pick(JA4_OK, rand)
  let ja3: string | undefined = pick(JA3_OK, rand)

  switch (input.persona) {
    case 'legit_ok':
      break
    case 'legit_sensitive':
      path = sensitive.length ? pick(sensitive, rand) : '/login'
      method = /login|signup|auth|password/i.test(path) ? 'POST' : 'GET'
      aiScore = 0.12 + rand() * 0.2
      break
    case 'rate_soft':
      entry = legit[0] ?? entry
      deviceFingerprint = stableFp(`rate-soft:${entry.ip}`)
      simJs = 'pass'
      break
    case 'rate_hard':
      entry = legit[0] ?? entry
      deviceFingerprint = stableFp(`rate-hard:${entry.ip}`)
      simJs = 'skip'
      aiScore = 0.35 + rand() * 0.25
      break
    case 'bot_ua':
      entry = pick(attack, rand)
      userAgent = pick(UA_BOT, rand)
      deviceFingerprint = randomFp()
      ja4 = undefined
      ja3 = undefined
      simJs = 'fail'
      aiScore = 0.55 + rand() * 0.35
      break
    case 'fail_js':
      entry = pick(attack, rand)
      simJs = 'fail'
      aiScore = 0.4 + rand() * 0.35
      deviceFingerprint = randomFp()
      break
    case 'pass_js':
      simJs = 'pass'
      path = pick(paths, rand)
      break
    case 'bad_ip':
      entry = pick(attack, rand)
      userAgent = pick(UA_BOT, rand)
      simJs = 'fail'
      aiScore = 0.65 + rand() * 0.3
      ja4 = 't13d0000h0_deadbeef0001_badc0ffee000'
      ja3 = undefined
      deviceFingerprint = randomFp()
      break
    default:
      break
  }

  if (aiMode === 'off') aiScore = 0
  else if (aiMode === 'fixed') aiScore = fixed
  aiScore = Math.min(1, Math.max(0, Number(aiScore.toFixed(3))))

  const headers: Record<string, string> = {
    Host: input.domain,
    'User-Agent': userAgent,
    Accept: 'text/html,application/json;q=0.9,*/*;q=0.8',
    'X-Real-IP': entry.ip,
    'X-Forwarded-For': entry.ip,
    'X-ZP-Simulation': input.tokenHeader,
    'X-ZP-Sim-Run': input.runId,
    'X-ZP-Sim-Persona': input.persona,
    'X-ZP-Sim-AI': String(aiScore),
    'X-Device-Fingerprint': deviceFingerprint,
  }

  if (simJs) headers['X-ZP-Sim-JS'] = simJs

  // تلميح Geo اختياري — Gateway يقدر يقرأه فقط مع توكن محاكاة صالح
  if (entry.countryCode) {
    headers['X-ZP-Sim-Country'] = entry.countryCode
  }

  if (input.enableJaHeaders !== false && ja4) {
    headers['X-JA4'] = ja4
    if (ja3) headers['X-JA3'] = ja3
    headers['X-Edge-Server'] =
      input.edgeToken || process.env.ZP_EDGE_TOKEN || 'zeroplus-edge'
  }

  return {
    persona: input.persona,
    method,
    path,
    ip: entry.ip,
    countryCode: entry.countryCode,
    userAgent,
    deviceFingerprint,
    ja4,
    ja3,
    simJs,
    aiScore,
    headers,
  }
}

/**
 * عدد التكرارات لنفس الشخصية في دفعة (rate stress)
 */
export function personaRepeatCount(
  persona: SimulationPersona,
  rand: () => number = defaultRand,
): number {
  if (persona === 'rate_hard') return 3 + Math.floor(rand() * 5)
  if (persona === 'rate_soft') return 2 + Math.floor(rand() * 2)
  return 1
}

export default {
  LEGIT_IP_POOL,
  ATTACK_IP_POOL,
  takeIpPool,
  selectPersonaByWeight,
  buildPersonaRequest,
  personaRepeatCount,
}