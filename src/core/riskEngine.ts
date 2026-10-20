// backend/src/core/risk.engine.ts
// ==================================================================
// Zero Plus - Risk Engine (pure)
// ------------------------------------------------------------------
// الدوسيه: Signals → Detection → AI → Risk Engine → Policy → Decision
// الملف ده بيجمع الإشارات في Risk Score واحد (0–100) ومعاه مكوّنات
// (components) بتوضح مين السبب. الـ policy.engine بياخد المكوّنات دي
// ويقرر منها (ويعرف قاعدة "الـ AI وحده ما يحظرش" والمرحلة اللي حسمت).
//
// نقي 100%: مفيش DB ولا شبكة، وبيتنسخ للـ Gateway.
//
// القديم شغال بنفس الأرقام بالظبط: computeRiskScore / DEFAULT_WEIGHTS / RiskSignals.
// ==================================================================

// ==================================================================
// Types
// ==================================================================

export type IpType =
  | 'RESIDENTIAL'
  | 'MOBILE'
  | 'DATACENTER'
  | 'VPN_PROXY'
  | 'TOR'
  | 'UNKNOWN'

export type FingerprintFlag =
  | 'TLS_BAD'
  | 'TLS_MISMATCH'
  | 'DEVICE_ROTATION'
  | 'IP_ROTATION'

/** المراحل اللي المكوّنات بتتنسب لها (جزء من DetectionStage في الـ Prisma) */
export type RiskStage =
  | 'IP_LOOKUP'
  | 'HISTORY_MATCH'
  | 'DEEP_COMPARISON'
  | 'TLS_FINGERPRINT'
  | 'AI_ANOMALY'

export type RiskSignals = {
  // ---- القديم ----
  isDatacenter?: boolean
  /** طلبات/ثانية: من 5 يبدأ التأثير ومن 20 الوزن كامل */
  requestRate?: number
  /** 0–1 */
  anomalyScore?: number
  /** 0–1 */
  fingerprintRisk?: number
  /** 1–10 */
  reputationScore?: number
  failedChecks?: number
  threatIntelMatch?: boolean
  // ---- الجديد (كله اختياري) ----
  ipType?: IpType
  /** عدد الطلبات ÷ حد الشركة (1 = عند الحد). بيخلي الخطورة نسبية لإعدادات كل شركة */
  rateLimitRatio?: number
  /** ثقة الـ AI (0–1): بتقلل أثر الشذوذ لو ضعيفة */
  anomalyConfidence?: number
  fingerprintFlags?: FingerprintFlag[]
  isKnownBotnet?: boolean
  botUserAgent?: boolean
  missingBrowserHeaders?: boolean
  pathScanning?: boolean
  bruteForce?: boolean
}

export type RiskWeights = {
  datacenter: number
  highRate: number
  anomaly: number
  fingerprint: number
  reputation: number
  failedChecks: number
  threatIntel: number
  // ---- الجديد (اختياري، ليه قيمة افتراضية) ----
  botUserAgent?: number
  missingHeaders?: number
  pathScanning?: number
  bruteForce?: number
}

export const DEFAULT_WEIGHTS: Required<RiskWeights> = {
  datacenter: 15,
  highRate: 25,
  anomaly: 30,
  fingerprint: 10,
  reputation: 20,
  failedChecks: 8,
  threatIntel: 25,
  botUserAgent: 12,
  missingHeaders: 5,
  pathScanning: 15,
  bruteForce: 15,
}

export type RiskComponent = {
  stage: RiskStage
  label: string
  points: number
}

export type RiskResult = {
  /** 0–100 */
  score: number
  /** المجموع قبل السقف (للتشخيص) */
  rawTotal: number
  capped: boolean
  components: RiskComponent[]
}

export type RiskOptions = {
  weights?: RiskWeights
  /** Policy.enableAiAnomaly: false بيتجاهل الشذوذ */
  enableAiAnomaly?: boolean
}

// ==================================================================
// Helpers
// ==================================================================

const clamp01 = (value: number): number =>
  Number.isFinite(value) ? Math.min(1, Math.max(0, value)) : 0

const finite = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value)

/** وزن IP حسب النوع: مركز بيانات و Tor كاملين، VPN/Proxy 60% */
const IP_TYPE_FACTOR: Record<IpType, number> = {
  DATACENTER: 1,
  TOR: 1,
  VPN_PROXY: 0.6,
  RESIDENTIAL: 0,
  MOBILE: 0,
  UNKNOWN: 0,
}

const IP_TYPE_LABEL: Partial<Record<IpType, string>> = {
  DATACENTER: 'عنوان من مركز بيانات',
  TOR: 'عقدة خروج Tor',
  VPN_PROXY: 'عنوان VPN أو Proxy',
}

const FINGERPRINT_FLAG_RISK: Record<FingerprintFlag, number> = {
  TLS_BAD: 1,
  TLS_MISMATCH: 0.8,
  DEVICE_ROTATION: 0.6,
  IP_ROTATION: 0.6,
}

/** دمج احتمالات مستقلة (noisy-or): كل علامة بترفع الخطورة من غير ما تعدّي 1 */
function combineFlags(flags: FingerprintFlag[]): number {
  let remaining = 1

  for (const flag of new Set(flags)) {
    remaining *= 1 - FINGERPRINT_FLAG_RISK[flag]
  }

  return clamp01(1 - remaining)
}

// ==================================================================
// الحساب الكامل (مع المكوّنات)
// ==================================================================

export function computeRisk(
  signals: RiskSignals,
  options: RiskOptions = {},
): RiskResult {
  const w: Required<RiskWeights> = { ...DEFAULT_WEIGHTS, ...(options.weights ?? {}) }
  const aiEnabled = options.enableAiAnomaly !== false

  const components: RiskComponent[] = []

  const add = (stage: RiskStage, label: string, points: number) => {
    if (points > 0) components.push({ stage, label, points })
  }

  // ---- 1) الشبكة (IP Lookup) ----
  const ipFactor = Math.max(
    signals.isDatacenter ? 1 : 0,
    signals.ipType ? IP_TYPE_FACTOR[signals.ipType] : 0,
  )

  if (ipFactor > 0) {
    const label =
      signals.isDatacenter && !signals.ipType
        ? 'عنوان من مركز بيانات'
        : (IP_TYPE_LABEL[signals.ipType ?? 'DATACENTER'] ?? 'عنوان من مركز بيانات')

    add('IP_LOOKUP', label, Math.round(w.datacenter * ipFactor))
  }

  // ---- 2) معدل الطلبات (مقارنة سلوكية) ----
  // الجزء القديم (طلبات/ثانية) والجديد (نسبة لحد الشركة): ناخد الأعلى، مش المجموع
  let rateFactor = 0

  if (finite(signals.requestRate) && signals.requestRate > 0) {
    const rate = signals.requestRate

    if (rate >= 20) rateFactor = 1
    else if (rate > 5) rateFactor = (rate - 5) / 15
  }

  if (finite(signals.rateLimitRatio) && signals.rateLimitRatio > 0) {
    const ratio = signals.rateLimitRatio

    rateFactor = Math.max(
      rateFactor,
      ratio >= 1 ? 1 : ratio >= 0.25 ? (ratio - 0.25) / 0.75 : 0,
    )
  }

  add('DEEP_COMPARISON', 'معدل طلبات مرتفع', Math.round(w.highRate * rateFactor))

  // ---- 3) الذكاء الاصطناعي ----
  if (aiEnabled && finite(signals.anomalyScore)) {
    const confidence = finite(signals.anomalyConfidence)
      ? clamp01(signals.anomalyConfidence)
      : 1

    add(
      'AI_ANOMALY',
      'شذوذ سلوكي (AI)',
      Math.round(w.anomaly * clamp01(signals.anomalyScore) * confidence),
    )
  }

  // ---- 4) البصمات ----
  let fingerprintRisk = finite(signals.fingerprintRisk)
    ? clamp01(signals.fingerprintRisk)
    : 0

  if (signals.fingerprintFlags && signals.fingerprintFlags.length > 0) {
    fingerprintRisk = Math.max(fingerprintRisk, combineFlags(signals.fingerprintFlags))
  }

  add('TLS_FINGERPRINT', 'إشارة بصمة مشبوهة', Math.round(w.fingerprint * fingerprintRisk))

  // ---- 5) السجل السابق (سمعة + فشل) ----
  if (finite(signals.reputationScore)) {
    const rep = Math.max(1, Math.min(10, signals.reputationScore))

    add('HISTORY_MATCH', 'سمعة سيئة للمصدر', Math.round(w.reputation * ((rep - 1) / 9)))
  }

  if (finite(signals.failedChecks) && signals.failedChecks > 0) {
    add(
      'HISTORY_MATCH',
      'فشل متكرر في الاختبارات',
      Math.min(signals.failedChecks, 5) * w.failedChecks,
    )
  }

  if (signals.threatIntelMatch || signals.isKnownBotnet) {
    add('HISTORY_MATCH', 'مصدر معروف بالتهديدات', w.threatIntel)
  }

  // ---- 6) سلوك (مقارنة سلوكية) ----
  if (signals.botUserAgent) add('DEEP_COMPARISON', 'User-Agent خاص بروبوت', w.botUserAgent)

  if (signals.missingBrowserHeaders) {
    add('DEEP_COMPARISON', 'ترويسات متصفح ناقصة', w.missingHeaders)
  }

  if (signals.pathScanning) add('DEEP_COMPARISON', 'فحص مسارات حساسة', w.pathScanning)

  if (signals.bruteForce) add('DEEP_COMPARISON', 'نمط تخمين كلمات المرور', w.bruteForce)

  const rawTotal = components.reduce((sum, c) => sum + c.points, 0)
  const score = Math.max(0, Math.min(100, rawTotal))

  return { score, rawTotal, capped: rawTotal > 100, components }
}

/**
 * الشكل اللي policy.engine بياخده في risk:
 *   decide({ ..., risk: toPolicyRisk(computeRisk(signals)) })
 */
export function toPolicyRisk(result: RiskResult): {
  score: number
  components: RiskComponent[]
} {
  return { score: result.score, components: result.components }
}

// ==================================================================
// الواجهة القديمة (متوافقة): نفس الأرقام بالظبط
// ==================================================================

export function computeRiskScore(
  signals: RiskSignals,
  weights: RiskWeights = DEFAULT_WEIGHTS,
): number {
  return computeRisk(signals, { weights }).score
}