// backend/src/modules/reports/gemini.client.ts
// ==================================================================
// Zero Plus - Gemini Client
// ------------------------------------------------------------------
// التواصل فقط مع Gemini API (Google AI Studio / Generative Language)
//
// المسؤوليات:
//   - generateReport(prompt, data) → نص التقرير + metadata
//   - chat(messages, systemContext?) → رد المحادثة
//   - معالجة 429 / 503 / timeout بأخطاء واضحة
//
// مش مسؤول عن: جمع بيانات DB، حفظ Prisma، إشعارات
//
// التوثيق الرسمي:
//   https://ai.google.dev/api
//   POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
// ==================================================================

import type { CollectedReportData } from "./reports.schema.js";

// ==================================================================
// Config
// ==================================================================

const GEMINI_API_BASE =
  process.env.GEMINI_API_BASE?.replace(/\/$/, "") ??
  "https://generativelanguage.googleapis.com/v1beta";

const GEMINI_MODEL = process.env.GEMINI_MODEL ?? "gemini-2.0-flash";

const GEMINI_TIMEOUT_MS = (() => {
  const n = Number(process.env.GEMINI_TIMEOUT_MS ?? 120_000);
  return Number.isFinite(n) && n >= 5_000 ? Math.floor(n) : 120_000;
})();

/** إعادة محاولة خفيفة على 429/503 */
const MAX_RETRIES = 2;
const RETRY_BASE_MS = 1_500;

function getApiKey(): string {
  const key = process.env.GEMINI_API_KEY?.trim();
  if (!key) {
    throw new GeminiClientError(
      "GEMINI_API_KEY غير مضبوط في البيئة",
      "CONFIG_MISSING",
      500,
    );
  }
  return key;
}

// ==================================================================
// Errors
// ==================================================================

export type GeminiErrorCode =
  | "CONFIG_MISSING"
  | "RATE_LIMITED"
  | "SERVICE_UNAVAILABLE"
  | "TIMEOUT"
  | "INVALID_REQUEST"
  | "EMPTY_RESPONSE"
  | "NETWORK"
  | "UNKNOWN";

export class GeminiClientError extends Error {
  public readonly code: GeminiErrorCode;
  public readonly statusCode: number;
  public readonly details?: unknown;

  constructor(
    message: string,
    code: GeminiErrorCode,
    statusCode = 502,
    details?: unknown,
  ) {
    super(message);
    this.name = "GeminiClientError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

// ==================================================================
// أنواع الطلب/الرد (متوافقة مع REST الرسمي)
// ==================================================================

export type GeminiRole = "user" | "model";

export interface GeminiContentPart {
  text: string;
}

export interface GeminiContent {
  role?: GeminiRole;
  parts: GeminiContentPart[];
}

export interface GeminiGenerateResult {
  text: string;
  model: string;
  /** مجموع tokens لو Gemini رجّع usageMetadata */
  tokensUsed: number | null;
  promptTokens: number | null;
  candidatesTokens: number | null;
  finishReason: string | null;
  raw?: unknown;
}

interface GeminiApiResponse {
  candidates?: Array<{
    content?: { parts?: Array<{ text?: string }>; role?: string };
    finishReason?: string;
  }>;
  usageMetadata?: {
    promptTokenCount?: number;
    candidatesTokenCount?: number;
    totalTokenCount?: number;
  };
  error?: {
    code?: number;
    message?: string;
    status?: string;
  };
}

// ==================================================================
// HTTP منخفض المستوى
// ==================================================================

async function sleep(ms: number): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

function buildGenerateUrl(model: string, apiKey: string): string {
  // نفس شكل AI Studio / الوثائق الرسمية
  return `${GEMINI_API_BASE}/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;
}

async function postGenerateContent(
  body: Record<string, unknown>,
  model: string = GEMINI_MODEL,
): Promise<GeminiApiResponse> {
  const apiKey = getApiKey();
  const url = buildGenerateUrl(model, apiKey);

  let lastError: GeminiClientError | null = null;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), GEMINI_TIMEOUT_MS);

    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      clearTimeout(timer);

      const json = (await res.json().catch(() => ({}))) as GeminiApiResponse;

      if (!res.ok || json.error) {
        const status = res.status || json.error?.code || 502;
        const msg = json.error?.message || `Gemini HTTP ${status}`;

        if (status === 429) {
          lastError = new GeminiClientError(
            "تم تجاوز حد طلبات Gemini. حاول بعد قليل.",
            "RATE_LIMITED",
            429,
            json.error,
          );
          if (attempt < MAX_RETRIES) {
            await sleep(RETRY_BASE_MS * (attempt + 1) * 2);
            continue;
          }
          throw lastError;
        }

        if (status === 503 || status === 502) {
          lastError = new GeminiClientError(
            "خدمة Gemini غير متاحة حاليًا.",
            "SERVICE_UNAVAILABLE",
            503,
            json.error,
          );
          if (attempt < MAX_RETRIES) {
            await sleep(RETRY_BASE_MS * (attempt + 1));
            continue;
          }
          throw lastError;
        }

        if (status === 400 || status === 404) {
          throw new GeminiClientError(
            msg || "طلب غير صالح إلى Gemini",
            "INVALID_REQUEST",
            400,
            json.error,
          );
        }

        throw new GeminiClientError(
          msg,
          "UNKNOWN",
          status >= 400 && status < 600 ? status : 502,
          json.error,
        );
      }

      return json;
    } catch (err) {
      clearTimeout(timer);

      if (err instanceof GeminiClientError) throw err;

      const isAbort =
        (err as Error)?.name === "AbortError" ||
        (err as Error)?.message?.includes("aborted");

      if (isAbort) {
        lastError = new GeminiClientError(
          `انتهت مهلة الاتصال بـ Gemini (${GEMINI_TIMEOUT_MS}ms)`,
          "TIMEOUT",
          504,
        );
        // timeout عادةً مش يستاهل retry تقيل
        throw lastError;
      }

      lastError = new GeminiClientError(
        `فشل الاتصال بـ Gemini: ${(err as Error).message}`,
        "NETWORK",
        502,
      );
      if (attempt < MAX_RETRIES) {
        await sleep(RETRY_BASE_MS * (attempt + 1));
        continue;
      }
      throw lastError;
    }
  }

  throw lastError ?? new GeminiClientError("فشل غير معروف", "UNKNOWN", 502);
}

function extractText(response: GeminiApiResponse): {
  text: string;
  finishReason: string | null;
} {
  const candidate = response.candidates?.[0];
  const parts = candidate?.content?.parts ?? [];
  const text = parts
    .map((p) => p.text ?? "")
    .join("")
    .trim();

  return {
    text,
    finishReason: candidate?.finishReason ?? null,
  };
}

function toResult(
  response: GeminiApiResponse,
  model: string,
): GeminiGenerateResult {
  const { text, finishReason } = extractText(response);

  if (!text) {
    throw new GeminiClientError("Gemini رجّع رد فاضي", "EMPTY_RESPONSE", 502, {
      finishReason,
      response,
    });
  }

  const usage = response.usageMetadata;

  return {
    text,
    model,
    tokensUsed: usage?.totalTokenCount ?? null,
    promptTokens: usage?.promptTokenCount ?? null,
    candidatesTokens: usage?.candidatesTokenCount ?? null,
    finishReason,
    raw: undefined, // مش بنخزن الـ raw كامل في DB
  };
}

// ==================================================================
// Generation config مشتركة
// ==================================================================

function reportGenerationConfig() {
  return {
    temperature: 0.35,
    topP: 0.95,
    topK: 40,
    maxOutputTokens: 8192,
    // رد طويل منظم
  };
}

function chatGenerationConfig() {
  return {
    temperature: 0.55,
    topP: 0.95,
    topK: 40,
    maxOutputTokens: 4096,
  };
}

// ==================================================================
// بناء الـ Prompt للتقرير
// ==================================================================

function buildReportSystemInstruction(): string {
  return [
    "You are a cybersecurity analyst at Zero Plus, a platform that protects websites from bots and attacks.",
    "Write a clear, professional report in English using technical terminology where appropriate.",
    "Rely only on the provided data. Do not fabricate numbers or events.",
    "If data is missing or insufficient, state that clearly.",
    "Do not mention internal server IPs or any infrastructure secrets.",
    "Suggested report structure:",
    "1) Executive Summary",
    "2) Period Statistics",
    "3) Key Threats and Patterns",
    "4) Servers and Status",
    "5) Reputation and Bans",
    "6) Challenge and Simulation Results (if available)",
    "7) Actionable Recommendations (prioritized)",
    "At the end of the report, write a line starting with: SUMMARY: followed by one or two sentences only.",
  ].join("\n");
}

function buildReportUserPrompt(
  prompt: string | undefined,
  data: CollectedReportData,
): string {
  const header = [
    `الفترة: ${data.periodStart} → ${data.periodEnd}`,
    `المنظمة: ${data.organizationName}`,
    `إحصائيات سريعة: ${JSON.stringify(data.stats)}`,
  ].join("\n");

  const userNote = prompt?.trim()
    ? `\n\nملاحظات إضافية من المستخدم:\n${prompt.trim()}`
    : "";

  // البيانات كاملة كـ JSON مضغوط نسبيًا
  const payload = {
    servers: data.servers,
    events: data.events,
    reputations: data.reputations,
    challenges: data.challenges,
    simulations: data.simulations,
  };

  return `${header}${userNote}\n\n--- بيانات الأمان (JSON) ---\n${JSON.stringify(payload)}`;
}

/**
 * يستخرج الملخص من سطر SUMMARY: لو موجود
 */
export function extractSummaryFromReport(text: string): string | null {
  const match = text.match(/SUMMARY:\s*(.+)/i);
  if (!match?.[1]) return null;
  return match[1].trim().slice(0, 500);
}

// ==================================================================
// API العامة
// ==================================================================

/**
 * توليد تقرير أمني من البيانات المُجمّعة
 */
export async function generateReport(
  prompt: string | undefined,
  data: CollectedReportData,
): Promise<GeminiGenerateResult & { summary: string | null }> {
  const model = GEMINI_MODEL;

  const body = {
    systemInstruction: {
      parts: [{ text: buildReportSystemInstruction() }],
    },
    contents: [
      {
        role: "user",
        parts: [{ text: buildReportUserPrompt(prompt, data) }],
      },
    ],
    generationConfig: reportGenerationConfig(),
    safetySettings: [
      // تخفيف الحظر على محتوى أمني تقني (لو الموديل دعم)
      { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_ONLY_HIGH" },
      { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_ONLY_HIGH" },
      {
        category: "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        threshold: "BLOCK_ONLY_HIGH",
      },
      {
        category: "HARM_CATEGORY_DANGEROUS_CONTENT",
        threshold: "BLOCK_ONLY_HIGH",
      },
    ],
  };

  const response = await postGenerateContent(body, model);
  const result = toResult(response, model);

  return {
    ...result,
    summary: extractSummaryFromReport(result.text),
  };
}

export interface ChatMessageInput {
  role: "user" | "assistant" | "system";
  content: string;
}

/**
 * محادثة متعددة الرسائل
 * - systemContext: إحصائيات الشركة (من الـ Service) تتحط في systemInstruction
 * - messages: تاريخ + الرسالة الحالية (الـ Service يركّبهم)
 */
export async function chat(
  messages: ChatMessageInput[],
  systemContext?: string,
): Promise<GeminiGenerateResult> {
  const model = GEMINI_MODEL;

  if (!messages.length) {
    throw new GeminiClientError(
      "لا توجد رسائل للمحادثة",
      "INVALID_REQUEST",
      400,
    );
  }

  const systemParts: string[] = [
    "You are a security assistant for the Zero Plus platform. Answer concisely and clearly in English.",
    "Use the provided context only when discussing company-specific data. Do not fabricate information.",
    "Never request, reveal, or expose secrets, keys, or internal Origin addresses.",
  ];

  if (systemContext?.trim()) {
    systemParts.push("--- سياق الشركة ---\n" + systemContext.trim());
  }

  // Gemini: system منفصل؛ باقي الرسائل user/model بالتناوب تقريبًا
  const contents: GeminiContent[] = [];

  for (const msg of messages) {
    if (msg.role === "system") {
      systemParts.push(msg.content);
      continue;
    }
    contents.push({
      role: msg.role === "assistant" ? "model" : "user",
      parts: [{ text: msg.content }],
    });
  }

  if (!contents.length) {
    throw new GeminiClientError(
      "يجب وجود رسالة مستخدم واحدة على الأقل",
      "INVALID_REQUEST",
      400,
    );
  }

  // ضمان أن أول content يكون user (متطلب شائع للـ API)
  if (contents[0]?.role === "model") {
    contents.unshift({
      role: "user",
      parts: [{ text: "." }],
    });
  }

  const body = {
    systemInstruction: {
      parts: [{ text: systemParts.join("\n\n") }],
    },
    contents,
    generationConfig: chatGenerationConfig(),
  };

  const response = await postGenerateContent(body, model);
  return toResult(response, model);
}

/**
 * فحص سريع إن المفتاح والموديل شغالين
 */
export async function pingGemini(): Promise<{ ok: boolean; model: string }> {
  try {
    const result = await chat(
      [{ role: "user", content: "Reply with exactly: OK" }],
      undefined,
    );
    return { ok: result.text.length > 0, model: result.model };
  } catch {
    return { ok: false, model: GEMINI_MODEL };
  }
}

export default {
  generateReport,
  chat,
  pingGemini,
  extractSummaryFromReport,
  GeminiClientError,
};
