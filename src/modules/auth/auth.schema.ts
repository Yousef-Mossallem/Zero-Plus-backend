// ==================================================================
// Zero Plus - Auth Validation Schemas (Zod)
// ==================================================================
// نظام المصادقة: WebAuthn / Passkeys
//
// الفكرة:
//   - المستخدم يعمل حساب بـ (اسم الشركة + الاسم + الإيميل)
//   - ثم يسجّل Passkey على جهازه (بصمة إصبع / وجه / Windows Hello)
//   - السيرفر يخزّن Public Key فقط داخل PasskeyCredential
//   - Private Key ما بيسيبش جهاز المستخدم أبدًا
//
// التدفق:
//   Signup:
//     1) POST /auth/register/start   → body: بيانات الشركة + المستخدم
//        السيرفر يرجع registration options (challenge)
//     2) المتصفح يستدعي navigator.credentials.create(...)
//        المستخدم يضع بصمته / وجهه
//     3) POST /auth/register/finish  → body: response من WebAuthn
//        السيرفر يتحقق ويحفظ Public Key ويصدر JWT
//
//   Login:
//     1) POST /auth/login/start      → body: email
//        السيرفر يرجع authentication options (challenge)
//     2) المتصفح يستدعي navigator.credentials.get(...)
//     3) POST /auth/login/finish     → body: assertion من WebAuthn
//        السيرفر يتحقق من التوقيع ويصدر JWT
//
// معتمد على Prisma:
//   User, Organization, PasskeyCredential, Policy
// ==================================================================

import { z } from 'zod'

// ------------------------------------------------------------------
// قواعد مشتركة قابلة لإعادة الاستخدام
// ------------------------------------------------------------------

/** البريد: للعرض والتواصل وربط الحساب — مش سر الدخول */
const emailSchema = z
  .string()
  .min(1, 'البريد الإلكتروني مطلوب')
  .email('صيغة البريد غير صحيحة')
  .min(5, 'البريد قصير جدًا')
  .max(255, 'البريد طويل جدًا')
  .transform((val) => val.toLowerCase().trim())

/** الاسم الكامل لصاحب الحساب */
const fullNameSchema = z
  .string()
  .min(1, 'الاسم الكامل مطلوب')
  .min(2, 'الاسم يجب ألا يقل عن حرفين')
  .max(100, 'الاسم طويل جدًا')
  .trim()

/** اسم الشركة / المنظمة */
const organizationNameSchema = z
  .string()
  .min(1, 'اسم الشركة مطلوب')
  .min(2, 'اسم الشركة يجب ألا يقل عن حرفين')
  .max(100, 'اسم الشركة طويل جدًا')
  .trim()

/**
 * حجم الترافيك التقريبي
 * يُستخدم لتوجيه نقطة بداية موديل الـ AI (Organization.sizeProfile)
 */
const sizeProfileSchema = z
  .enum(['small', 'medium', 'large'], {
    message: 'حجم الترافيك يجب أن يكون small أو medium أو large',
  })
  .default('medium')

/**
 * اسم الجهاز للعرض في Profile
 * مثال: "iPhone Face ID" / "Windows Hello" / "Android Fingerprint"
 */
const deviceNameSchema = z
  .string()
  .max(120, 'اسم الجهاز طويل جدًا')
  .trim()
  .optional()

/**
 * Base64URL string — الشكل اللي WebAuthn بيبعت بيه
 * challenge / credentialId / clientDataJSON / authenticatorData / signature ...
 */
const base64UrlSchema = z
  .string()
  .min(1, 'قيمة WebAuthn فارغة')
  .max(8192, 'قيمة WebAuthn طويلة جدًا')
  .regex(/^[A-Za-z0-9_-]+$/, 'صيغة Base64URL غير صحيحة')

/**
 * كلمة مرور اختيارية تمامًا
 * مش وسيلة الدخول — احتياطي لحالات نادرة (أدمن / استعادة)
 */
const optionalPasswordSchema = z
  .string()
  .min(8, 'كلمة المرور يجب ألا تقل عن 8 أحرف')
  .max(128, 'كلمة المرور طويلة جدًا')
  .regex(/[a-z]/, 'يجب أن تحتوي على حرف صغير')
  .regex(/[A-Z]/, 'يجب أن تحتوي على حرف كبير')
  .regex(/[0-9]/, 'يجب أن تحتوي على رقم')
  .optional()

// ------------------------------------------------------------------
// WebAuthn — أشكال الـ Client Responses (مبسّطة ومتوافقة مع @simplewebauthn)
// ------------------------------------------------------------------

/**
 * جزء الـ response بعد navigator.credentials.create()
 * (Registration — إنشاء Passkey جديد)
 */
const registrationResponseSchema = z
  .object({
    id: z.string().min(1),
    rawId: base64UrlSchema,
    type: z.literal('public-key'),
    authenticatorAttachment: z
      .enum(['platform', 'cross-platform'])
      .optional(),
    clientExtensionResults: z.record(z.string(), z.unknown()).optional(),
    response: z.object({
      clientDataJSON: base64UrlSchema,
      attestationObject: base64UrlSchema,
      transports: z
        .array(z.enum(['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card']))
        .optional(),
      publicKeyAlgorithm: z.number().optional(),
      publicKey: base64UrlSchema.optional(),
      authenticatorData: base64UrlSchema.optional(),
    }),
  })
  .strict()

/**
 * جزء الـ response بعد navigator.credentials.get()
 * (Authentication — تسجيل الدخول بـ Passkey موجود)
 */
const authenticationResponseSchema = z
  .object({
    id: z.string().min(1),
    rawId: base64UrlSchema,
    type: z.literal('public-key'),
    authenticatorAttachment: z
      .enum(['platform', 'cross-platform'])
      .optional(),
    clientExtensionResults: z.record(z.string(), z.unknown()).optional(),
    response: z.object({
      clientDataJSON: base64UrlSchema,
      authenticatorData: base64UrlSchema,
      signature: base64UrlSchema,
      userHandle: z.string().nullable().optional(),
    }),
  })
  .strict()

// ==================================================================
// 1) REGISTER START — بداية إنشاء الحساب
//    POST /auth/register/start
// ==================================================================
// السيرفر:
//   - يتحقق من الإيميل مش مستخدم
//   - ينشئ challenge مؤقت (Redis أو memory)
//   - يرجع PublicKeyCredentialCreationOptions للفرونت
// الفرونت:
//   - يستدعي navigator.credentials.create(options)
// ==================================================================

export const registerStartSchema = z
  .object({
    organizationName: organizationNameSchema,
    fullName: fullNameSchema,
    email: emailSchema,

    /** اختياري — لتوجيه موديل الـ AI */
    sizeProfile: sizeProfileSchema,

    /** اختياري — مش للدخول */
    password: optionalPasswordSchema,
  })
  .strict()

// ==================================================================
// 2) REGISTER FINISH — تأكيد التسجيل بعد ما المستخدم حط بصمته
//    POST /auth/register/finish
// ==================================================================
// السيرفر:
//   - يتحقق من الـ challenge
//   - يتحقق من attestation عبر @simplewebauthn/server
//   - ينشئ Organization + User(OWNER) + PasskeyCredential + Policy
//   - يصدر JWT
// ==================================================================

export const registerFinishSchema = z
  .object({
    /** نفس الإيميل اللي اتبعت في register/start عشان نربط الـ challenge */
    email: emailSchema,

    /** اسم للعرض على الـ Passkey */
    deviceName: deviceNameSchema,

    /**
     * الـ credential اللي رجعه navigator.credentials.create()
     * بعد تحويل ArrayBuffers لـ Base64URL في الفرونت
     */
    credential: registrationResponseSchema,
  })
  .strict()

// ==================================================================
// 3) LOGIN START — بداية تسجيل الدخول
//    POST /auth/login/start
// ==================================================================
// السيرفر:
//   - يدور على User بالإيميل
//   - يجيب Passkeys المسجّلة (غير الملغاة)
//   - ينشئ challenge ويرجع PublicKeyCredentialRequestOptions
// ==================================================================

export const loginStartSchema = z
  .object({
    email: emailSchema,
  })
  .strict()

// ==================================================================
// 4) LOGIN FINISH — تأكيد الدخول بعد ما المستخدم حط بصمته
//    POST /auth/login/finish
// ==================================================================
// السيرفر:
//   - يتحقق من الـ challenge
//   - يتحقق من الـ assertion بالتوقيع ضد Public Key المخزّن
//   - يحدّث counter + lastUsedAt + lastLoginAt
//   - يصدر JWT
// ==================================================================

export const loginFinishSchema = z
  .object({
    email: emailSchema,

    /** الـ assertion من navigator.credentials.get() */
    credential: authenticationResponseSchema,
  })
  .strict()

// ==================================================================
// 5) ADD PASSKEY START — إضافة جهاز/بصمة جديدة (مسجّل دخول)
//    POST /auth/passkeys/register/start
// ==================================================================

export const addPasskeyStartSchema = z
  .object({
    /** فاضي حاليًا — المستخدم من الـ JWT */
  })
  .strict()
  .optional()
  .default({})

// ==================================================================
// 6) ADD PASSKEY FINISH
//    POST /auth/passkeys/register/finish
// ==================================================================

export const addPasskeyFinishSchema = z
  .object({
    deviceName: deviceNameSchema,
    credential: registrationResponseSchema,
  })
  .strict()

// ==================================================================
// 7) REVOKE PASSKEY — إلغاء مفتاح
//    DELETE /auth/passkeys
// ==================================================================

export const revokePasskeySchema = z
  .object({
    /** id بتاع صف PasskeyCredential في الداتابيز (مش credentialId) */
    passkeyId: z.string().uuid('معرّف الـ Passkey غير صالح'),
  })
  .strict()

// ==================================================================
// 8) UPDATE PROFILE
//    PATCH /auth/profile
// ==================================================================

export const updateProfileSchema = z
  .object({
    fullName: fullNameSchema.optional(),
  })
  .strict()

// ==================================================================
// 9) SET OPTIONAL PASSWORD (مش للدخول الأساسي)
//    POST /auth/password
// ==================================================================

export const setPasswordSchema = z
  .object({
    newPassword: z
      .string()
      .min(8, 'كلمة المرور يجب ألا تقل عن 8 أحرف')
      .max(128)
      .regex(/[a-z]/, 'يجب أن تحتوي على حرف صغير')
      .regex(/[A-Z]/, 'يجب أن تحتوي على حرف كبير')
      .regex(/[0-9]/, 'يجب أن تحتوي على رقم'),
  })
  .strict()

// ==================================================================
// Types — للاستخدام في Service و Routes
// ==================================================================

export type RegisterStartInput = z.infer<typeof registerStartSchema>
export type RegisterFinishInput = z.infer<typeof registerFinishSchema>
export type LoginStartInput = z.infer<typeof loginStartSchema>
export type LoginFinishInput = z.infer<typeof loginFinishSchema>
export type AddPasskeyFinishInput = z.infer<typeof addPasskeyFinishSchema>
export type RevokePasskeyInput = z.infer<typeof revokePasskeySchema>
export type UpdateProfileInput = z.infer<typeof updateProfileSchema>
export type SetPasswordInput = z.infer<typeof setPasswordSchema>

/** أشكال WebAuthn بعد التحويل من الفرونت */
export type RegistrationCredentialJSON = z.infer<typeof registrationResponseSchema>
export type AuthenticationCredentialJSON = z.infer<typeof authenticationResponseSchema>