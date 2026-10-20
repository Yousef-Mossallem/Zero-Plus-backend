// backend/src/modules/auth/auth.service.ts
// ==================================================================
// Zero Plus - Auth Service
// WebAuthn / Passkeys (بصمة إصبع أو وجه)
// السيرفر يخزّن Public Key فقط — Private Key ما بيسيبش الجهاز
// ==================================================================

import type { FastifyInstance } from 'fastify'
// بدلاً من: import bcrypt from 'bcrypt'
import bcrypt from 'bcryptjs'
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
} from '@simplewebauthn/server'
import type {
  RegisterStartInput,
  RegisterFinishInput,
  LoginStartInput,
  LoginFinishInput,
  AddPasskeyFinishInput,
  UpdateProfileInput,
  SetPasswordInput,
} from './auth.schema.js'

// ------------------------------------------------------------------
// Config — من Environment
// ------------------------------------------------------------------

const SALT_ROUNDS = 12

/** Domain بتاع الـ Relying Party (مثال: localhost أو zeroplus.com) */
function getRpId(): string {
  return process.env.WEBAUTHN_RP_ID || 'localhost'
}

/** اسم يظهر للمستخدم في نافذة البصمة */
function getRpName(): string {
  return process.env.WEBAUTHN_RP_NAME || 'Zero Plus'
}

/** Origin المسموح (مثال: http://localhost:5173) */
function getOrigin(): string {
  return process.env.WEBAUTHN_ORIGIN || 'http://localhost:5173'
}

/** مدة صلاحية الـ challenge بالثواني */
const CHALLENGE_TTL_SEC = 60

// ------------------------------------------------------------------
// Challenge store (Redis لو موجود، وإلا memory)
// المفتاح: challenge:{email} أو challenge:user:{userId}
// ------------------------------------------------------------------

type ChallengeRecord = {
  challenge: string
  // بيانات مؤقتة للـ register/start قبل ما الـ finish يكمل
  pending?: {
    organizationName: string
    fullName: string
    email: string
    sizeProfile: string
    passwordHash: string | null
  }
  userId?: string
}

async function saveChallenge(
  fastify: FastifyInstance,
  key: string,
  record: ChallengeRecord
): Promise<void> {
  const payload = JSON.stringify(record)
  const redis = (fastify as FastifyInstance & { redis?: { set: Function } }).redis
  if (redis?.set) {
    await redis.set(`webauthn:${key}`, payload, 'EX', CHALLENGE_TTL_SEC)
    return
  }
  // fallback memory
  if (!(globalThis as any).__zpChallenges) {
    ;(globalThis as any).__zpChallenges = new Map<string, { exp: number; data: string }>()
  }
  ;(globalThis as any).__zpChallenges.set(key, {
    exp: Date.now() + CHALLENGE_TTL_SEC * 1000,
    data: payload,
  })
}

async function takeChallenge(
  fastify: FastifyInstance,
  key: string
): Promise<ChallengeRecord | null> {
  const redis = (fastify as FastifyInstance & { redis?: { get: Function; del: Function } }).redis
  if (redis?.get) {
    const raw = await redis.get(`webauthn:${key}`)
    if (!raw) return null
    await redis.del(`webauthn:${key}`)
    return JSON.parse(raw) as ChallengeRecord
  }
  const store = (globalThis as any).__zpChallenges as
    | Map<string, { exp: number; data: string }>
    | undefined
  if (!store) return null
  const entry = store.get(key)
  store.delete(key)
  if (!entry || entry.exp < Date.now()) return null
  return JSON.parse(entry.data) as ChallengeRecord
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS)
}

function generateSlug(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

function signToken(
  fastify: FastifyInstance,
  payload: {
    id: string
    email: string
    role: string
    organizationId: string
    passkeyId?: string
  }
) {
  const body: {
    id: string
    email: string
    role: string
    organizationId: string
    passkeyId?: string
  } = {
    id: payload.id,
    email: payload.email,
    role: payload.role,
    organizationId: payload.organizationId,
  }
  if (payload.passkeyId) {
    body.passkeyId = payload.passkeyId
  }
  return fastify.jwt.sign(body)
}

/** حوّل Uint8Array لـ Buffer عشان Prisma Bytes */
function toBuffer(data: Uint8Array): Buffer {
  return Buffer.from(data)
}

// ==================================================================
// REGISTER START
// ينشئ challenge + يخزّن بيانات الحساب مؤقتًا لحد الـ finish
// ==================================================================

export async function registerStart(
  fastify: FastifyInstance,
  data: RegisterStartInput
) {
  const { organizationName, fullName, email, sizeProfile = 'medium', password } =
    data

  const existingUser = await fastify.prisma.user.findUnique({
    where: { email },
  })
  if (existingUser) {
    throw new Error('EMAIL_ALREADY_EXISTS')
  }

  const passwordHash = password ? await hashPassword(password) : null

  // options لإنشاء Passkey جديد (مفيش excludeCredentials لأن الحساب جديد)
  const options = await generateRegistrationOptions({
    rpName: getRpName(),
    rpID: getRpId(),
    userName: email,
    userDisplayName: fullName,
    // نفضّل platform authenticator = بصمة / وجه على نفس الجهاز
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'preferred',
      requireResidentKey: false,
    },
    // ES256 + RS256
    supportedAlgorithmIDs: [-7, -257],
  })

  await saveChallenge(fastify, `reg:${email}`, {
    challenge: options.challenge,
    pending: {
      organizationName,
      fullName,
      email,
      sizeProfile,
      passwordHash,
    },
  })

  return {
    options,
    // الفرونت محتاج يعرف الـ rpId أحيانًا
    rpId: getRpId(),
  }
}

// ==================================================================
// REGISTER FINISH
// يتحقق من الـ attestation → ينشئ Org + User + Passkey + Policy → JWT
// ==================================================================

export async function registerFinish(
  fastify: FastifyInstance,
  data: RegisterFinishInput
) {
  const { email, deviceName, credential } = data

  const record = await takeChallenge(fastify, `reg:${email}`)
  if (!record?.pending || !record.challenge) {
    throw new Error('CHALLENGE_EXPIRED')
  }

  const pending = record.pending

  let verification: VerifiedRegistrationResponse
  try {
    verification = await verifyRegistrationResponse({
      response: credential as any,
      expectedChallenge: record.challenge,
      expectedOrigin: getOrigin(),
      expectedRPID: getRpId(),
      requireUserVerification: true,
    })
  } catch {
    throw new Error('WEBAUTHN_VERIFICATION_FAILED')
  }

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error('WEBAUTHN_VERIFICATION_FAILED')
  }

  const { credential: regCred, credentialDeviceType, credentialBackedUp } =
    verification.registrationInfo

  const credentialId = regCred.id
  const publicKey = toBuffer(regCred.publicKey)
  const counter = regCred.counter
  const transports = (credential.response.transports ?? []) as string[]
  const aaguid =
    (verification.registrationInfo as any).aaguid?.toString?.() ?? null

  // تأكد الإيميل لسه فاضي (سباق نادر)
  const existingUser = await fastify.prisma.user.findUnique({
    where: { email: pending.email },
  })
  if (existingUser) {
    throw new Error('EMAIL_ALREADY_EXISTS')
  }

  // credentialId فريد عالميًا
  const existingCred = await fastify.prisma.passkeyCredential.findUnique({
    where: { credentialId },
  })
  if (existingCred) {
    throw new Error('PASSKEY_ALREADY_REGISTERED')
  }

  let slug = generateSlug(pending.organizationName)
  const existingOrg = await fastify.prisma.organization.findUnique({
    where: { slug },
  })
  if (existingOrg) {
    slug = `${slug}-${Math.floor(1000 + Math.random() * 9000)}`
  }

  const result = await fastify.prisma.$transaction(async (tx) => {
    const organization = await tx.organization.create({
      data: {
        name: pending.organizationName,
        slug,
        plan: 'free',
        isActive: true,
        sizeProfile: pending.sizeProfile,
      },
    })

    const user = await tx.user.create({
      data: {
        email: pending.email,
        fullName: pending.fullName,
        passwordHash: pending.passwordHash,
        role: 'OWNER',
        organizationId: organization.id,
        isActive: true,
        lastLoginAt: new Date(),
      },
      select: {
        id: true,
        email: true,
        fullName: true,
        role: true,
        organizationId: true,
        createdAt: true,
      },
    })

    const passkey = await tx.passkeyCredential.create({
      data: {
        credentialId,
        publicKey: new Uint8Array(regCred.publicKey),
        counter,
        transports,
        deviceName: deviceName ?? credentialDeviceType ?? 'Passkey',
        aaguid,
        userId: user.id,
        lastUsedAt: new Date(),
      },
      select: {
        id: true,
        deviceName: true,
        transports: true,
        createdAt: true,
      },
    })

    await tx.policy.create({
      data: {
        organizationId: organization.id,
      },
    })

    return { user, organization, passkey }
  })

  const token = signToken(fastify, {
    id: result.user.id,
    email: result.user.email,
    role: result.user.role,
    organizationId: result.user.organizationId,
    passkeyId: result.passkey.id,
  })

  return {
    token,
    user: {
      id: result.user.id,
      email: result.user.email,
      fullName: result.user.fullName,
      role: result.user.role,
      organizationId: result.user.organizationId,
    },
    organization: {
      id: result.organization.id,
      name: result.organization.name,
      slug: result.organization.slug,
      sizeProfile: result.organization.sizeProfile,
    },
    passkey: {
      id: result.passkey.id,
      deviceName: result.passkey.deviceName,
      transports: result.passkey.transports,
    },
  }
}

// ==================================================================
// LOGIN START
// يرجع authentication options بناءً على Passkeys المستخدم
// ==================================================================

export async function loginStart(
  fastify: FastifyInstance,
  data: LoginStartInput
) {
  const { email } = data

  const user = await fastify.prisma.user.findUnique({
    where: { email },
    include: {
      passkeys: {
        where: { isRevoked: false },
        select: {
          credentialId: true,
          transports: true,
        },
      },
      organization: {
        select: { isActive: true },
      },
    },
  })

  // نفس الرسالة سواء الإيميل مش موجود أو مفيش passkeys (منع enumeration)
  if (!user || !user.isActive || !user.organization.isActive || user.passkeys.length === 0) {
    // لسه نرجع options فاضي الشكل عشان الفرونت ما يفرّقش — أو نرمي خطأ موحّد
    throw new Error('INVALID_CREDENTIALS')
  }

  const options = await generateAuthenticationOptions({
    rpID: getRpId(),
    userVerification: 'required',
    allowCredentials: user.passkeys.map((pk) => ({
      id: pk.credentialId,
      transports: pk.transports as AuthenticatorTransport[],
    })),
  })

  await saveChallenge(fastify, `login:${email}`, {
    challenge: options.challenge,
    userId: user.id,
  })

  return {
    options,
    rpId: getRpId(),
  }
}

// ==================================================================
// LOGIN FINISH
// يتحقق من الـ assertion ضد Public Key → JWT
// ==================================================================

export async function loginFinish(
  fastify: FastifyInstance,
  data: LoginFinishInput
) {
  const { email, credential } = data

  const record = await takeChallenge(fastify, `login:${email}`)
  if (!record?.challenge || !record.userId) {
    throw new Error('CHALLENGE_EXPIRED')
  }

  const passkey = await fastify.prisma.passkeyCredential.findFirst({
    where: {
      credentialId: credential.id,
      isRevoked: false,
      userId: record.userId,
    },
    include: {
      user: {
        include: {
          organization: {
            select: {
              id: true,
              name: true,
              slug: true,
              isActive: true,
              sizeProfile: true,
            },
          },
        },
      },
    },
  })

  if (!passkey || !passkey.user) {
    throw new Error('INVALID_CREDENTIALS')
  }

  const user = passkey.user

  if (!user.isActive) {
    throw new Error('ACCOUNT_DISABLED')
  }
  if (!user.organization.isActive) {
    throw new Error('ORGANIZATION_DISABLED')
  }

  let verification: VerifiedAuthenticationResponse
  try {
    verification = await verifyAuthenticationResponse({
      response: credential as any,
      expectedChallenge: record.challenge,
      expectedOrigin: getOrigin(),
      expectedRPID: getRpId(),
      credential: {
        id: passkey.credentialId,
        publicKey: new Uint8Array(passkey.publicKey),
        counter: passkey.counter,
        transports: passkey.transports as AuthenticatorTransport[],
      },
      requireUserVerification: true,
    })
  } catch {
    throw new Error('WEBAUTHN_VERIFICATION_FAILED')
  }

  if (!verification.verified) {
    throw new Error('WEBAUTHN_VERIFICATION_FAILED')
  }

  const newCounter = verification.authenticationInfo.newCounter

  await fastify.prisma.$transaction([
    fastify.prisma.passkeyCredential.update({
      where: { id: passkey.id },
      data: {
        counter: newCounter,
        lastUsedAt: new Date(),
      },
    }),
    fastify.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    }),
  ])

  const token = signToken(fastify, {
    id: user.id,
    email: user.email,
    role: user.role,
    organizationId: user.organizationId,
    passkeyId: passkey.id,
  })

  return {
    token,
    user: {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      organizationId: user.organizationId,
    },
    organization: {
      id: user.organization.id,
      name: user.organization.name,
      slug: user.organization.slug,
      sizeProfile: user.organization.sizeProfile,
    },
    passkey: {
      id: passkey.id,
      deviceName: passkey.deviceName,
    },
  }
}

// ==================================================================
// ADD PASSKEY START (مستخدم مسجّل دخول)
// ==================================================================

export async function addPasskeyStart(
  fastify: FastifyInstance,
  userId: string
) {
  const user = await fastify.prisma.user.findUnique({
    where: { id: userId },
    include: {
      passkeys: {
        where: { isRevoked: false },
        select: { credentialId: true, transports: true },
      },
    },
  })

  if (!user || !user.isActive) {
    throw new Error('USER_NOT_FOUND')
  }

  const options = await generateRegistrationOptions({
    rpName: getRpName(),
    rpID: getRpId(),
    userName: user.email,
    userDisplayName: user.fullName,
    // استبعد الـ passkeys الموجودة عشان ما يسجّلش نفس الجهاز مرتين بالغلط
    excludeCredentials: user.passkeys.map((pk) => ({
      id: pk.credentialId,
      transports: pk.transports as AuthenticatorTransport[],
    })),
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'preferred',
    },
    supportedAlgorithmIDs: [-7, -257],
  })

  await saveChallenge(fastify, `addpk:${userId}`, {
    challenge: options.challenge,
    userId,
  })

  return {
    options,
    rpId: getRpId(),
  }
}

// ==================================================================
// ADD PASSKEY FINISH
// ==================================================================

export async function addPasskeyFinish(
  fastify: FastifyInstance,
  userId: string,
  data: AddPasskeyFinishInput
) {
  const { deviceName, credential } = data

  const record = await takeChallenge(fastify, `addpk:${userId}`)
  if (!record?.challenge) {
    throw new Error('CHALLENGE_EXPIRED')
  }

  let verification: VerifiedRegistrationResponse
  try {
    verification = await verifyRegistrationResponse({
      response: credential as any,
      expectedChallenge: record.challenge,
      expectedOrigin: getOrigin(),
      expectedRPID: getRpId(),
      requireUserVerification: true,
    })
  } catch {
    throw new Error('WEBAUTHN_VERIFICATION_FAILED')
  }

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error('WEBAUTHN_VERIFICATION_FAILED')
  }

  const { credential: regCred, credentialDeviceType } =
    verification.registrationInfo

  const existingCred = await fastify.prisma.passkeyCredential.findUnique({
    where: { credentialId: regCred.id },
  })
  if (existingCred) {
    throw new Error('PASSKEY_ALREADY_REGISTERED')
  }

  const passkey = await fastify.prisma.passkeyCredential.create({
    data: {
      credentialId: regCred.id,
      publicKey: Uint8Array.from(regCred.publicKey),
      counter: regCred.counter,
      transports: (credential.response.transports ?? []) as string[],
      deviceName: deviceName ?? credentialDeviceType ?? 'Passkey',
      aaguid:
        (verification.registrationInfo as any).aaguid?.toString?.() ?? null,
      userId,
      lastUsedAt: new Date(),
    },
    select: {
      id: true,
      deviceName: true,
      transports: true,
      createdAt: true,
    },
  })

  return passkey
}

// ==================================================================
// REVOKE PASSKEY
// ==================================================================

export async function revokePasskey(
  fastify: FastifyInstance,
  userId: string,
  passkeyId: string
) {
  const passkey = await fastify.prisma.passkeyCredential.findFirst({
    where: { id: passkeyId, userId },
  })

  if (!passkey) {
    throw new Error('PASSKEY_NOT_FOUND')
  }

  const activeCount = await fastify.prisma.passkeyCredential.count({
    where: { userId, isRevoked: false },
  })

  if (activeCount <= 1 && !passkey.isRevoked) {
    throw new Error('CANNOT_REVOKE_LAST_PASSKEY')
  }

  await fastify.prisma.passkeyCredential.update({
    where: { id: passkeyId },
    data: { isRevoked: true },
  })

  return { ok: true }
}

// ==================================================================
// LIST PASSKEYS
// ==================================================================

export async function listPasskeys(fastify: FastifyInstance, userId: string) {
  return fastify.prisma.passkeyCredential.findMany({
    where: { userId, isRevoked: false },
    select: {
      id: true,
      deviceName: true,
      transports: true,
      lastUsedAt: true,
      createdAt: true,
    },
    orderBy: { lastUsedAt: 'desc' },
  })
}

// ==================================================================
// GET ME
// ==================================================================

export async function getMe(fastify: FastifyInstance, userId: string) {
  const user = await fastify.prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      fullName: true,
      role: true,
      organizationId: true,
      lastLoginAt: true,
      createdAt: true,
      uiPreferences: true,
      organization: {
        select: {
          id: true,
          name: true,
          slug: true,
          plan: true,
          sizeProfile: true,
        },
      },
      passkeys: {
        where: { isRevoked: false },
        select: {
          id: true,
          deviceName: true,
          transports: true,
          lastUsedAt: true,
          createdAt: true,
        },
      },
    },
  })

  if (!user) {
    throw new Error('USER_NOT_FOUND')
  }

  return user
}

// ==================================================================
// UPDATE PROFILE
// ==================================================================

export async function updateProfile(
  fastify: FastifyInstance,
  userId: string,
  data: UpdateProfileInput
) {
  return fastify.prisma.user.update({
    where: { id: userId },
    data: {
      ...(data.fullName ? { fullName: data.fullName } : {}),
    },
    select: {
      id: true,
      email: true,
      fullName: true,
      role: true,
      organizationId: true,
    },
  })
}

// ==================================================================
// SET OPTIONAL PASSWORD
// ==================================================================

export async function setPassword(
  fastify: FastifyInstance,
  userId: string,
  data: SetPasswordInput
) {
  const passwordHash = await hashPassword(data.newPassword)
  await fastify.prisma.user.update({
    where: { id: userId },
    data: { passwordHash },
  })
  return { ok: true}

}
