// backend/src/server.ts
// ==================================================================
// Zero Plus - Server Entry Point
// الملف اللي بيشغل السيرفر فعليًا
// ==================================================================

import 'dotenv/config'
import { buildApp } from './app.js'

const PORT = Number(process.env.PORT) || 4000
const HOST = process.env.HOST || '0.0.0.0'

async function start() {
  try {
    const app = await buildApp()

    await app.listen({ port: PORT, host: HOST })

    console.log(`
============================================================
  Zero Plus Backend is running!
============================================================
  Local:    http://localhost:${PORT}
  Health:   http://localhost:${PORT}/health
  Env:      ${process.env.NODE_ENV || 'development'}
============================================================
    `)
  } catch (err) {
    console.error('Failed to start server:', err)
    process.exit(1)
  }
}

start()