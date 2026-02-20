import 'reflect-metadata'

import {createStructuredLogger} from '@broker-interceptor/logging'

import {createAdminApiApp} from './app'
import {loadConfig} from './config'

export const appName = 'broker-admin-api'

const main = async () => {
  const config = loadConfig(process.env)
  const app = await createAdminApiApp({config})

  await app.start()

  const shutdown = async () => {
    await app.stop()
    process.exit(0)
  }

  process.on('SIGINT', () => {
    void shutdown()
  })
  process.on('SIGTERM', () => {
    void shutdown()
  })
}

void main().catch(error => {
  const env =
    process.env.NODE_ENV === 'production'
      ? 'production'
      : process.env.NODE_ENV === 'test'
        ? 'test'
        : 'development'
  const startupLogger = createStructuredLogger({
    service: appName,
    env,
    level: 'error'
  })
  startupLogger.fatal({
    event: 'process.startup.failed',
    component: 'process.entrypoint',
    message: 'Broker admin API startup failed',
    reason_code: 'startup_failed',
    metadata: {
      error
    }
  })
  process.exit(1)
})
