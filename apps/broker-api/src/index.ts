import 'reflect-metadata'

import {fileURLToPath} from 'node:url'

import {createStructuredLogger} from '@broker-interceptor/logging'

import {createBrokerApiApp} from './app'
import {loadConfig} from './config'

export const appName = 'broker-api'

export * from './app'
export * from './config'
export * from './dependencyBridge'
export * from './errors'
export * from './http'
export * from './infrastructure'
export * from './repository'
export * from './runtime'

const main = async () => {
  const config = loadConfig(process.env)
  const app = await createBrokerApiApp({config})

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

const isMainModule = (() => {
  const currentFile = fileURLToPath(import.meta.url)
  const entryFile = process.argv[1]
  if (!entryFile) {
    return false
  }

  return currentFile === entryFile
})()

if (isMainModule) {
  void main().catch(error => {
    const env = process.env.NODE_ENV === 'production' ? 'production' : process.env.NODE_ENV === 'test' ? 'test' : 'development'
    const startupLogger = createStructuredLogger({
      service: appName,
      env,
      level: 'error'
    })
    startupLogger.fatal({
      event: 'process.startup.failed',
      component: 'process.entrypoint',
      message: 'Broker API startup failed',
      reason_code: 'startup_failed',
      metadata: {
        error
      }
    })
    process.exit(1)
  })
}
