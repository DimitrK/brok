import 'reflect-metadata'

import {fileURLToPath} from 'node:url'

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
export * from './server'

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
    console.error(error)
    process.exit(1)
  })
}
