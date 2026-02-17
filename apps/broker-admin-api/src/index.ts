import 'reflect-metadata'

import {createAdminApiApp} from './app'
import {loadConfig} from './config'

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
  console.error(error)
  process.exit(1)
})
