import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest'

const originalArgv = [...process.argv]

const flushMicrotasks = async () => {
  await new Promise<void>(resolve => {
    setTimeout(() => resolve(), 0)
  })
}

beforeEach(() => {
  process.argv = [...originalArgv]
})

afterEach(() => {
  process.argv = [...originalArgv]
  vi.restoreAllMocks()
  vi.resetModules()
})

describe('broker-api index entrypoint', () => {
  it('does not auto-start when imported as a non-entry module', async () => {
    const createBrokerApiApp = vi.fn()
    const loadConfig = vi.fn()

    vi.doMock('../app', () => ({
      createBrokerApiApp
    }))
    vi.doMock('../config', () => ({
      loadConfig
    }))
    vi.doMock('node:url', () => ({
      fileURLToPath: vi.fn(() => '/virtual/index.ts')
    }))

    process.argv[1] = '/virtual/other-entry.js'

    const imported = await import('../index')
    await flushMicrotasks()

    expect(imported.appName).toBe('broker-api')
    expect(loadConfig).not.toHaveBeenCalled()
    expect(createBrokerApiApp).not.toHaveBeenCalled()
  }, 15_000)

  it('starts app when running as the entry module and handles startup failures', async () => {
    const start = vi.fn().mockResolvedValue(undefined)
    const stop = vi.fn().mockResolvedValue(undefined)
    const loadConfig = vi.fn().mockReturnValue({mode: 'test'})
    const createBrokerApiApp = vi.fn().mockResolvedValue({start, stop})

    vi.doMock('../app', () => ({
      createBrokerApiApp
    }))
    vi.doMock('../config', () => ({
      loadConfig
    }))
    vi.doMock('node:url', () => ({
      fileURLToPath: vi.fn(() => '/virtual/entry.js')
    }))

    process.argv[1] = '/virtual/entry.js'

    const onSpy = vi.spyOn(process, 'on').mockImplementation(() => process)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never)

    await import('../index')
    await flushMicrotasks()

    expect(loadConfig).toHaveBeenCalledTimes(1)
    expect(createBrokerApiApp).toHaveBeenCalledTimes(1)
    expect(start).toHaveBeenCalledTimes(1)

    const sigintHandler = onSpy.mock.calls.find(call => call[0] === 'SIGINT')?.[1]
    expect(typeof sigintHandler).toBe('function')
    if (typeof sigintHandler === 'function') {
      sigintHandler()
    }
    await flushMicrotasks()

    expect(stop).toHaveBeenCalledTimes(1)
    expect(exitSpy).toHaveBeenCalledWith(0)
  })

  it('logs and exits when startup fails in entry mode', async () => {
    const startupError = new Error('broker startup failed')
    const createBrokerApiApp = vi.fn().mockRejectedValue(startupError)

    vi.doMock('../app', () => ({
      createBrokerApiApp
    }))
    vi.doMock('../config', () => ({
      loadConfig: vi.fn().mockReturnValue({})
    }))
    vi.doMock('node:url', () => ({
      fileURLToPath: vi.fn(() => '/virtual/failing-entry.js')
    }))

    process.argv[1] = '/virtual/failing-entry.js'

    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never)

    await import('../index')
    await flushMicrotasks()

    expect(createBrokerApiApp).toHaveBeenCalledTimes(1)
    expect(consoleErrorSpy).toHaveBeenCalledWith(startupError)
    expect(exitSpy).toHaveBeenCalledWith(1)
  })
})
