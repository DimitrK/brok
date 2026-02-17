import {afterEach, describe, expect, it, vi} from 'vitest'

afterEach(() => {
  vi.restoreAllMocks()
  vi.resetModules()
})

const flushMicrotasks = async () => {
  await new Promise<void>(resolve => {
    setTimeout(() => resolve(), 0)
  })
}

describe('index entrypoint', () => {
  it('loads config, starts app, and wires shutdown handlers', async () => {
    const start = vi.fn().mockResolvedValue(undefined)
    const stop = vi.fn().mockResolvedValue(undefined)
    const createAdminApiApp = vi.fn().mockResolvedValue({start, stop})
    const loadConfig = vi.fn().mockReturnValue({})

    vi.doMock('../app', () => ({
      createAdminApiApp
    }))
    vi.doMock('../config', () => ({
      loadConfig
    }))

    const onSpy = vi.spyOn(process, 'on').mockImplementation(() => process)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never)

    await import('../index')
    await flushMicrotasks()

    expect(loadConfig).toHaveBeenCalledTimes(1)
    expect(createAdminApiApp).toHaveBeenCalledTimes(1)
    expect(start).toHaveBeenCalledTimes(1)

    const sigintHandler = onSpy.mock.calls.find(call => call[0] === 'SIGINT')?.[1]
    const sigtermHandler = onSpy.mock.calls.find(call => call[0] === 'SIGTERM')?.[1]

    expect(sigintHandler).toBeTypeOf('function')
    expect(sigtermHandler).toBeTypeOf('function')

    if (typeof sigintHandler === 'function') {
      sigintHandler()
    }
    await flushMicrotasks()

    expect(stop).toHaveBeenCalledTimes(1)
    expect(exitSpy).toHaveBeenCalledWith(0)
  })

  it('logs startup failures and exits with code 1', async () => {
    const startupError = new Error('startup failed')
    const createAdminApiApp = vi.fn().mockRejectedValue(startupError)

    vi.doMock('../app', () => ({
      createAdminApiApp
    }))
    vi.doMock('../config', () => ({
      loadConfig: vi.fn().mockReturnValue({})
    }))

    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never)

    await import('../index')
    await flushMicrotasks()

    expect(createAdminApiApp).toHaveBeenCalledTimes(1)
    expect(consoleErrorSpy).toHaveBeenCalledWith(startupError)
    expect(exitSpy).toHaveBeenCalledWith(1)
  })
})
