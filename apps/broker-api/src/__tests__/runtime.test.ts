import {describe, expect, it, vi} from 'vitest'

import {createDataPlaneRuntime} from '../runtime'

type MockServer = {
  once: ReturnType<typeof vi.fn>
  off: ReturnType<typeof vi.fn>
  listen: ReturnType<typeof vi.fn>
  close: ReturnType<typeof vi.fn>
}

const createMockServer = (): {
  server: MockServer
  listeners: Map<string, (...args: unknown[]) => void>
} => {
  const listeners = new Map<string, (...args: unknown[]) => void>()

  const server: MockServer = {
    once: vi.fn((event: string, handler: (...args: unknown[]) => void) => {
      listeners.set(event, handler)
      return server
    }),
    off: vi.fn((event: string) => {
      listeners.delete(event)
      return server
    }),
    listen: vi.fn((_port: number, _host: string, callback: () => void) => {
      callback()
      return server
    }),
    close: vi.fn((callback: () => void) => {
      callback()
      return server
    })
  }

  return {
    server,
    listeners
  }
}

describe('data plane runtime', () => {
  it('starts server and removes temporary error listener after successful listen', async () => {
    const {server} = createMockServer()

    const runtime = createDataPlaneRuntime({
      server: server as never,
      host: '127.0.0.1',
      port: 8081
    })

    await expect(runtime.start()).resolves.toBeUndefined()

    expect(server.once).toHaveBeenCalledWith('error', expect.any(Function))
    expect(server.listen).toHaveBeenCalledWith(8081, '127.0.0.1', expect.any(Function))
    expect(server.off).toHaveBeenCalledWith('error', expect.any(Function))
  })

  it('rejects startup when server emits an error before successful listen', async () => {
    const {server, listeners} = createMockServer()
    const startupError = new Error('listen failed')

    server.listen = vi.fn((port: number, host: string, callback: () => void) => {
      void port
      void host
      void callback
      const errorListener = listeners.get('error')
      if (errorListener) {
        errorListener(startupError)
      }
      return server
    })

    const runtime = createDataPlaneRuntime({
      server: server as never,
      host: '127.0.0.1',
      port: 8081
    })

    await expect(runtime.start()).rejects.toThrow('listen failed')
  })

  it('stops server by delegating to close callback completion', async () => {
    const {server} = createMockServer()

    const runtime = createDataPlaneRuntime({
      server: server as never,
      host: '127.0.0.1',
      port: 8081
    })

    await expect(runtime.stop()).resolves.toBeUndefined()
    expect(server.close).toHaveBeenCalledTimes(1)
  })
})
