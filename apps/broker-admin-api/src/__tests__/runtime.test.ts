import {EventEmitter} from 'node:events'
import type {Server} from 'node:http'

import {describe, expect, it, vi} from 'vitest'

import {createControlPlaneRuntime} from '../runtime'

type FakeServer = Server & {
  listen: ReturnType<typeof vi.fn>
  close: ReturnType<typeof vi.fn>
}

const makeFakeServer = ({
  emitListenError
}: {
  emitListenError?: Error
} = {}): FakeServer => {
  const emitter = new EventEmitter()

  const server = {
    once: emitter.once.bind(emitter),
    off: emitter.off.bind(emitter),
    listen: vi.fn((_port: number, _host: string, callback: () => void) => {
      if (emitListenError) {
        setTimeout(() => {
          emitter.emit('error', emitListenError)
        }, 0)
        return
      }

      callback()
    }),
    close: vi.fn((callback: () => void) => {
      callback()
    })
  } as unknown as FakeServer

  return server
}

describe('runtime controls', () => {
  it('starts and stops the server', async () => {
    const server = makeFakeServer()
    const runtime = createControlPlaneRuntime({
      server,
      host: '127.0.0.1',
      port: 8080
    })

    await expect(runtime.start()).resolves.toBeUndefined()
    await expect(runtime.stop()).resolves.toBeUndefined()

    expect(server.listen).toHaveBeenCalledWith(8080, '127.0.0.1', expect.any(Function))
    expect(server.close).toHaveBeenCalledTimes(1)
  })

  it('fails start when the server emits an error', async () => {
    const listenError = new Error('listen failed')
    const server = makeFakeServer({emitListenError: listenError})
    const runtime = createControlPlaneRuntime({
      server,
      host: '127.0.0.1',
      port: 8080
    })

    await expect(runtime.start()).rejects.toBe(listenError)
  })
})
