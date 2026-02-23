import {describe, expect, it, vi} from 'vitest'
import type {Request, Response} from 'express'
import type {IncomingMessage, ServerResponse} from 'node:http'

import {ExecuteController} from '../nest/controllers/executeController'
import {FallbackController} from '../nest/controllers/fallbackController'
import {HealthController} from '../nest/controllers/healthController'
import {ManifestKeysController} from '../nest/controllers/manifestKeysController'
import {SessionController} from '../nest/controllers/sessionController'
import {WorkloadManifestController} from '../nest/controllers/workloadManifestController'
import type {BrokerApiRouteHandlers} from '../http/routes/types'

const makeRequest = (): Request => ({}) as Request
const makeResponse = (): Response => ({}) as Response

const makeRouteHandlers = () =>
  ({
    health: vi.fn(() => Promise.resolve()),
    manifestKeys: vi.fn(() => Promise.resolve()),
    session: vi.fn(() => Promise.resolve()),
    execute: vi.fn(() => Promise.resolve()),
    workloadManifest: vi.fn(() => Promise.resolve()),
    fallback: vi.fn(() => Promise.resolve())
  }) as unknown as BrokerApiRouteHandlers

describe('nest controllers', () => {
  it('health controller delegates to request handler bridge', async () => {
    const handlers = makeRouteHandlers()
    const controller = new HealthController(handlers)
    const request = makeRequest()
    const response = makeResponse()

    await controller.handle(request, response)

    expect(handlers.health).toHaveBeenCalledTimes(1)
    expect(handlers.health).toHaveBeenCalledWith(
      request as unknown as IncomingMessage,
      response as unknown as ServerResponse
    )
  })

  it('manifest keys controller delegates to request handler bridge', async () => {
    const handlers = makeRouteHandlers()
    const controller = new ManifestKeysController(handlers)
    const request = makeRequest()
    const response = makeResponse()

    await controller.handle(request, response)

    expect(handlers.manifestKeys).toHaveBeenCalledTimes(1)
    expect(handlers.manifestKeys).toHaveBeenCalledWith(
      request as unknown as IncomingMessage,
      response as unknown as ServerResponse
    )
  })

  it('session controller delegates to request handler bridge', async () => {
    const handlers = makeRouteHandlers()
    const controller = new SessionController(handlers)
    const request = makeRequest()
    const response = makeResponse()

    await controller.handle(request, response)

    expect(handlers.session).toHaveBeenCalledTimes(1)
    expect(handlers.session).toHaveBeenCalledWith(
      request as unknown as IncomingMessage,
      response as unknown as ServerResponse
    )
  })

  it('execute controller delegates to request handler bridge', async () => {
    const handlers = makeRouteHandlers()
    const controller = new ExecuteController(handlers)
    const request = makeRequest()
    const response = makeResponse()

    await controller.handle(request, response)

    expect(handlers.execute).toHaveBeenCalledTimes(1)
    expect(handlers.execute).toHaveBeenCalledWith(
      request as unknown as IncomingMessage,
      response as unknown as ServerResponse
    )
  })

  it('workload manifest controller delegates to request handler bridge', async () => {
    const handlers = makeRouteHandlers()
    const controller = new WorkloadManifestController(handlers)
    const request = makeRequest()
    const response = makeResponse()

    await controller.handle(request, response)

    expect(handlers.workloadManifest).toHaveBeenCalledTimes(1)
    expect(handlers.workloadManifest).toHaveBeenCalledWith(
      request as unknown as IncomingMessage,
      response as unknown as ServerResponse
    )
  })

  it('fallback controller delegates to request handler bridge', async () => {
    const handlers = makeRouteHandlers()
    const controller = new FallbackController(handlers)
    const request = makeRequest()
    const response = makeResponse()

    await controller.handle(request, response)

    expect(handlers.fallback).toHaveBeenCalledTimes(1)
    expect(handlers.fallback).toHaveBeenCalledWith(
      request as unknown as IncomingMessage,
      response as unknown as ServerResponse
    )
  })
})
