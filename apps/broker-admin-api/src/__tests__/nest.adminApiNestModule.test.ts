import {describe, expect, it} from 'vitest'

import {AdminApiNestModule} from '../nest/adminApiNestModule'
import {
  BROKER_ADMIN_API_CONFIG,
  BROKER_ADMIN_API_DEPENDENCY_BRIDGE,
  BROKER_ADMIN_API_REPOSITORY,
  BROKER_ADMIN_API_REQUEST_HANDLER
} from '../nest/tokens'

describe('admin api nest module', () => {
  it('registers providers and request handler factory', () => {
    const config = {maxBodyBytes: 1_024} as never
    const repository = {} as never
    const dependencyBridge = {} as never

    const dynamicModule = AdminApiNestModule.register({
      config,
      repository,
      dependencyBridge
    })

    expect(dynamicModule.module).toBe(AdminApiNestModule)
    const providers = dynamicModule.providers ?? []
    expect(providers.length).toBeGreaterThanOrEqual(4)

    const configProvider = providers.find(
      provider =>
        typeof provider === 'object' && provider !== null && 'provide' in provider && provider.provide === BROKER_ADMIN_API_CONFIG
    )
    expect(configProvider).toBeDefined()

    const repositoryProvider = providers.find(
      provider =>
        typeof provider === 'object' &&
        provider !== null &&
        'provide' in provider &&
        provider.provide === BROKER_ADMIN_API_REPOSITORY
    )
    expect(repositoryProvider).toBeDefined()

    const dependencyBridgeProvider = providers.find(
      provider =>
        typeof provider === 'object' &&
        provider !== null &&
        'provide' in provider &&
        provider.provide === BROKER_ADMIN_API_DEPENDENCY_BRIDGE
    )
    expect(dependencyBridgeProvider).toBeDefined()

    const requestHandlerProvider = providers.find(
      provider =>
        typeof provider === 'object' &&
        provider !== null &&
        'provide' in provider &&
        provider.provide === BROKER_ADMIN_API_REQUEST_HANDLER
    )

    if (
      !requestHandlerProvider ||
      typeof requestHandlerProvider !== 'object' ||
      !('useFactory' in requestHandlerProvider) ||
      typeof requestHandlerProvider.useFactory !== 'function'
    ) {
      throw new Error('expected request handler provider with useFactory')
    }

    const requestHandlerUnknown: unknown = requestHandlerProvider.useFactory(
      config,
      repository,
      dependencyBridge
    )
    expect(typeof requestHandlerUnknown).toBe('function')
  })
})
