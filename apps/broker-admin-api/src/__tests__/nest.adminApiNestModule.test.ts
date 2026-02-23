import {describe, expect, it} from 'vitest'

import {AdminApiNestModule} from '../nest/adminApiNestModule'
import {AdminApiControllerContext} from '../nest/controllerContext'
import {
  BROKER_ADMIN_API_CONFIG,
  BROKER_ADMIN_API_DEPENDENCY_BRIDGE,
  BROKER_ADMIN_API_LOGGER,
  BROKER_ADMIN_API_REPOSITORY
} from '../nest/tokens'

describe('admin api nest module', () => {
  it('registers providers for controller runtime dependencies', () => {
    const config = {maxBodyBytes: 1_024} as never
    const repository = {} as never
    const dependencyBridge = {} as never
    const logger = {} as never

    const dynamicModule = AdminApiNestModule.register({
      config,
      repository,
      dependencyBridge,
      logger
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

    const loggerProvider = providers.find(
      provider =>
        typeof provider === 'object' &&
        provider !== null &&
        'provide' in provider &&
        provider.provide === BROKER_ADMIN_API_LOGGER
    )
    expect(loggerProvider).toBeDefined()

    expect(providers).toContain(AdminApiControllerContext)
  })
})
