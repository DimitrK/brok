import {DynamicModule, Module} from '@nestjs/common'
import type {StructuredLogger} from '@broker-interceptor/logging'

import type {ServiceConfig} from '../config'
import type {DependencyBridge} from '../dependencyBridge'
import type {ControlPlaneRepository} from '../repository'
import {AdminAccessRequestsController} from './controllers/adminAccessRequestsController'
import {AdminAuthController} from './controllers/adminAuthController'
import {AdminUsersController} from './controllers/adminUsersController'
import {ApprovalsController} from './controllers/approvalsController'
import {AuditController} from './controllers/auditController'
import {FallbackController} from './controllers/fallbackController'
import {HealthController} from './controllers/healthController'
import {IntegrationsController} from './controllers/integrationsController'
import {ManifestKeysController} from './controllers/manifestKeysController'
import {PoliciesController} from './controllers/policiesController'
import {TemplatesController} from './controllers/templatesController'
import {TenantsController} from './controllers/tenantsController'
import {WorkloadsController} from './controllers/workloadsController'
import {AdminApiControllerContext} from './controllerContext'
import {
  BROKER_ADMIN_API_CONFIG,
  BROKER_ADMIN_API_DEPENDENCY_BRIDGE,
  BROKER_ADMIN_API_LOGGER,
  BROKER_ADMIN_API_REPOSITORY
} from './tokens'

export type AdminApiNestModuleOptions = {
  config: ServiceConfig
  repository: ControlPlaneRepository
  dependencyBridge: DependencyBridge
  logger: StructuredLogger
}

@Module({
  controllers: [
    HealthController,
    AdminAuthController,
    AdminUsersController,
    AdminAccessRequestsController,
    TenantsController,
    WorkloadsController,
    IntegrationsController,
    TemplatesController,
    PoliciesController,
    ApprovalsController,
    AuditController,
    ManifestKeysController,
    FallbackController
  ]
})
export class AdminApiNestModule {
  public static register(options: AdminApiNestModuleOptions): DynamicModule {
    return {
      module: AdminApiNestModule,
      providers: [
        {
          provide: BROKER_ADMIN_API_CONFIG,
          useValue: options.config
        },
        {
          provide: BROKER_ADMIN_API_REPOSITORY,
          useValue: options.repository
        },
        {
          provide: BROKER_ADMIN_API_DEPENDENCY_BRIDGE,
          useValue: options.dependencyBridge
        },
        {
          provide: BROKER_ADMIN_API_LOGGER,
          useValue: options.logger
        },
        AdminApiControllerContext
      ]
    }
  }
}
