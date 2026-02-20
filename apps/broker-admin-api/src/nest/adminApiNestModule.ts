import type {IncomingMessage, ServerResponse} from 'node:http'

import {All, Controller, DynamicModule, Inject, Module, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import type {StructuredLogger} from '@broker-interceptor/logging'

import type {ServiceConfig} from '../config'
import type {DependencyBridge} from '../dependencyBridge'
import type {ControlPlaneRepository} from '../repository'
import {createAdminApiRequestHandler} from '../server'
import {
  BROKER_ADMIN_API_CONFIG,
  BROKER_ADMIN_API_DEPENDENCY_BRIDGE,
  BROKER_ADMIN_API_LOGGER,
  BROKER_ADMIN_API_REPOSITORY,
  BROKER_ADMIN_API_REQUEST_HANDLER
} from './tokens'

type RequestHandler = ReturnType<typeof createAdminApiRequestHandler>

export type AdminApiNestModuleOptions = {
  config: ServiceConfig
  repository: ControlPlaneRepository
  dependencyBridge: DependencyBridge
  logger: StructuredLogger
}

@Controller()
class AdminApiController {
  public constructor(
    @Inject(BROKER_ADMIN_API_REQUEST_HANDLER)
    private readonly requestHandler: RequestHandler
  ) {}

  @All('*')
  public async handle(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.requestHandler(
      request as unknown as IncomingMessage,
      response as unknown as ServerResponse
    )
  }
}

@Module({
  controllers: [AdminApiController]
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
        {
          provide: BROKER_ADMIN_API_REQUEST_HANDLER,
          inject: [
            BROKER_ADMIN_API_CONFIG,
            BROKER_ADMIN_API_REPOSITORY,
            BROKER_ADMIN_API_DEPENDENCY_BRIDGE,
            BROKER_ADMIN_API_LOGGER
          ],
          useFactory: (
            config: ServiceConfig,
            repository: ControlPlaneRepository,
            dependencyBridge: DependencyBridge,
            logger: StructuredLogger
          ) =>
            createAdminApiRequestHandler({
              config,
              repository,
              dependencyBridge,
              logger
            })
        }
      ]
    }
  }
}
