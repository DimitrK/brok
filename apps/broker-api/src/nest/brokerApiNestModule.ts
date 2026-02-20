import type {IncomingMessage, ServerResponse} from 'node:http'

import {All, Controller, DynamicModule, Inject, Module, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'

import type {AuditService} from '@broker-interceptor/audit'
import type {FetchLike} from '@broker-interceptor/forwarder'
import type {StructuredLogger} from '@broker-interceptor/logging'
import type {DnsResolver} from '@broker-interceptor/ssrf-guard'

import type {ServiceConfig} from '../config'
import {DataPlaneRepository} from '../repository'
import {createBrokerApiRequestHandler} from '../server'
import {
  BROKER_API_AUDIT_SERVICE,
  BROKER_API_CONFIG,
  BROKER_API_DNS_RESOLVER,
  BROKER_API_FETCH_IMPL,
  BROKER_API_LOGGER,
  BROKER_API_NOW,
  BROKER_API_REPOSITORY,
  BROKER_API_REQUEST_HANDLER
} from './tokens'

type RequestHandler = ReturnType<typeof createBrokerApiRequestHandler>

export type BrokerApiNestModuleOptions = {
  config: ServiceConfig
  repository: DataPlaneRepository
  auditService: AuditService
  logger: StructuredLogger
  fetchImpl?: FetchLike
  dnsResolver?: DnsResolver
  now?: () => Date
}

@Controller()
class BrokerApiController {
  public constructor(
    @Inject(BROKER_API_REQUEST_HANDLER)
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
  controllers: [BrokerApiController]
})
export class BrokerApiNestModule {
  public static register(options: BrokerApiNestModuleOptions): DynamicModule {
    return {
      module: BrokerApiNestModule,
      providers: [
        {
          provide: BROKER_API_CONFIG,
          useValue: options.config
        },
        {
          provide: BROKER_API_REPOSITORY,
          useValue: options.repository
        },
        {
          provide: BROKER_API_AUDIT_SERVICE,
          useValue: options.auditService
        },
        {
          provide: BROKER_API_LOGGER,
          useValue: options.logger
        },
        {
          provide: BROKER_API_FETCH_IMPL,
          useValue: options.fetchImpl
        },
        {
          provide: BROKER_API_DNS_RESOLVER,
          useValue: options.dnsResolver
        },
        {
          provide: BROKER_API_NOW,
          useValue: options.now
        },
        {
          provide: BROKER_API_REQUEST_HANDLER,
          inject: [
            BROKER_API_CONFIG,
            BROKER_API_REPOSITORY,
            BROKER_API_AUDIT_SERVICE,
            BROKER_API_LOGGER,
            BROKER_API_FETCH_IMPL,
            BROKER_API_DNS_RESOLVER,
            BROKER_API_NOW
          ],
          useFactory: (
            config: ServiceConfig,
            repository: DataPlaneRepository,
            auditService: AuditService,
            logger: StructuredLogger,
            fetchImpl: FetchLike | undefined,
            dnsResolver: DnsResolver | undefined,
            now: (() => Date) | undefined
          ) =>
            createBrokerApiRequestHandler({
              config,
              repository,
              auditService,
              logger,
              ...(fetchImpl ? {fetchImpl} : {}),
              ...(dnsResolver ? {dnsResolver} : {}),
              ...(now ? {now} : {})
            })
        }
      ]
    }
  }
}
