import type {IncomingMessage, ServerResponse} from 'node:http'

import {Controller, Get, Inject, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'

import type {BrokerApiRouteHandlers} from '../../http/routes/types'
import {BROKER_API_ROUTE_HANDLERS} from '../tokens'

@Controller()
export class WorkloadManifestController {
  public constructor(
    @Inject(BROKER_API_ROUTE_HANDLERS) private readonly routeHandlers: BrokerApiRouteHandlers
  ) {}

  @Get('/v1/workloads/:workloadId/manifest')
  public async handle(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.routeHandlers.workloadManifest(
      request as unknown as IncomingMessage,
      response as unknown as ServerResponse
    )
  }
}
