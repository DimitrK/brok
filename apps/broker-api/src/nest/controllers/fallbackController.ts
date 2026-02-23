import type {IncomingMessage, ServerResponse} from 'node:http'

import {All, Controller, Inject, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'

import type {BrokerApiRouteHandlers} from '../../http/routes/types'
import {BROKER_API_ROUTE_HANDLERS} from '../tokens'

@Controller()
export class FallbackController {
  public constructor(
    @Inject(BROKER_API_ROUTE_HANDLERS) private readonly routeHandlers: BrokerApiRouteHandlers
  ) {}

  @All('*')
  public async handle(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.routeHandlers.fallback(
      request as unknown as IncomingMessage,
      response as unknown as ServerResponse
    )
  }
}
