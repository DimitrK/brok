import type {IncomingMessage, ServerResponse} from 'node:http'

import {Controller, Inject, Post, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'

import type {BrokerApiRouteHandlers} from '../../http/routes/types'
import {BROKER_API_ROUTE_HANDLERS} from '../tokens'

@Controller()
export class SessionController {
  public constructor(
    @Inject(BROKER_API_ROUTE_HANDLERS) private readonly routeHandlers: BrokerApiRouteHandlers
  ) {}

  @Post('/v1/session')
  public async handle(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.routeHandlers.session(
      request as unknown as IncomingMessage,
      response as unknown as ServerResponse
    )
  }
}
