import {Controller, Get, Inject, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'

import {sendJson} from '../../http'
import {AdminApiControllerContext} from '../controllerContext'

@Controller()
export class HealthController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Get('/healthz')
  public async handle(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: ({correlationId}) => {
        sendJson({
          response,
          status: 200,
          correlationId,
          payload: {status: 'ok'}
        })
      }
    })
  }
}
