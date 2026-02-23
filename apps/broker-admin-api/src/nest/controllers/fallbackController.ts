import {All, Controller, Inject, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'

import {notFound} from '../../errors'
import {AdminApiControllerContext} from '../controllerContext'

@Controller()
export class FallbackController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @All('*')
  public async handle(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async () => {
        await this.context.authenticateRequest({request})
        throw notFound('route_not_found', 'Route not found')
      }
    })
  }
}
