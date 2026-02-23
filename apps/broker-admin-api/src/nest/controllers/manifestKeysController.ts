import {Controller, Get, Inject, Req, Res} from '@nestjs/common'
import type {Request, Response} from 'express'
import {OpenApiManifestKeysSchema} from '@broker-interceptor/schemas'

import {requireAnyRole} from '../../auth'
import {sendJson} from '../../http'
import {AdminApiControllerContext, listAccessRoles} from '../controllerContext'

@Controller()
export class ManifestKeysController {
  public constructor(@Inject(AdminApiControllerContext) private readonly context: AdminApiControllerContext) {}

  @Get('/v1/keys/manifest')
  public async list(@Req() request: Request, @Res() response: Response): Promise<void> {
    await this.context.handleRequest({
      request,
      response,
      handler: async ({correlationId}) => {
        const principal = await this.context.authenticateRequest({request})
        requireAnyRole({principal, allowed: [...listAccessRoles]})

        const manifestKeys = await this.context.repository.getManifestKeys()
        const payload = OpenApiManifestKeysSchema.parse(manifestKeys.payload)

        sendJson({
          response,
          status: 200,
          correlationId,
          payload,
          headers: {
            'cache-control': 'public, max-age=60, must-revalidate',
            etag: manifestKeys.etag
          }
        })
      }
    })
  }
}
