import {OpenApiManifestKeysSchema} from '@broker-interceptor/schemas'

import {sendJson} from '../../http'
import type {BrokerApiRouteLogicHandler} from './types'

export const handleManifestKeysRoute: BrokerApiRouteLogicHandler = async ({
  request,
  response,
  correlationId,
  runtime
}) => {
  await runtime.requireMtlsContextWithLogging({
    request,
    repository: runtime.repository,
    ...(runtime.config.expectedSanUriPrefix
      ? {expectedSanUriPrefix: runtime.config.expectedSanUriPrefix}
      : {})
  })

  const manifestKeys = await runtime.repository.getManifestVerificationKeysShared()
  const payload = OpenApiManifestKeysSchema.parse(manifestKeys)

  sendJson({
    response,
    status: 200,
    correlationId,
    payload,
    headers: {
      'cache-control': 'public, max-age=60, must-revalidate'
    }
  })
}
