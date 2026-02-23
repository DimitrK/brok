import {sendJson} from '../../http'
import type {BrokerApiRouteLogicHandler} from './types'

export const handleHealthRoute: BrokerApiRouteLogicHandler = ({response, correlationId}) => {
  sendJson({
    response,
    status: 200,
    correlationId,
    payload: {status: 'ok'}
  })
}
