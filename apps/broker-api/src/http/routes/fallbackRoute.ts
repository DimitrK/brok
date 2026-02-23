import {badRequest} from '../../errors'
import type {BrokerApiRouteLogicHandler} from './types'

export const handleFallbackRoute: BrokerApiRouteLogicHandler = ({method, pathname}) => {
  throw badRequest('route_not_found', `Unsupported route ${method} ${pathname}`)
}
