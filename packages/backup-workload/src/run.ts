import {initializeRuntimeEnvironment} from './runtime-env.js';
import {loadConfig} from './config.js';
import {initializeInterceptor} from '@broker-interceptor/interceptor-node';

initializeRuntimeEnvironment();

const config = loadConfig();
const s3Endpoint = new URL(config.s3Endpoint);
const endpointScheme = s3Endpoint.protocol.slice(0, -1);
const endpointPort = s3Endpoint.port
  ? Number.parseInt(s3Endpoint.port, 10)
  : endpointScheme === 'https'
    ? 443
    : endpointScheme === 'http'
      ? 80
      : 0;
const basePath = s3Endpoint.pathname === '/' ? '' : s3Endpoint.pathname.replace(/\/+$/u, '');
const objectPathGroup = `${basePath}/${config.s3Prefix}/*`;

const initializationConfig = {
  brokerUrl: config.broker.brokerUrl,
  workloadId: config.broker.workloadId,
  ...(config.broker.sessionToken ? {sessionToken: config.broker.sessionToken} : {}),
  ...(config.broker.mtlsCertPath ? {mtlsCertPath: config.broker.mtlsCertPath} : {}),
  ...(config.broker.mtlsKeyPath ? {mtlsKeyPath: config.broker.mtlsKeyPath} : {}),
  ...(config.broker.mtlsCaPath ? {mtlsCaPath: config.broker.mtlsCaPath} : {}),
  ...(config.broker.sessionTtlSeconds ? {sessionTtlSeconds: config.broker.sessionTtlSeconds} : {}),
  integrationOverrides: [
    {
      integrationId: config.broker.s3IntegrationId,
      match: {
        hosts: [s3Endpoint.hostname],
        schemes: [endpointScheme === 'http' ? 'http' : 'https'],
        ports: [endpointPort],
        path_groups: [basePath || '/', objectPathGroup]
      }
    }
  ]
} as Parameters<typeof initializeInterceptor>[0];

const initialization = await initializeInterceptor(initializationConfig);

if (!initialization.ok) {
  throw new Error(initialization.error);
}

await import('./index.js');
