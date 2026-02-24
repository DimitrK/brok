import type {Server} from 'node:http';

import 'reflect-metadata';
import helmet from 'helmet';
import express from 'express';
import {NestFactory} from '@nestjs/core';
import {ExpressAdapter} from '@nestjs/platform-express';
import {createVaultExternalCaProvider, type ExternalCaEnrollmentProvider} from '@broker-interceptor/auth';
import {createStructuredLogger} from '@broker-interceptor/logging';

import {AdminAuthenticator} from './auth';
import {CertificateIssuer} from './certificateIssuer';
import type {CertificateIssuerConfig, ServiceConfig} from './config';
import {DependencyBridge} from './dependencyBridge';
import {createProcessInfrastructure} from './infrastructure';
import {AdminApiNestModule} from './nest/adminApiNestModule';
import {expressDecodeErrorMiddleware} from './nest/expressDecodeErrorMiddleware';
import {pathEncodingGuardMiddleware} from './nest/pathEncodingGuardMiddleware';
import {ControlPlaneRepository} from './repository';

const createExternalCaEnrollmentProvider = (
  issuerConfig: CertificateIssuerConfig
): ExternalCaEnrollmentProvider | undefined => {
  if (issuerConfig.mode !== 'vault') {
    return undefined;
  }

  return createVaultExternalCaProvider({
    vaultAddr: issuerConfig.vaultAddr,
    vaultToken: issuerConfig.vaultToken,
    pkiMount: issuerConfig.vaultPkiMount,
    requestTimeoutMs: issuerConfig.vaultRequestTimeoutMs
  });
};

export const createAdminApiApp = async ({config}: {config: ServiceConfig}) => {
  const infrastructure = await createProcessInfrastructure({config});

  try {
    const logger = createStructuredLogger({
      service: 'broker-admin-api',
      env: config.nodeEnv,
      level: config.logging.level,
      extraSensitiveKeys: config.logging.redactExtraKeys
    });
    const repository = await ControlPlaneRepository.create({
      statePath: config.statePath,
      manifestKeys: config.manifestKeys,
      enrollmentTokenTtlSeconds: config.enrollmentTokenTtlSeconds,
      processInfrastructure: infrastructure,
      logger
    });

    const authenticator = new AdminAuthenticator(config.auth);
    const certificateIssuer = new CertificateIssuer(config.certificateIssuer);
    const externalCaEnrollmentProvider = createExternalCaEnrollmentProvider(config.certificateIssuer);

    const dependencyBridge = new DependencyBridge({
      repository,
      authenticator,
      certificateIssuer,
      externalCaEnrollmentProvider,
      processInfrastructure: infrastructure,
      manifestKeyEncryption: {
        key: config.secretKey,
        keyId: config.secretKeyId
      }
    });
    await dependencyBridge.persistStateWithDbPackage();

    const expressApp = express();
    expressApp.disable('x-powered-by');
    expressApp.use(
      helmet({
        contentSecurityPolicy: false
      })
    );
    expressApp.use(pathEncodingGuardMiddleware);

    const nestApp = await NestFactory.create(
      AdminApiNestModule.register({
        config,
        repository,
        dependencyBridge,
        logger
      }),
      new ExpressAdapter(expressApp),
      {
        bodyParser: false,
        logger: config.nodeEnv === 'test' ? false : ['error', 'warn', 'log']
      }
    );

    if ((config.corsAllowedOrigins ?? []).length > 0) {
      nestApp.enableCors({
        origin: config.corsAllowedOrigins
      });
    }

    await nestApp.init();
    expressApp.use(expressDecodeErrorMiddleware);

    const server = nestApp.getHttpServer() as Server;

    const start = async () => {
      await nestApp.listen(config.port, config.host);
    };

    const stop = async () => {
      await nestApp.close();
      await infrastructure.close();
    };

    return {
      server,
      start,
      stop,
      repository,
      dependencyBridge,
      infrastructure
    };
  } catch (error) {
    await infrastructure.close();
    throw error;
  }
};

export type AdminApiApp = Awaited<ReturnType<typeof createAdminApiApp>>;
