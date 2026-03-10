import type {
  OpenApiExecuteRequest,
  OpenApiHeaderList,
  OpenApiTemplate,
  SecretMaterial,
  UpstreamAuthStrategy,
  UpstreamAuthType
} from '@broker-interceptor/schemas';

import {RuntimeAuthError} from './errors';

export type RuntimeAuthBuildHeadersInput<
  TStrategy extends UpstreamAuthStrategy = UpstreamAuthStrategy,
  TSecretMaterial extends SecretMaterial = SecretMaterial
> = {
  strategy: TStrategy;
  secretMaterial: TSecretMaterial;
  request: OpenApiExecuteRequest['request'];
  template: OpenApiTemplate;
  matchedPathGroupId: string;
  now?: Date;
};

type RuntimeAuthStrategyImplementation<
  TStrategy extends UpstreamAuthStrategy = UpstreamAuthStrategy,
  TSecretMaterial extends SecretMaterial = SecretMaterial
> = {
  readonly type: TStrategy['type'];
  supportsSecret: (secretMaterial: SecretMaterial) => secretMaterial is TSecretMaterial;
  buildHeaders: (input: RuntimeAuthBuildHeadersInput<TStrategy, TSecretMaterial>) => OpenApiHeaderList;
};

export type RuntimeAuthStrategyModule = {
  readonly type: UpstreamAuthType;
  supportsSecret: (secretMaterial: SecretMaterial) => boolean;
  buildHeaders: (input: RuntimeAuthBuildHeadersInput) => OpenApiHeaderList;
};

export const defineRuntimeAuthStrategy = <
  TStrategy extends UpstreamAuthStrategy,
  TSecretMaterial extends SecretMaterial
>(
  implementation: RuntimeAuthStrategyImplementation<TStrategy, TSecretMaterial>
): RuntimeAuthStrategyModule => ({
  type: implementation.type,
  supportsSecret: secretMaterial => implementation.supportsSecret(secretMaterial),
  buildHeaders: input => {
    if (input.strategy.type !== implementation.type || !implementation.supportsSecret(input.secretMaterial)) {
      throw new RuntimeAuthError({
        code: 'runtime_auth_secret_type_incompatible',
        message: `Runtime auth strategy ${implementation.type} is incompatible with secret type ${input.secretMaterial.type}`
      });
    }

    return implementation.buildHeaders({
      ...input,
      strategy: input.strategy as TStrategy,
      secretMaterial: input.secretMaterial
    });
  }
});
