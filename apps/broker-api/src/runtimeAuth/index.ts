import {
  type OpenApiExecuteRequest,
  type OpenApiHeaderList,
  type OpenApiTemplate,
  type SecretMaterial,
  TemplatePathGroupConstraintsSchema,
  type UpstreamAuthStrategy,
  type UpstreamAuthType
} from '@broker-interceptor/schemas';

import {RuntimeAuthError} from './errors';
import type {RuntimeAuthStrategyModule} from './strategyModule';
import {awsSigV4RuntimeAuthStrategy} from './strategies/awsSigV4Strategy';
import {resolvePathGroup} from './utils';

const runtimeAuthStrategyRegistry = {
  aws_sigv4: awsSigV4RuntimeAuthStrategy
} satisfies Record<UpstreamAuthType, RuntimeAuthStrategyModule>;

export const resolveRuntimeAuthStrategy = ({
  template,
  matchedPathGroupId
}: {
  template: OpenApiTemplate;
  matchedPathGroupId: string;
}): UpstreamAuthStrategy | null => {
  const pathGroup = resolvePathGroup({template, matchedPathGroupId});
  if (!pathGroup) {
    throw new RuntimeAuthError({
      code: 'runtime_auth_path_group_missing',
      message: `Matched path group ${matchedPathGroupId} was not found on the template`
    });
  }

  if (!pathGroup.constraints) {
    return null;
  }

  const parsedConstraints = TemplatePathGroupConstraintsSchema.safeParse(pathGroup.constraints);
  if (!parsedConstraints.success) {
    throw new RuntimeAuthError({
      code: 'runtime_auth_constraint_invalid',
      message: `Runtime auth constraints are invalid for path group ${matchedPathGroupId}`
    });
  }

  return parsedConstraints.data.upstream_auth ?? null;
};

const buildBearerHeaders = ({secretMaterial}: {secretMaterial: SecretMaterial}): OpenApiHeaderList => {
  if (secretMaterial.type === 'api_key' || secretMaterial.type === 'oauth_refresh_token') {
    return [{name: 'Authorization', value: `Bearer ${secretMaterial.value}`}];
  }

  throw new RuntimeAuthError({
    code: 'runtime_auth_secret_type_incompatible',
    message: `Secret type ${secretMaterial.type} requires an explicit runtime auth strategy`
  });
};

export const buildExecuteAuthHeaders = ({
  secretMaterial,
  request,
  template,
  matchedPathGroupId,
  now = new Date(),
  strategy = resolveRuntimeAuthStrategy({template, matchedPathGroupId})
}: {
  secretMaterial: SecretMaterial;
  request: OpenApiExecuteRequest['request'];
  template: OpenApiTemplate;
  matchedPathGroupId: string;
  now?: Date;
  strategy?: UpstreamAuthStrategy | null;
}): OpenApiHeaderList => {
  if (!strategy) {
    return buildBearerHeaders({secretMaterial});
  }

  const runtimeAuthHandler = runtimeAuthStrategyRegistry[strategy.type];
  // Keep the runtime guard even though the registry is compile-time exhaustive:
  // persisted/schema data can drift from the current TypeScript view and must still fail closed.
  if (!runtimeAuthHandler) {
    throw new RuntimeAuthError({
      code: 'runtime_auth_strategy_unsupported',
      message: `Runtime auth strategy ${strategy.type} is not supported by broker-api`
    });
  }

  if (!runtimeAuthHandler.supportsSecret(secretMaterial)) {
    throw new RuntimeAuthError({
      code: 'runtime_auth_secret_type_incompatible',
      message: `Secret type ${secretMaterial.type} is incompatible with runtime auth strategy ${strategy.type}`
    });
  }

  try {
    return runtimeAuthHandler.buildHeaders({
      strategy,
      secretMaterial,
      request,
      template,
      matchedPathGroupId,
      now
    });
  } catch (error) {
    if (error instanceof RuntimeAuthError) {
      throw error;
    }

    const message = error instanceof Error ? error.message : 'Required runtime auth inputs are unavailable';
    throw new RuntimeAuthError({
      code: 'runtime_auth_inputs_unavailable',
      message
    });
  }
};
