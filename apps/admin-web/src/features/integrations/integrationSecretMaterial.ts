import {
  OpenApiIntegrationSecretMaterialWriteSchema,
  type OpenApiIntegrationSecretMaterialWrite
} from '@broker-interceptor/schemas';

export type IntegrationSecretType = OpenApiIntegrationSecretMaterialWrite['type'];

export type IntegrationSecretDraft = {
  secretType: IntegrationSecretType;
  secretValue: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  region: string;
};

export const hasRequiredIntegrationSecretMaterial = (draft: IntegrationSecretDraft) => {
  if (draft.secretType === 'aws_sigv4') {
    return Boolean(draft.accessKeyId.trim() && draft.secretAccessKey.trim() && draft.region.trim());
  }

  return Boolean(draft.secretValue.trim());
};

export const buildIntegrationSecretMaterial = (
  draft: IntegrationSecretDraft
): OpenApiIntegrationSecretMaterialWrite => {
  if (draft.secretType === 'aws_sigv4') {
    return OpenApiIntegrationSecretMaterialWriteSchema.parse({
      type: 'aws_sigv4',
      access_key_id: draft.accessKeyId.trim(),
      secret_access_key: draft.secretAccessKey.trim(),
      ...(draft.sessionToken.trim() ? {session_token: draft.sessionToken.trim()} : {}),
      region: draft.region.trim()
    });
  }

  return OpenApiIntegrationSecretMaterialWriteSchema.parse({
    type: draft.secretType,
    value: draft.secretValue.trim()
  });
};
