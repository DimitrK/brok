import {
  OpenApiIntegrationSecretMaterialWriteSchema,
  SecretMaterialTypeSchema,
  type OpenApiIntegrationSecretMaterialWrite,
  type SecretMaterialType
} from '@broker-interceptor/schemas';

export type IntegrationSecretType = SecretMaterialType;

export type IntegrationSecretFieldKey =
  | 'secretValue'
  | 'accessKeyId'
  | 'secretAccessKey'
  | 'sessionToken'
  | 'region';

export type IntegrationSecretDraft = {
  secretType: IntegrationSecretType;
  secretValue: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  region: string;
};

export type IntegrationSecretFieldDefinition = {
  key: IntegrationSecretFieldKey;
  label: string;
  placeholder: string;
  inputType?: 'password' | 'text';
  autoComplete?: string;
  optional?: boolean;
  width: 'default' | 'wide';
  rowId?: string;
};

type IntegrationSecretAdapter = {
  type: IntegrationSecretType;
  label: string;
  helpText?: string;
  fields: readonly IntegrationSecretFieldDefinition[];
  isComplete: (draft: IntegrationSecretDraft) => boolean;
  build: (draft: IntegrationSecretDraft) => OpenApiIntegrationSecretMaterialWrite;
};

const integrationSecretDraftTemplate: Omit<IntegrationSecretDraft, 'secretType'> = {
  secretValue: '',
  accessKeyId: '',
  secretAccessKey: '',
  sessionToken: '',
  region: ''
};

export const createEmptyIntegrationSecretDraft = (
  secretType: IntegrationSecretType = 'api_key'
): IntegrationSecretDraft => ({
  secretType,
  ...integrationSecretDraftTemplate
});

const integrationSecretAdapterRegistry: Record<IntegrationSecretType, IntegrationSecretAdapter> = {
  api_key: {
    type: 'api_key',
    label: 'API key',
    fields: [
      {
        key: 'secretValue',
        label: 'Secret value',
        placeholder: 'sk-...',
        inputType: 'password',
        autoComplete: 'new-password',
        width: 'wide'
      }
    ],
    isComplete: draft => Boolean(draft.secretValue.trim()),
    build: draft =>
      OpenApiIntegrationSecretMaterialWriteSchema.parse({
        type: 'api_key',
        value: draft.secretValue.trim()
      })
  },
  oauth_refresh_token: {
    type: 'oauth_refresh_token',
    label: 'OAuth refresh token',
    fields: [
      {
        key: 'secretValue',
        label: 'Refresh token',
        placeholder: 'refresh-token',
        inputType: 'password',
        autoComplete: 'new-password',
        width: 'wide'
      }
    ],
    isComplete: draft => Boolean(draft.secretValue.trim()),
    build: draft =>
      OpenApiIntegrationSecretMaterialWriteSchema.parse({
        type: 'oauth_refresh_token',
        value: draft.secretValue.trim()
      })
  },
  aws_sigv4: {
    type: 'aws_sigv4',
    label: 'AWS SigV4',
    helpText:
      'Region is required for SigV4 credentials. For non-AWS or custom S3-compatible hosts, use the explicit region expected by the upstream signer configuration.',
    fields: [
      {
        key: 'accessKeyId',
        label: 'Access key ID',
        placeholder: 'AKIA...',
        autoComplete: 'off',
        width: 'default',
        rowId: 'sigv4-credentials'
      },
      {
        key: 'region',
        label: 'Region',
        placeholder: 'eu-west-1',
        autoComplete: 'off',
        width: 'default',
        rowId: 'sigv4-credentials'
      },
      {
        key: 'secretAccessKey',
        label: 'Secret access key',
        placeholder: 'AWS secret access key',
        inputType: 'password',
        autoComplete: 'new-password',
        width: 'wide'
      },
      {
        key: 'sessionToken',
        label: 'Session token',
        placeholder: 'Temporary credentials session token',
        inputType: 'password',
        autoComplete: 'new-password',
        optional: true,
        width: 'wide'
      }
    ],
    isComplete: draft =>
      Boolean(draft.accessKeyId.trim() && draft.secretAccessKey.trim() && draft.region.trim()),
    build: draft =>
      OpenApiIntegrationSecretMaterialWriteSchema.parse({
        type: 'aws_sigv4',
        access_key_id: draft.accessKeyId.trim(),
        secret_access_key: draft.secretAccessKey.trim(),
        ...(draft.sessionToken.trim() ? {session_token: draft.sessionToken.trim()} : {}),
        region: draft.region.trim()
      })
  }
};

export const integrationSecretAdapters = Object.freeze(integrationSecretAdapterRegistry);

export const integrationSecretTypeOptions = SecretMaterialTypeSchema.options.map(secretType => ({
  value: secretType,
  label: integrationSecretAdapterRegistry[secretType].label
}));

export const getIntegrationSecretAdapter = (secretType: IntegrationSecretType) =>
  integrationSecretAdapterRegistry[secretType];

export const hasRequiredIntegrationSecretMaterial = (draft: IntegrationSecretDraft) =>
  getIntegrationSecretAdapter(draft.secretType).isComplete(draft);

export const buildIntegrationSecretMaterial = (
  draft: IntegrationSecretDraft
): OpenApiIntegrationSecretMaterialWrite => getIntegrationSecretAdapter(draft.secretType).build(draft);
