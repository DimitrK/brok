import {
  OpenApiIntegrationSecretMaterialWriteSchema,
  type OpenApiIntegrationSecretMaterialWrite
} from '@broker-interceptor/schemas'

export type AuditSafeCredentialSummary = Readonly<Record<string, string | boolean>>

type CredentialType = OpenApiIntegrationSecretMaterialWrite['type']

type CredentialSummaryAdapter<TType extends CredentialType> = (
  secretMaterial: Extract<OpenApiIntegrationSecretMaterialWrite, {type: TType}>
) => AuditSafeCredentialSummary

const credentialSummaryAdapters: {
  [TType in CredentialType]: CredentialSummaryAdapter<TType>
} = {
  api_key: () => ({
    credential_type: 'api_key'
  }),
  oauth_refresh_token: () => ({
    credential_type: 'oauth_refresh_token'
  }),
  aws_sigv4: secretMaterial => ({
    credential_type: 'aws_sigv4',
    credential_region: secretMaterial.region,
    temporary_session_present: secretMaterial.session_token !== undefined
  })
}

export const summarizeCredentialMaterial = (
  secretMaterial: OpenApiIntegrationSecretMaterialWrite
): AuditSafeCredentialSummary => {
  const parsedSecretMaterial = OpenApiIntegrationSecretMaterialWriteSchema.parse(secretMaterial)

  const adapter = credentialSummaryAdapters[parsedSecretMaterial.type] as CredentialSummaryAdapter<
    typeof parsedSecretMaterial.type
  >

  return adapter(parsedSecretMaterial)
}
