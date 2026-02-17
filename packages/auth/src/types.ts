import type {ParsedCsrContract, WorkloadRecordContract} from './contracts';

export type WorkloadPrincipal = {
  sanUri: string | null;
  sanUriCount: number;
  certFingerprint256: string | null;
  extKeyUsageOids: string[];
  authorized: boolean;
  authorizationError?: string;
};

export type AuthContext = {
  tenantId: string;
  workloadId: string;
  sessionId: string;
  dpopKeyThumbprint?: string;
  scopes?: string[];
  flags?: string[];
};

export type MtlsContext = {
  tenantId: string;
  workloadId: string;
  certFingerprint256: string;
  sanUri: string;
};

export type WorkloadRecord = WorkloadRecordContract;

export type SessionRecord = {
  sessionId: string;
  workloadId: string;
  tenantId: string;
  certFingerprint256: string;
  tokenHash: string;
  expiresAt: string;
  dpopKeyThumbprint?: string;
};

export type SessionIssueResult = {
  token: string;
  session: SessionRecord;
};

export type EnrollmentTokenRecord = {
  tokenHash: string;
  workloadId: string;
  expiresAt: string;
};

export type JtiStore = {
  checkAndStore: (jti: string, expiresAt: Date) => Promise<boolean> | boolean;
};

export type VaultRoleSpec = {
  allowed_uri_sans: string;
  allow_any_name: boolean;
  allow_ip_sans: boolean;
  ttl?: string;
  max_ttl?: string;
};

export type VaultPkiClient = {
  signCsr: (input: {roleName: string; csrPem: string}) => Promise<{
    certificatePem: string;
    caChainPem: string[];
  }>;
  readRole: (roleName: string) => Promise<VaultRoleSpec | null>;
  writeRole: (input: {roleName: string; role: VaultRoleSpec}) => Promise<void>;
  readPolicy?: (name: string) => Promise<string>;
};

export type ParsedCsr = ParsedCsrContract;

export type ExternalCaEnrollmentErrorCode =
  | 'external_ca_not_configured'
  | 'external_ca_unreachable'
  | 'external_ca_profile_invalid'
  | 'external_ca_enrollment_denied';

export type ExternalCaEnrollmentError = {
  code: ExternalCaEnrollmentErrorCode;
  message: string;
};

export type IssueExternalCaEnrollmentInput = {
  tenantId: string;
  workloadName: string;
};

export type IssueExternalCaEnrollmentOutput = {
  mtlsCaPem: string;
  enrollmentReference?: string;
};

export type IssueExternalCaEnrollmentResult =
  | {ok: true; value: IssueExternalCaEnrollmentOutput}
  | {ok: false; error: ExternalCaEnrollmentError};

export type ExternalCaIssueEnrollmentInput = IssueExternalCaEnrollmentInput & {
  signal?: AbortSignal;
};

export type ExternalCaEnrollmentProvider = {
  issueEnrollment:
    | ((
        input: ExternalCaIssueEnrollmentInput
      ) => Promise<IssueExternalCaEnrollmentOutput> | IssueExternalCaEnrollmentOutput)
    | ((
        input: ExternalCaIssueEnrollmentInput
      ) => Promise<IssueExternalCaEnrollmentResult> | IssueExternalCaEnrollmentResult);
};
