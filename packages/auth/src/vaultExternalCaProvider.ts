import type {
  ExternalCaEnrollmentProvider,
  ExternalCaIssueEnrollmentInput,
  IssueExternalCaEnrollmentResult
} from './types';

const DEFAULT_REQUEST_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 64 * 1024;

export type VaultExternalCaProviderConfig = {
  /**
   * Vault server address (e.g., https://vault.example.com:8200).
   * Must use HTTPS in production.
   */
  vaultAddr: string;

  /**
   * Vault authentication token with read access to the PKI mount CA chain.
   */
  vaultToken: string;

  /**
   * PKI secrets engine mount path (default: "pki").
   */
  pkiMount?: string;

  /**
   * Request timeout in milliseconds (default: 5000).
   */
  requestTimeoutMs?: number;
};

const normalizeVaultAddr = (addr: string): string => {
  const trimmed = addr.trim();
  return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
};

const fetchVaultCaChain = async ({
  vaultAddr,
  vaultToken,
  pkiMount,
  timeoutMs,
  signal
}: {
  vaultAddr: string;
  vaultToken: string;
  pkiMount: string;
  timeoutMs: number;
  signal?: AbortSignal;
}): Promise<IssueExternalCaEnrollmentResult> => {
  const normalizedAddr = normalizeVaultAddr(vaultAddr);
  const caChainUrl = `${normalizedAddr}/v1/${pkiMount}/ca_chain`;

  const abortController = new AbortController();
  const onExternalAbort = () => abortController.abort(signal?.reason);

  if (signal) {
    if (signal.aborted) {
      return {
        ok: false,
        error: {
          code: 'external_ca_unreachable',
          message: 'Request aborted before execution'
        }
      };
    }
    signal.addEventListener('abort', onExternalAbort, {once: true});
  }

  const timeout = setTimeout(() => {
    abortController.abort(new Error('vault_request_timeout'));
  }, timeoutMs);

  try {
    const response = await fetch(caChainUrl, {
      method: 'GET',
      headers: {
        'X-Vault-Token': vaultToken,
        Accept: 'application/x-pem-file'
      },
      signal: abortController.signal,
      redirect: 'error'
    });

    if (!response.ok) {
      if (response.status === 403 || response.status === 401) {
        return {
          ok: false,
          error: {
            code: 'external_ca_enrollment_denied',
            message: `Vault returned ${response.status}: access denied to CA chain`
          }
        };
      }

      if (response.status === 404) {
        return {
          ok: false,
          error: {
            code: 'external_ca_profile_invalid',
            message: `Vault PKI mount "${pkiMount}" not found or CA not configured`
          }
        };
      }

      return {
        ok: false,
        error: {
          code: 'external_ca_unreachable',
          message: `Vault returned unexpected status ${response.status}`
        }
      };
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_BYTES) {
      return {
        ok: false,
        error: {
          code: 'external_ca_profile_invalid',
          message: 'CA chain response exceeds maximum allowed size'
        }
      };
    }

    const caChainPem = await response.text();

    if (!caChainPem || caChainPem.trim().length === 0) {
      return {
        ok: false,
        error: {
          code: 'external_ca_profile_invalid',
          message: 'Vault returned empty CA chain'
        }
      };
    }

    if (Buffer.byteLength(caChainPem, 'utf8') > MAX_RESPONSE_BYTES) {
      return {
        ok: false,
        error: {
          code: 'external_ca_profile_invalid',
          message: 'CA chain exceeds maximum allowed size'
        }
      };
    }

    const hasCertBlock = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/u.test(caChainPem);
    if (!hasCertBlock) {
      return {
        ok: false,
        error: {
          code: 'external_ca_profile_invalid',
          message: 'Vault CA chain does not contain valid certificate PEM blocks'
        }
      };
    }

    const hasPrivateKey = /-----BEGIN [^-]*PRIVATE KEY-----/iu.test(caChainPem);
    if (hasPrivateKey) {
      return {
        ok: false,
        error: {
          code: 'external_ca_profile_invalid',
          message: 'Vault CA chain contains private key material (rejected)'
        }
      };
    }

    return {
      ok: true,
      value: {
        mtlsCaPem: caChainPem.trim()
      }
    };
  } catch (error: unknown) {
    if (error instanceof Error) {
      if (error.name === 'AbortError' || error.message === 'vault_request_timeout') {
        return {
          ok: false,
          error: {
            code: 'external_ca_unreachable',
            message: 'Vault request timed out or was aborted'
          }
        };
      }

      if (error.message.includes('redirect')) {
        return {
          ok: false,
          error: {
            code: 'external_ca_unreachable',
            message: 'Vault attempted redirect (denied for security)'
          }
        };
      }
    }

    return {
      ok: false,
      error: {
        code: 'external_ca_unreachable',
        message: 'Failed to connect to Vault'
      }
    };
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', onExternalAbort);
  }
};

/**
 * Creates a Vault-backed ExternalCaEnrollmentProvider.
 *
 * This provider fetches the CA certificate chain from a Vault PKI secrets engine
 * and returns it as the mTLS CA PEM that workloads will trust.
 *
 * @example
 * ```typescript
 * const provider = createVaultExternalCaProvider({
 *   vaultAddr: 'https://vault.example.com:8200',
 *   vaultToken: 's.xxxxxxxxxxxxxx',
 *   pkiMount: 'pki',
 *   requestTimeoutMs: 5000
 * });
 *
 * const result = await provider.issueEnrollment({
 *   tenantId: 'tenant-123',
 *   workloadName: 'my-workload'
 * });
 * ```
 */
export const createVaultExternalCaProvider = (
  config: VaultExternalCaProviderConfig
): ExternalCaEnrollmentProvider => {
  const {vaultAddr, vaultToken, pkiMount = 'pki', requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS} = config;

  if (!vaultAddr || vaultAddr.trim().length === 0) {
    throw new Error('vaultAddr is required for VaultExternalCaProvider');
  }

  if (!vaultToken || vaultToken.trim().length === 0) {
    throw new Error('vaultToken is required for VaultExternalCaProvider');
  }

  return {
    issueEnrollment: async (
      input: ExternalCaIssueEnrollmentInput
    ): Promise<IssueExternalCaEnrollmentResult> => {
      // The tenantId and workloadName are logged for audit purposes but
      // not used in the Vault CA chain fetch (the CA chain is shared).
      // Future: per-tenant or per-workload PKI mounts could use these fields.
      void input.tenantId;
      void input.workloadName;

      return fetchVaultCaChain({
        vaultAddr,
        vaultToken,
        pkiMount,
        timeoutMs: requestTimeoutMs,
        signal: input.signal
      });
    }
  };
};
