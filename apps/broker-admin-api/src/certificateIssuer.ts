import {createHash, createPrivateKey, createPublicKey, randomBytes, timingSafeEqual, webcrypto} from 'node:crypto';
import {promises as fs} from 'node:fs';

import {signCsrWithVault, type VaultPkiClient} from '@broker-interceptor/auth';
import * as x509 from '@peculiar/x509';

import type {CertificateIssuerConfig, LocalCertificateIssuerConfig} from './config';
import {isAppError, serviceUnavailable} from './errors';

export type IssueCertificateInput = {
  csrPem: string;
  workloadId: string;
  sanUri: string;
  ttlSeconds: number;
};

export type IssueCertificateResult = {
  clientCertPem: string;
  caChainPem: string;
  expiresAt: string;
};

type VaultSignResponse = {
  data?: {
    certificate?: unknown;
    ca_chain?: unknown;
  };
};

type LocalSigningMaterial = {
  caCert: x509.X509Certificate;
  signingKey: CryptoKey;
  signingAlgorithm: {
    name: string;
    hash?: 'SHA-256' | 'SHA-384' | 'SHA-512';
  };
};

const addSeconds = (base: Date, seconds: number) => new Date(base.getTime() + seconds * 1000);

const renderMockPem = ({label, payload}: {label: string; payload: string}) => {
  const base64 = Buffer.from(payload, 'utf8').toString('base64');
  const wrapped = base64.match(/.{1,64}/gu)?.join('\n') ?? base64;
  return [`-----BEGIN ${label}-----`, wrapped, `-----END ${label}-----`].join('\n');
};

const normalizeVaultAddr = (value: string) => value.replace(/\/+$/u, '');

const renderDerPem = ({label, der}: {label: string; der: Buffer}) => {
  const base64 = der.toString('base64');
  const wrapped = base64.match(/.{1,64}/gu)?.join('\n') ?? base64;
  return [`-----BEGIN ${label}-----`, wrapped, `-----END ${label}-----`].join('\n');
};

const parseVaultResponse = (responseBody: unknown): {certificatePem: string; caChainPem: string[]} => {
  if (typeof responseBody !== 'object' || responseBody === null) {
    throw serviceUnavailable('vault_response_invalid', 'Vault response is not a JSON object');
  }

  const parsed = responseBody as VaultSignResponse;
  const certificate = parsed.data?.certificate;
  const caChain = parsed.data?.ca_chain;

  if (typeof certificate !== 'string' || certificate.trim().length === 0) {
    throw serviceUnavailable('vault_response_invalid', 'Vault signing response does not contain a valid certificate');
  }

  if (!Array.isArray(caChain) || caChain.length === 0 || caChain.some(entry => typeof entry !== 'string')) {
    throw serviceUnavailable(
      'vault_response_invalid',
      'Vault signing response does not contain a valid certificate chain'
    );
  }

  return {
    certificatePem: certificate,
    caChainPem: caChain as string[]
  };
};

const localSigningMaterialCache = new Map<string, Promise<LocalSigningMaterial>>();

const getCurveHashAlgorithm = (namedCurve: string): 'SHA-256' | 'SHA-384' | 'SHA-512' => {
  switch (namedCurve) {
    case 'P-256':
      return 'SHA-256';
    case 'P-384':
      return 'SHA-384';
    case 'P-521':
      return 'SHA-512';
    default:
      throw serviceUnavailable('local_ca_invalid', `Unsupported EC named curve for local signing: ${namedCurve}`);
  }
};

const resolveLocalSigningAlgorithms = (keyObject: ReturnType<typeof createPrivateKey>) => {
  const keyType = keyObject.asymmetricKeyType;
  if (keyType === 'rsa') {
    return {
      importAlgorithm: {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
      } as const,
      signingAlgorithm: {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
      } as const
    };
  }

  if (keyType === 'ec') {
    const namedCurve = keyObject.asymmetricKeyDetails?.namedCurve;
    if (!namedCurve) {
      throw serviceUnavailable('local_ca_invalid', 'EC private key is missing named curve metadata');
    }

    return {
      importAlgorithm: {
        name: 'ECDSA',
        namedCurve
      } as const,
      signingAlgorithm: {
        name: 'ECDSA',
        hash: getCurveHashAlgorithm(namedCurve)
      } as const
    };
  }

  if (keyType === 'ed25519') {
    return {
      importAlgorithm: {
        name: 'Ed25519'
      } as const,
      signingAlgorithm: {
        name: 'EdDSA'
      } as const
    };
  }

  throw serviceUnavailable('local_ca_invalid', `Unsupported local CA key algorithm: ${keyType}`);
};

const getLocalSigningMaterial = async (config: LocalCertificateIssuerConfig): Promise<LocalSigningMaterial> => {
  const cacheKey = `${config.caCertPath}\u0000${config.caKeyPath}`;
  const cached = localSigningMaterialCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const loadingPromise = (async () => {
    let caCertPem: string;
    let caKeyPem: string;
    try {
      [caCertPem, caKeyPem] = await Promise.all([
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        fs.readFile(config.caCertPath, 'utf8'),
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        fs.readFile(config.caKeyPath, 'utf8')
      ]);
    } catch (error) {
      throw serviceUnavailable(
        'local_ca_unavailable',
        `Failed to load CA files: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    let caCert: x509.X509Certificate;
    let signingKey: CryptoKey;
    let signingAlgorithm: LocalSigningMaterial['signingAlgorithm'];

    try {
      caCert = new x509.X509Certificate(caCertPem);

      const keyObject = createPrivateKey(caKeyPem);
      const publicKeyDer = createPublicKey(keyObject).export({
        format: 'der',
        type: 'spki'
      });
      const certPublicKeyDer = Buffer.from(caCert.publicKey.rawData);
      if (
        !Buffer.isBuffer(publicKeyDer) ||
        publicKeyDer.length !== certPublicKeyDer.length ||
        !timingSafeEqual(publicKeyDer, certPublicKeyDer)
      ) {
        throw serviceUnavailable('local_ca_invalid', 'Local CA certificate and private key do not match');
      }

      const algorithms = resolveLocalSigningAlgorithms(keyObject);
      const keyDer = keyObject.export({format: 'der', type: 'pkcs8'});
      if (!Buffer.isBuffer(keyDer)) {
        throw serviceUnavailable('local_ca_invalid', 'Local CA private key export failed');
      }
      signingKey = await webcrypto.subtle.importKey(
        'pkcs8',
        keyDer,
        algorithms.importAlgorithm,
        false,
        ['sign']
      );
      signingAlgorithm = algorithms.signingAlgorithm;
    } catch (error) {
      if (isAppError(error)) {
        throw error;
      }
      throw serviceUnavailable(
        'local_ca_invalid',
        `Failed to parse CA certificate or key: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    return {
      caCert,
      signingKey,
      signingAlgorithm
    };
  })();

  localSigningMaterialCache.set(cacheKey, loadingPromise);
  try {
    return await loadingPromise;
  } catch (error) {
    localSigningMaterialCache.delete(cacheKey);
    throw error;
  }
};

const issueMockCertificate = ({
  input,
  mtlsCaPem
}: {
  input: IssueCertificateInput;
  mtlsCaPem: string;
}): IssueCertificateResult => {
  const issuedAt = new Date();
  const expiresAt = addSeconds(issuedAt, input.ttlSeconds).toISOString();
  const digest = createHash('sha256').update(input.csrPem, 'utf8').digest('base64url');
  const mockPayload = JSON.stringify(
    {
      workload_id: input.workloadId,
      san_uri: input.sanUri,
      csr_sha256_b64url: digest,
      issued_at: issuedAt.toISOString(),
      expires_at: expiresAt
    },
    null,
    2
  );

  return {
    clientCertPem: renderMockPem({label: 'CERTIFICATE', payload: mockPayload}),
    caChainPem: mtlsCaPem,
    expiresAt
  };
};

const issueLocalCertificate = async ({
  input,
  config
}: {
  input: IssueCertificateInput;
  config: LocalCertificateIssuerConfig;
}): Promise<IssueCertificateResult> => {
  const signingMaterial = await getLocalSigningMaterial(config);

  // Parse CSR
  let csr: x509.Pkcs10CertificateRequest;
  try {
    csr = new x509.Pkcs10CertificateRequest(input.csrPem);
  } catch (error) {
    throw serviceUnavailable(
      'csr_parse_failed',
      `Failed to parse CSR: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const issuedAt = new Date();
  const expiresAt = addSeconds(issuedAt, input.ttlSeconds);
  const serialNumber = randomBytes(16).toString('hex');

  // Build certificate extensions
  const extensions: x509.Extension[] = [
    // Basic Constraints: CA:FALSE
    new x509.BasicConstraintsExtension(false, undefined, true),
    // Key Usage: Digital Signature, Key Encipherment
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment, true),
    // Extended Key Usage: TLS Web Client Authentication
    new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.2'], true),
    // Subject Alternative Name
    new x509.SubjectAlternativeNameExtension([{type: 'url', value: input.sanUri}], false)
  ];

  // Create and sign certificate
  let certificate: x509.X509Certificate;
  try {
    certificate = await x509.X509CertificateGenerator.create({
      serialNumber,
      subject: csr.subject,
      issuer: signingMaterial.caCert.subject,
      notBefore: issuedAt,
      notAfter: expiresAt,
      signingAlgorithm: signingMaterial.signingAlgorithm,
      publicKey: csr.publicKey,
      signingKey: signingMaterial.signingKey,
      extensions
    });
  } catch (error) {
    throw serviceUnavailable(
      'cert_sign_failed',
      `Failed to sign certificate: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  return {
    clientCertPem: renderDerPem({
      label: 'CERTIFICATE',
      der: Buffer.from(certificate.rawData)
    }),
    caChainPem: config.mtlsCaPem,
    expiresAt: expiresAt.toISOString()
  };
};

const createVaultClient = ({
  config,
  ttlSeconds
}: {
  config: Extract<CertificateIssuerConfig, {mode: 'vault'}>;
  ttlSeconds: number;
}): VaultPkiClient => ({
  signCsr: async ({roleName, csrPem}) => {
    const endpoint = `${normalizeVaultAddr(config.vaultAddr)}/v1/${config.vaultPkiMount}/sign/${roleName}`;
    let response: Response;
    try {
      response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-vault-token': config.vaultToken
        },
        body: JSON.stringify({
          csr: csrPem,
          ttl: `${ttlSeconds}s`
        }),
        redirect: 'error',
        signal: AbortSignal.timeout(config.vaultRequestTimeoutMs)
      });
    } catch (error) {
      if (error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError')) {
        throw serviceUnavailable(
          'vault_unreachable',
          `Vault signing request timed out after ${config.vaultRequestTimeoutMs}ms`
        );
      }

      throw serviceUnavailable('vault_unreachable', 'Vault signing request could not be completed');
    }

    if (!response.ok) {
      throw serviceUnavailable('vault_sign_failed', `Vault signing request failed with status ${response.status}`);
    }

    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.toLowerCase().includes('application/json')) {
      throw serviceUnavailable('vault_response_invalid', 'Vault signing response content-type must be JSON');
    }

    let parsedResponse: unknown;
    try {
      parsedResponse = await response.json();
    } catch {
      throw serviceUnavailable('vault_response_invalid', 'Vault signing response is not valid JSON');
    }
    const certificateMaterial = parseVaultResponse(parsedResponse);

    return {
      certificatePem: certificateMaterial.certificatePem,
      caChainPem: certificateMaterial.caChainPem
    };
  },
  readRole: () => Promise.resolve(null),
  writeRole: () => Promise.resolve()
});

const issueVaultCertificate = async ({
  input,
  config
}: {
  input: IssueCertificateInput;
  config: Extract<CertificateIssuerConfig, {mode: 'vault'}>;
}): Promise<IssueCertificateResult> => {
  const signedCertificate = await signCsrWithVault({
    client: createVaultClient({
      config,
      ttlSeconds: input.ttlSeconds
    }),
    roleName: config.vaultPkiRole,
    csrPem: input.csrPem
  });

  return {
    clientCertPem: signedCertificate.certificatePem,
    caChainPem: signedCertificate.caChainPem.join('\n'),
    expiresAt: addSeconds(new Date(), input.ttlSeconds).toISOString()
  };
};

export class CertificateIssuer {
  public constructor(private readonly config: CertificateIssuerConfig) {}

  public get mtlsCaPem() {
    return this.config.mtlsCaPem;
  }

  public async issue(input: IssueCertificateInput): Promise<IssueCertificateResult> {
    if (this.config.mode === 'mock') {
      return issueMockCertificate({input, mtlsCaPem: this.config.mtlsCaPem});
    }

    if (this.config.mode === 'local') {
      return issueLocalCertificate({input, config: this.config});
    }

    return issueVaultCertificate({input, config: this.config});
  }
}
