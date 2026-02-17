const textEncoder = new TextEncoder();

const base64UrlEncode = (value: Uint8Array) =>
  btoa(String.fromCharCode(...value))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const requireCrypto = () => {
  if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
    throw new Error('Secure browser crypto APIs are required for OAuth PKCE.');
  }

  return window.crypto;
};

export const createPkcePair = async () => {
  const cryptoApi = requireCrypto();
  const random = new Uint8Array(32);
  cryptoApi.getRandomValues(random);

  const codeVerifier = base64UrlEncode(random);
  const challengeBuffer = await cryptoApi.subtle.digest('SHA-256', textEncoder.encode(codeVerifier));
  const codeChallenge = base64UrlEncode(new Uint8Array(challengeBuffer));

  return {
    codeVerifier,
    codeChallenge
  };
};
