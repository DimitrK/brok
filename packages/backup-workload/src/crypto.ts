import {createCipheriv, createDecipheriv, createHash, randomBytes} from 'node:crypto';

const AES_GCM_IV_BYTES = 12;

export type EncryptedPayload = {
  ivB64: string;
  authTagB64: string;
  ciphertext: Buffer;
  sha256: string;
};

export const encryptPayload = ({plaintext, key}: {plaintext: Buffer; key: Buffer}): EncryptedPayload => {
  const iv = randomBytes(AES_GCM_IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    ivB64: iv.toString('base64'),
    authTagB64: authTag.toString('base64'),
    ciphertext,
    sha256: createHash('sha256').update(ciphertext).digest('hex')
  };
};

export const decryptPayload = ({
  ciphertext,
  key,
  ivB64,
  authTagB64
}: {
  ciphertext: Buffer;
  key: Buffer;
  ivB64: string;
  authTagB64: string;
}) => {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(authTagB64, 'base64'));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
};
