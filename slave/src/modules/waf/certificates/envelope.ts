import {
  constants,
  createCipheriv,
  createPublicKey,
  publicEncrypt,
  randomBytes,
} from 'node:crypto';

// Each delivery is bound to its site and revision, and only its recipient can unwrap it.
export function sealForNode(pem: string, publicKeyPem: string, siteId: string, revision: number) {
  const publicKey = createPublicKey(publicKeyPem);
  if (
    publicKey.asymmetricKeyType !== 'rsa' ||
    (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
  )
    throw new Error('Node encryption key must be RSA with at least 2048 bits');
  const key = randomBytes(32),
    iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(`${siteId}:${revision}`));
  const ciphertext = Buffer.concat([cipher.update(pem, 'utf8'), cipher.final()]);
  return {
    algorithm: 'RSA-OAEP-256+A256GCM',
    wrapped_key: publicEncrypt(
      { key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      key,
    ).toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}
