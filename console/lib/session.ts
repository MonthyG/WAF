import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { cookies } from 'next/headers';
export const cookieName = 'waf_session';
function key() {
  const value = Buffer.from(process.env.CONSOLE_SESSION_KEY ?? '', 'base64');
  if (value.length !== 32) throw new Error('CONSOLE_SESSION_KEY must encode 32 random bytes');
  return value;
}
export function seal(token: string) {
  const iv = randomBytes(12),
    cipher = createCipheriv('aes-256-gcm', key(), iv);
  cipher.setAAD(Buffer.from(cookieName));
  const data = Buffer.concat([
    cipher.update(JSON.stringify({ token, expires: Date.now() + 3600000 })),
    cipher.final(),
  ]);
  return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64url');
}
export async function token() {
  const value = (await cookies()).get(cookieName)?.value;
  if (!value) return null;
  try {
    const data = Buffer.from(value, 'base64url');
    const decipher = createDecipheriv('aes-256-gcm', key(), data.subarray(0, 12));
    decipher.setAAD(Buffer.from(cookieName));
    decipher.setAuthTag(data.subarray(12, 28));
    const session = JSON.parse(
      Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString(),
    );
    return typeof session.token === 'string' && session.expires > Date.now() ? session.token : null;
  } catch {
    return null;
  }
}
export function cookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.CONSOLE_SECURE_COOKIES !== 'false',
    sameSite: 'strict' as const,
    path: '/',
    maxAge: 3600,
  };
}
export function validOrigin(request: Request) {
  const expected = process.env.CONSOLE_ORIGIN;
  if (!expected) return false;
  return request.headers.get('origin') === new URL(expected).origin;
}
export function apiURL(path: string) {
  const base = process.env.WAF_API_URL;
  if (!base) throw new Error('WAF_API_URL is required');
  return new URL(base.replace(/\/$/, '') + '/v1/waf/' + path);
}
export async function readBody(request: Request, max = 262144) {
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > max) {
      await reader.cancel();
      throw new Error('Request too large');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}
