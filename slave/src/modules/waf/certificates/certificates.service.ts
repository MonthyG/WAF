import { createCipheriv, createDecipheriv, createPrivateKey, randomBytes, X509Certificate } from 'node:crypto';
import { HttpError } from '../errors.js';

export function validateCertificate(pem:string,keyPem:string,domains:string[]) {
  try {
    const blocks=pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
    if(!blocks?.length)throw new Error();
    const chain=blocks.map(b=>new X509Certificate(b));
    const leaf=chain[0];
    if(!leaf.checkPrivateKey(createPrivateKey(keyPem)))throw new Error();
    const now=Date.now();
    for(const c of chain)if(Date.parse(c.validFrom)>now || Date.parse(c.validTo)<=now)throw new Error();
    for(let i=0;i<chain.length-1;i++)if(!chain[i].checkIssued(chain[i+1]) || !chain[i].verify(chain[i+1].publicKey))throw new Error();
    for(const domain of domains)if(!leaf.checkHost(domain))throw new Error();
    return {notAfter:new Date(leaf.validTo)};
  }catch{throw new HttpError(422,'invalid_certificate','Certificate must be current, cover all domains, match its private key, and contain a correctly ordered chain');}
}

export function encryptKey(pem:string,key:Buffer,context:string) {
  if(key.length!==32)throw new Error('WAF_MASTER_KEY must decode to 32 bytes');
  const iv=randomBytes(12);const cipher=createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(Buffer.from(context));
  const encrypted=Buffer.concat([cipher.update(pem,'utf8'),cipher.final()]);
  return ['v1',iv.toString('base64'),cipher.getAuthTag().toString('base64'),encrypted.toString('base64')].join('.');
}
export function decryptKey(value:string,key:Buffer,context:string) {
  const [version,iv,tag,data]=value.split('.');if(version!=='v1')throw new Error('Unsupported encrypted key version');
  const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(iv,'base64'));decipher.setAAD(Buffer.from(context));decipher.setAuthTag(Buffer.from(tag,'base64'));
  return Buffer.concat([decipher.update(Buffer.from(data,'base64')),decipher.final()]).toString('utf8');
}
