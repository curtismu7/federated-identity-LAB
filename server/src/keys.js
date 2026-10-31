// RSA keys for the lab's mock issuers. Generated lazily and kept IN MEMORY ONLY, shared by every workspace of this process: a key is a slot
// (issuer number x generation), so two visitors' issuers hold the same lab keys, which are worthless outside this process and are never written
// or shown (only the public halves are ever published). RSA key generation is fine; no EC key is ever generated here.
import crypto from 'node:crypto';

export const GENERATIONS = 6; // key generations per issuer (the first plus five rotations)
const pool = new Map();

export function keyAt(index) {
  if (!Number.isInteger(index) || index < 0 || index > 64) throw new Error('key slot out of range');
  if (!pool.has(index)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const { kty, n, e } = publicKey.export({ format: 'jwk' });
    pool.set(index, { privateKey, publicJwk: { kty, n, e } });
  }
  return pool.get(index);
}
export const keyCount = () => pool.size;
