import * as jose from 'jose';

const { publicKey, privateKey } = await jose.generateKeyPair('RSA-OAEP-256')

export const exportPublicKey = await jose.exportSPKI(publicKey)

export { privateKey }
