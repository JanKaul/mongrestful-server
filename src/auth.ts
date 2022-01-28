import * as jose from 'jose';

const { publicKey, privateKey } = await jose.generateKeyPair('RSA-OAEP-256')

export const exportPublicKey = await jose.exportSPKI(publicKey)

const cookieSecret = await jose.generateSecret("HS256")

export const exportCookieSecret = JSON.stringify(await jose.exportJWK(cookieSecret as jose.KeyLike))

export { privateKey }
