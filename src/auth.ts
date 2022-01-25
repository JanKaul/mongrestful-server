import * as jose from 'jose';

// export const secret = await jose.generateSecret('A256GCM')

// export const jwt = await new jose.EncryptJWT({ 'username': encodeURIComponent(username), 'password': encodeURIComponent(password), 'authorized': true })
//     .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
//     .setIssuedAt()
//     .setExpirationTime('24h')
//     .encrypt(secret)

// console.log("Token: " + jwt);

// const { payload, protectedHeader } = await jose.jwtDecrypt(jwt, secret)

// console.log(payload)

const { publicKey, privateKey } = await jose.generateKeyPair('ES256')

export const exportPublicKey = await jose.exportSPKI(publicKey)

// export const jwt = await new jose.EncryptJWT({ 'username': encodeURIComponent("jan"), 'password': encodeURIComponent("kaul") })
//     .setProtectedHeader({ alg: 'ECDH-ES+A256KW', enc: 'A256GCM' })
//     .setIssuedAt()
//     .encrypt(publicKey)

// console.log("Token: " + jwt);

// const { payload, protectedHeader } = await jose.jwtDecrypt(jwt, privateKey)

// console.log(payload)