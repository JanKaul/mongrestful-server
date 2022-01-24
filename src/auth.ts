import * as jose from 'jose';
import { default as prompts } from "prompts";

let { username, password } = await prompts([{ type: "text", name: "username", message: "username:" }, { type: "password", name: "password", message: "password:" }])

const secret = await jose.generateSecret('A256GCM')

export const jwt = await new jose.EncryptJWT({ 'username': encodeURIComponent(username), 'password': encodeURIComponent(password), 'authorized': true })
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setIssuedAt()
    .setExpirationTime('2h')
    .encrypt(secret)

console.log("Token: " + jwt);

const { payload, protectedHeader } = await jose.jwtDecrypt(jwt, secret)

console.log(payload)