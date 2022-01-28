import { default as express } from "express"
import { default as cors } from "cors"
import { default as bodyParser } from "body-parser"
import { default as session } from "express-session"
import * as jose from "jose"
import { Maybe, nothing, maybe, Either, left, right } from "tsmonads";
import { match } from "ts-pattern"
import { MongoClient } from "mongodb";

import { exportPublicKey, privateKey, exportCookieSecret } from "./auth"

// import { runMongoDb } from "./database"

let client: Maybe<MongoClient> = nothing()

try {
    const app = express();
    const port = 3000;

    app.use(express.json())
    app.use(bodyParser.text())
    app.use(cors({ origin: true, credentials: true }));
    app.use(session({
        secret: exportCookieSecret,
        resave: false,
        saveUninitialized: true,
    }))

    // runMongoDb(app).catch(console.dir);

    app.listen(port, () => {
        console.log(`Mongrestful server listening on port ${port}`)
    })

    app.get('/public_key', (req, res) => {
        res.send(encodeURIComponent(exportPublicKey))
    })

    app.post('/connect', async (req, res) => {
        const { payload, protectedHeader } = await jose.jwtDecrypt(req.body, privateKey)
        const { url, clientPublicKey } = payload

        client = match(client)
            .with({ hasValue: true }, (res) => maybe(res.unsafeLift()))
            .with({ hasValue: false }, (_) => {
                let mongoUrl = new URL(decodeURIComponent(url as string).replace(/^http:\/\//i, 'mongodb://'))
                mongoUrl.port = "27017"
                mongoUrl.hostname = "localhost"

                try {
                    return maybe(new MongoClient(mongoUrl.toString()))
                } catch (error) {
                    console.log(error)
                    return nothing()
                }
            })
            .exhaustive()

        let answer = await match(client)
            .with({ hasValue: true }, async (res) => {
                if (!req["session"].secret) {
                    const sessionSecret = await jose.generateSecret('A256GCM') as jose.KeyLike

                    req["session"].secret = await jose.exportJWK(sessionSecret)
                }
                return await new jose.EncryptJWT({
                    secret: encodeURIComponent(JSON.stringify(req["session"].secret))
                })
                    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
                    .setIssuedAt()
                    .encrypt(await jose.importSPKI(decodeURIComponent(clientPublicKey as string), 'RSA-OAEP-256'))
            })
            .with({ hasValue: false }, async (res) => {
                return await new jose.EncryptJWT({
                    secret: undefined
                })
                    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
                    .setIssuedAt()
                    .encrypt(await jose.importSPKI(decodeURIComponent(clientPublicKey as string), 'RSA-OAEP-256'))
            })
            .exhaustive()

        res.send(answer)
    })

    app.post('/close', async (req, res) => {

        const sessionSecret = await jose.importJWK(req["session"].secret, 'A256GCM')

        const { payload, protectedHeader } = await jose.jwtDecrypt(req.body, sessionSecret)
        const { authorized } = payload

        const answer = await new jose.EncryptJWT({
            success: authorized
        })
            .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
            .setIssuedAt()
            .encrypt(sessionSecret)

        res.send(answer)
    })
} finally {
    client.map(x => x.close())
}

