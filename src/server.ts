import { default as express } from "express"
import { default as cors } from "cors"
import { default as bodyParser } from "body-parser"
import { default as session } from "express-session"
import * as jose from "jose"
import { Optional, Some, None } from "optional-typescript"
import { match } from "ts-pattern"
import { MongoClient } from "mongodb";

import { exportPublicKey, privateKey, exportCookieSecret } from "./auth"

// import { runMongoDb } from "./database"

let client: Optional<MongoClient> = None()

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
        const { username, password, clientPublicKey } = payload

        const sessionSecret = await jose.generateSecret('A256GCM') as jose.KeyLike

        req["session"].secret = await jose.exportJWK(sessionSecret)

        const answer = await new jose.EncryptJWT({
            secret: encodeURIComponent(JSON.stringify(await jose.exportJWK(sessionSecret)))
        })
            .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
            .setIssuedAt()
            .encrypt(await jose.importSPKI(decodeURIComponent(clientPublicKey as string), 'RSA-OAEP-256'))

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

