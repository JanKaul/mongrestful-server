import { default as express } from "express"
import { default as cors } from "cors"
import { default as bodyParser } from "body-parser"
import { default as session } from "express-session"
import * as jose from "jose"
import { Option, some, none, Result, ok, err } from "matchingmonads"
import { match } from "ts-pattern"
import { DbOptions, MongoClient } from "mongodb";

import { exportPublicKey, privateKey, exportCookieSecret } from "./auth"
import { databaseRoutes } from "./database"

let client: Option<MongoClient> = none()

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

    app.listen(port, () => {
        console.log(`Mongrestful server listening on port ${port}`)
    })

    app.get('/public_key', (req, res) => {
        res.send(encodeURIComponent(exportPublicKey))
    })

    app.post('/connect', async (req, res) => {
        const { payload, protectedHeader } = await jose.jwtDecrypt(req.body, privateKey)
        const { url, clientPublicKey } = payload

        client = await match(client)
            .with({ tag: "some" }, async (x) => some(x.value))
            .with({ tag: "none" }, async (_) => {
                let mongoUrl = new URL(decodeURIComponent(url as string).replace(/^http:\/\//i, 'mongodb://'))
                mongoUrl.port = "27017"
                mongoUrl.hostname = "localhost"

                try {
                    return some(await new MongoClient(mongoUrl.toString()).connect())
                } catch (error) {
                    console.log(error)
                    return none<MongoClient>()
                }
            })
            .exhaustive()

        let answer = await match(client)
            .with({ tag: "some" }, async (_) => {
                if (!req["session"].secret) {
                    const sessionSecret = await jose.generateSecret('A256GCM') as jose.KeyLike

                    req["session"].secret = await jose.exportJWK(sessionSecret)
                }
                return await new jose.EncryptJWT({
                    result: ok(encodeURIComponent(JSON.stringify(req["session"].secret)))
                })
                    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
                    .setIssuedAt()
                    .encrypt(await jose.importSPKI(decodeURIComponent(clientPublicKey as string), 'RSA-OAEP-256'))
            })
            .with({ tag: "none" }, async (_) => {
                return await new jose.EncryptJWT({
                    result: err("Error: No MongoDB client running on the server.")
                })
                    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
                    .setIssuedAt()
                    .encrypt(await jose.importSPKI(decodeURIComponent(clientPublicKey as string), 'RSA-OAEP-256'))
            })
            .exhaustive()

        res.send(answer)
    })

    app.post('/db', async (req, res) => {

        const sessionSecret = await jose.importJWK(req["session"].secret, 'A256GCM')

        const { payload, protectedHeader } = await jose.jwtDecrypt(req.body, sessionSecret)
        const { dbName, dbOptions } = payload

        const result = match(client)
            .with({ tag: "some" }, (x) => {
                let result;
                try {
                    const db = x.value.db(dbName as string, dbOptions as DbOptions)
                    databaseRoutes(dbName as string, dbOptions, client, app)
                    result = ok("Success: Database is accessible at the route: /" + dbName as string)
                } catch (error) {
                    result = err(error.toString())
                }
                return result
            })
            .with({ tag: "none" }, _ => err("Error: There is no MongoDB client running."))
            .exhaustive()

        const answer = await new jose.EncryptJWT({
            result: result
        })
            .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
            .setIssuedAt()
            .encrypt(sessionSecret)

        res.send(answer)
    })

    app.post('/close', async (req, res) => {

        const sessionSecret = await jose.importJWK(req["session"].secret, 'A256GCM')

        const { payload, protectedHeader } = await jose.jwtDecrypt(req.body, sessionSecret)
        const { authorized } = payload

        const result = await match(client)
            .with({ tag: "some" }, async (x) => {
                let result;
                try {
                    await x.value.close()
                    result = ok("Success: Client closed successfully.")
                } catch (error) {
                    result = err("Error: Closing MongoDb client failed.")
                }
                return result
            })
            .with({ tag: "none" }, async _ => err("Error: There is no MongoDB client running."))
            .exhaustive()

        const answer = await new jose.EncryptJWT({
            result: result
        })
            .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
            .setIssuedAt()
            .encrypt(sessionSecret)

        res.send(answer)
    })
} finally {
    client.asyncMap(async (x: MongoClient) => await x.close())
}

