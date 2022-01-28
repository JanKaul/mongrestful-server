import { default as express } from "express"
import { default as cors } from "cors"
import { default as bodyParser } from "body-parser"
import * as jose from "jose"
import { Optional, Some, None } from "optional-typescript"
import { match } from "ts-pattern"

import { exportPublicKey, privateKey } from "./auth"
import { MongoClient } from "mongodb";
// import { runMongoDb } from "./database"

let client: Optional<MongoClient> = None()

let sessions = new Map()

try {
    const app = express();
    const port = 3000;

    app.use(express.json())
    app.use(bodyParser.text())
    app.use(cors());

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



        const answer = await new jose.EncryptJWT({
            secret: encodeURIComponent(JSON.stringify(await jose.exportJWK(sessionSecret)))
        })
            .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
            .setIssuedAt()
            .encrypt(await jose.importSPKI(decodeURIComponent(clientPublicKey as string), 'RSA-OAEP-256'))

        res.send(answer)
    })
} finally {
    client.map(x => x.close())
}

