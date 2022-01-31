import { Express } from "express"
import { MongoClient, DbOptions, CollectionOptions } from "mongodb";
import * as jose from "jose"
import { Option, some, none, Result, ok, err } from "matchingmonads"
import { match } from "ts-pattern"

export function collectionRoute(dbName: string, dbOptions: DbOptions, collectionName: string, collectionOptions: CollectionOptions, client: Option<MongoClient>, app: Express) {
    app.post("/" + dbName + "/" + collectionName, async (req, res) => {

        const sessionSecret = await jose.importJWK(req["session"].secret, 'A256GCM')

        const { payload, protectedHeader } = await jose.jwtDecrypt(req.body, sessionSecret)
        const { collectionName, collectionOptions } = payload

        const result = match(client)
            .with({ tag: "some" }, (x) => {
                let result;
                try {
                    const db = x.value.db(dbName)
                    const collection = db.collection(collectionName as string, collectionOptions as CollectionOptions)
                    result = ok("Success: Database is accessible as the route:" + collectionName as string)
                } catch (error) {
                    result = err("Error: Closing MongoDb client failed.")
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
}