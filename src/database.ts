import { Express } from "express"
import { MongoClient, DbOptions, CollectionOptions } from "mongodb";
import * as jose from "jose"
import { Option, some, none, Result, ok, err } from "matchingmonads"
import { match } from "ts-pattern"

import { collectionRoute } from "./collection";

export function databaseRoute(dbName: string, dbOptions: DbOptions, client: Option<MongoClient>, app: Express) {

    app.post("/" + dbName + "/collection", async (req, res) => {

        const sessionSecret = await jose.importJWK(req["session"].secret, 'A256GCM')

        const { payload, protectedHeader } = await jose.jwtDecrypt(req.body, sessionSecret)
        const { collectionName, collectionOptions } = payload

        const result = match(client)
            .with({ tag: "some" }, (x) => {
                let result;
                try {
                    const db = x.value.db(dbName)
                    const collection = db.collection(collectionName as string, collectionOptions as CollectionOptions)
                    collectionRoute(dbName, dbOptions, collectionName as string, collectionOptions as CollectionOptions, x, app)
                    result = ok("Success: Collection is accessible at the route: /" + dbName + "/collection" + collectionName as string)
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
}