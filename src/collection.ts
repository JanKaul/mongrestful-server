import { Express } from "express"
import { MongoClient, DbOptions, CollectionOptions } from "mongodb";
import * as jose from "jose"
import { Option, some, none, Result, ok, err } from "matchingmonads"
import { match } from "ts-pattern"

export function collectionRoutes(dbName: string, dbOptions: DbOptions, collectionName: string, collectionOptions: CollectionOptions, client: Option<MongoClient>, app: Express) {

    app.post("/" + dbName + "/" + collectionName + "/findone", async (req, res) => {

        const sessionSecret = await jose.importJWK(req["session"].secret, 'A256GCM')

        const { payload, protectedHeader } = await jose.jwtDecrypt(req.body, sessionSecret)
        const { filter, options } = payload

        const result = await match(client)
            .with({ tag: "some" }, async (x) => {
                let result;
                try {
                    const db = (await x.value.connect()).db(dbName)
                    const collection = db.collection(collectionName as string, collectionOptions as CollectionOptions)
                    result = ok(await collection.findOne(filter, options))
                } catch (error) {
                    result = err(error.toString())
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

    app.post("/" + dbName + "/" + collectionName + "/insertone", async (req, res) => {

        const sessionSecret = await jose.importJWK(req["session"].secret, 'A256GCM')

        const { payload, protectedHeader } = await jose.jwtDecrypt(req.body, sessionSecret)
        const { doc, options } = payload

        const result = await match(client)
            .with({ tag: "some" }, async (x) => {
                let result;
                try {
                    const db = (await x.value.connect()).db(dbName)
                    const collection = db.collection(collectionName as string, collectionOptions as CollectionOptions)
                    result = ok(await collection.insertOne(doc, options))
                } catch (error) {
                    result = err(error.toString())
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

    app.post("/" + dbName + "/" + collectionName + "/insertmany", async (req, res) => {

        const sessionSecret = await jose.importJWK(req["session"].secret, 'A256GCM')

        const { payload, protectedHeader } = await jose.jwtDecrypt(req.body, sessionSecret)
        const { docs, options } = payload

        const result = await match(client)
            .with({ tag: "some" }, async (x) => {
                let result;
                try {
                    const db = (await x.value.connect()).db(dbName)
                    const collection = db.collection(collectionName as string, collectionOptions as CollectionOptions)
                    result = ok(await collection.insertMany(docs as unknown[], options))
                } catch (error) {
                    result = err(error.toString())
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

    app.post("/" + dbName + "/" + collectionName + "/deleteone", async (req, res) => {

        const sessionSecret = await jose.importJWK(req["session"].secret, 'A256GCM')

        const { payload, protectedHeader } = await jose.jwtDecrypt(req.body, sessionSecret)
        const { filter, options } = payload

        const result = await match(client)
            .with({ tag: "some" }, async (x) => {
                let result;
                try {
                    const db = (await x.value.connect()).db(dbName)
                    const collection = db.collection(collectionName as string, collectionOptions as CollectionOptions)
                    result = ok(await collection.deleteOne(filter, options))
                } catch (error) {
                    result = err(error.toString())
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
}