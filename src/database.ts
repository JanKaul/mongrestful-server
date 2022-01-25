import { MongoClient } from "mongodb";

const url = 'mongodb://localhost:27017';

const client = new MongoClient(url);

export async function runMongoDb(app) {
    try {
        await client.connect();
        const adminDb = client.db("admin").admin();
        const databases = await (await adminDb.listDatabases()).databases;
        for (const database of databases) {
            app.get('/' + database.name, function (req, res) {
                res.send(database.name)
            })
        }
    } finally {
        await client.close();
    }
}