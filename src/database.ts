import { MongoClient } from "mongodb";

export async function runMongoDb(url, app) {
    const client = new MongoClient(url);
    try {
        const port = 3000;
        await client.connect();
        const adminDb = client.db("admin").admin();
        const databases = await (await adminDb.listDatabases()).databases;
        for (const database of databases) {
            app.get('/' + database.name, function (req, res) {
                res.send(database.name)
            })
        }
        app.listen(port, () => {
            console.log(`Mongrestful server listening on port ${port}`)
        })
    } finally {
        await client.close();
    }
}