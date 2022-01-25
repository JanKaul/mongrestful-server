import { default as express } from "express"
import { default as cors } from "cors"

import { exportPublicKey } from "./auth"
// import { runMongoDb } from "./database"

const app = express();
const port = 3000;

app.use(cors());

// runMongoDb(app).catch(console.dir);

app.get('/public_key', (req, res) => {
    res.send(exportPublicKey)
})

app.listen(port, () => {
    console.log(`Mongrestful server listening on port ${port}`)
})