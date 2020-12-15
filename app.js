const express = require("express");
const { query } = require("express");
const app = express();
const port = 8080;

const moment = require('moment');

const bodyParser = require("body-parser");
app.use(bodyParser.json());

// Disable CORS
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, authorization");
    next();
});


// Reference: https://github.com/auth0/node-jsonwebtoken
const awsRegion = 'us-east-2';
const userPoolId = 'us-east-2_VGbmuGvJP';
const appClientIds = '45er0df675ul996u66j8innebu';

const jwt = require('jsonwebtoken');
const jwksRSA = require('jwks-rsa');
const jwksClient = jwksRSA({
    jwksUri: `https://cognito-idp.${awsRegion}.amazonaws.com/${userPoolId}/.well-known/jwks.json`,
})

function getJSONWebKey(header, callback){
    jwksClient.getSigningKey(header.kid, (err, key) => {
        if(err){
            return;
        }

        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    })
}

// Verify JSON Web Token
function authenticateJWT(req, res, next, userType){
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if(token == null){
        return res.sendStatus(401);
    } 

    // Based on Step 3 (https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html)
    // Pass the options requiring verification to the verify method
    const jwtOptions = {
        algorithms: ['RS256'],
        ignoreExpiration: false, // Always check for expiration
        audience: appClientIds,
        issuer: `https://cognito-idp.${awsRegion}.amazonaws.com/${userPoolId}`,
    }

    jwt.verify(token, getJSONWebKey, jwtOptions, (err, decodedToken) => {
        if(err){
            console.log("Error: ", err);
            res.status(401).send();
            return;
        }

        if(decodedToken.token_use != 'access' && decodedToken.token_use != 'id'){
            console.log("Invalid token_use attribute!");
            res.status(401).send();
            return;
        }

        if(userType !== null){
            if(!decodedToken['cognito:groups'].includes(userType)){
                res.status(403).send();
                return;
            }
        }

        next();
    })
}

function authenticateNormalUser(req, res, next){
    authenticateJWT(req, res, next, 'user');
}

function authenticateGudangUser(req, res, next){
    authenticateJWT(req, res, next, 'gudang');
}

function authenticateAnyUser(req, res, next){
    authenticateJWT(req, res, next, null);
}


const mongo = require('mongodb');
const MongoClient = mongo.MongoClient;
const ObjectId = mongo.ObjectId;
const uri = "mongodb+srv://pervasiv:kentuvalair@cluster0.ncsxd.mongodb.net/plcmonitor?retryWrites=true&w=majority";
const client = new MongoClient(uri, { useNewUrlParser: true });

let database = null;
let bahan_coll = null;
let campuran_coll = null;
let hasil_coll = null;
let history_coll = null;
let recent_coll = null;
let recent_change_stream = null;

const webPush = require('web-push');
let notificationSubscriptions = [];
const notificationOptions = {
    gcmAPIKey : "372642852326",
    TTL: 60,
}

function sendNotification(message){
    notificationSubscriptions.forEach(async subs => {
        try {
            console.log("Sending Notification to ", subs.uid);
            await webPush.sendNotification(subs.subscription, message, notificationOptions);
        } catch (error) {
            console.error(error)
        }
    })
}

app.listen(port, async () => {
    console.log("app listening port " + port);
    await client.connect(err => {
        database = client.db("plcmonitor");
        bahan_coll = database.collection("bahan");
        campuran_coll = database.collection("campuran");
        hasil_coll = database.collection("hasil");
        history_coll = database.collection("history");
        recent_coll = database.collection("recent");

        // Set up ChangeStream
        if(recent_coll){
            recent_change_stream = recent_coll.watch({fullDocument: 'updateLookup'});

            recent_change_stream.on('change', changeEvent => {
                const changedDocument = changeEvent.fullDocument;

                let notificationMessage = 'New Mix Input Received!';

                if(changedDocument.Timestamp.finished_mix){
                    notificationMessage = 'Mix Finished!';
                } else if (changedDocument.Timestamp.start_mix){
                    notificationMessage = 'Mix Processed!';
                }

                sendNotification(notificationMessage);
            });

            // Set up WebPush
            const vapidKeys = require('./vapid-keys.json');
            webPush.setVapidDetails(
                'mailto:arida.rosa@student.umn.ac.id',
                vapidKeys.publicKey,
                vapidKeys.privateKey
            );
        }

        console.log("Successfully connected to MongoDB CloudDB");
    });
});


//!BAHAN
// GET all bahan
app.get("/bahan", authenticateAnyUser, async (req, res) => {
    if (database === null || bahan_coll === null) {
        const response = {
            "status": "database_connect_failed",
            "message": "Server failed to connect to database"
        };

        res.status(500).send(response);
        return;
    }

    const coll = bahan_coll.find() // Untuk Query All
    let result = [];

    try {
        await coll.forEach(doc => {
            result.push(doc);
        });

        const response = {
            status: "success",
            count: result.count,
            data: result,
        }

        res.status(200).send(response);
    } catch (error) {
        console.log(error);
        const response = {
            status: "db_query_failed",
            message: "Failed to run database query"
        }

        res.status(500).send(response);
    }
});

// GET bahan dengan id :bahan_id
app.get("/bahan/:bahan_id", authenticateAnyUser, async (req, res) => {
    if (database === null || bahan_coll === null) {
        const response = {
            "status": "database_connect_failed",
            "message": "Server failed to connect to database"
        };

        res.status(500).send(response);
        return;
    }

    try {
        const doc = await bahan_coll.findOne({ // Untuk Query Spesifik
            _id: ObjectId(req.params.bahan_id)
        })

        const status_code = doc ? 200 : 404;

        const response = {
            status: "success",
            data: doc,
        }

        res.status(status_code).send(response);
    } catch (error) {
        console.log(error);
        const response = {
            status: "db_query_failed",
            message: "Failed to run database query"
        }

        res.status(500).send(response);
    }
});

// Update stok bahan 
app.post("/bahan/stok", authenticateGudangUser, async (req, res) => {
    if (database === null || bahan_coll === null) {
        const response = {
            "status": "database_connect_failed",
            "message": "Server failed to connect to database"
        };

        res.status(500).send(response);
        return;
    }

    // Menerima dan sanitasi
    let {
        qty_alkohol,
        qty_aloevera,
        qty_hidrogen
    } = req.body;

    // Validasi
    if (
        qty_alkohol === null || 
        qty_aloevera === null ||
        qty_hidrogen === null
    ) {
        const response = {
            status: "invalid_params",
            message: "One of the required fields are null",
        }

        res.status(400).send(response);
        return;
    }


    if(
        Number.parseFloat(qty_alkohol) === Number.NaN ||
        Number.parseFloat(qty_aloevera) === Number.NaN ||
        Number.parseFloat(qty_hidrogen) === Number.NaN
    ) {
        const response = {
            status: "not_a_number",
            message: "One of the parameters given is not a number",
        }

        res.status(400).send(response);
        return;
    } else {
        qty_alkohol = parseFloat(qty_alkohol);
        qty_aloevera = parseFloat(qty_aloevera);
        qty_hidrogen = parseFloat(qty_hidrogen);
    }

    let updates = [];

    if(qty_alkohol > 0){
        updates.push({
            updateOne:{
                "filter"    : {nama_bahan: "Alkohol"},
                "update": {
                    $inc: {qty: Math.abs(qty_alkohol)},
                    $set: {
                        tgl_dimasukkan : Date(),
                        tgl_expired    : moment(Date()).add(14, 'days').toDate(),
                    }
                }
            }
        });
    }

    if(qty_aloevera > 0){
        updates.push({
            updateOne:{
                "filter"    : {nama_bahan: "Aloevera"},
                "update": {
                    $inc: {qty: Math.abs(qty_aloevera)},
                    $set: {
                        tgl_dimasukkan : Date(),
                        tgl_expired    : moment(Date()).add(1, 'months').toDate(),
                    }
                }
            }
        });
    }

    if(qty_hidrogen > 0){
        updates.push({
            updateOne:{
                "filter"    : {nama_bahan: "Hidrogen Peroxide"},
                "update": {
                    $inc: {qty: Math.abs(qty_hidrogen)},
                    $set: {
                        tgl_dimasukkan : Date(),
                        tgl_expired    : moment(Date()).add(1, 'months').toDate(),
                    }
                }
            }
        });
    }

    console.log("Test")

    // Interaksi ke database
    const insertResult = await bahan_coll.bulkWrite(updates);

    const response = {
        status: "success",
        message: "Stock updated successfully!"
    }

    // Mengurus Response
    res.status(200).send(response);
});


//!Campuran
// GET all campuran
app.get("/campuran", async (req, res) => {
    if (database === null || campuran_coll === null) {
        const response = {
            "status": "database_connect_failed",
            "message": "Server failed to connect to database"
        };

        res.status(500).send(response);
        return;
    }

    const coll = campuran_coll.find() // Untuk Query All
    let result = [];

    try {
        await coll.forEach(doc => {
            result.push(doc);
        });

        const response = {
            status: "success",
            count: result.count,
            data: result,
        }

        res.status(200).send(response);
    } catch (error) {
        console.log(error);
        const response = {
            status: "db_query_failed",
            message: "Failed to run database query"
        }

        res.status(500).send(response);
    }
});

// GET campuran dengan id :campuran_id
app.get("/campuran/:campuran_id", async (req, res) => {
    if (database === null || campuran_coll === null) {
        const response = {
            "status": "database_connect_failed",
            "message": "Server failed to connect to database"
        };

        res.status(500).send(response);
        return;
    }

    try {
        const doc = await campuran_coll.findOne({ // Untuk Query Spesifik
            _id: ObjectId(req.params.campuran_id)
        });

        const status_code = doc ? 200 : 404;

        const response = {
            status: "success",
            data: doc,
        }

        res.status(status_code).send(response);
    } catch (error) {
        console.log(error);
        const response = {
            status: "db_query_failed",
            message: "Failed to run database query"
        }

        res.status(500).send(response);
    }
});

// Bikin campuran baru
app.post("/campuran", authenticateNormalUser, async (req, res) => {
    if (database === null || campuran_coll === null || bahan_coll === null || recent_coll === null || history_coll === null) {
        const response = {
            "status": "database_connect_failed",
            "message": "Server failed to connect to database"
        };

        res.status(500).send(response);
        return;
    }

    // Menerima dan sanitasi
    let {
        qty_alkohol,
        qty_aloevera,
        qty_hidrogen,
    } = req.body


    // Validasi
    if (
        qty_alkohol === null || 
        qty_aloevera === null ||
        qty_hidrogen === null
    ) {
        const response = {
            status: "invalid_params",
            message: "One of the required fields are null",
        }

        res.status(400).send(response);
        return;
    }


    if (
        Number.parseInt(qty_alkohol) === Number.NaN ||
        Number.parseInt(qty_aloevera) === Number.NaN ||
        Number.parseInt(qty_hidrogen) === Number.NaN
    ) {
        const response = {
            status: "not_a_number",
            message: "One of the parameters given is not a number",
        }

        res.status(400).send(response);
        return;
    } else {
        qty_alkohol  = parseInt(qty_alkohol);
        qty_aloevera = parseInt(qty_aloevera);
        qty_hidrogen = parseInt(qty_hidrogen);
    }

    const session = client.startSession();

    try {
        const alkohol = await bahan_coll.findOne({nama_bahan : "Alkohol", qty:{$gt:  qty_alkohol}});
        const aloevera = await bahan_coll.findOne({nama_bahan : "Aloevera", qty:{$gt: qty_aloevera}});
        const hidrogen = await bahan_coll.findOne({nama_bahan : "Hidrogen Peroxide", qty:{$gt: qty_hidrogen}});

        if(alkohol === null || aloevera === null || hidrogen === null){
            const response = {
                status  : "invalid_qty",
                message : "An ingredient doesn't have enough stock"
            }
    
            res.status(400).send(response);
            return;
        }

        const new_campuran = {
            alkohol:{
                id: ObjectId(alkohol._id),
                qty: qty_alkohol,
            },
            aloevera:{
                id: ObjectId(aloevera._id),
                qty: qty_aloevera,
            },
            hidrogen_peroxide:{
                id: ObjectId(hidrogen._id),
                qty: qty_hidrogen,
            },
        }

        // Transaction

        await session.withTransaction(async () => {
            const result = await campuran_coll.insertOne(new_campuran);

            const history_entry = {
                PIC: "dummy_user",
                id_campuran: result.insertedId,
                id_hasil: null,
                Timestamp:{
                    created_mix: Date(),
                    start_mix: null,
                    finished_mix: null
                }
            }

            await history_coll.insertOne(history_entry);
            console.log(result.insertedId)
            await recent_coll.findOneAndUpdate({}, {$set: {
                PIC: "dummy_user",
                id_campuran: result.insertedId,
                id_hasil: null,
                Timestamp:{
                    created_mix: Date(),
                    start_mix: null,
                    finished_mix: null
                }
            }}, {upsert: true});

            await bahan_coll.bulkWrite([
                {
                    updateOne:{
                        "filter" : {nama_bahan: "Alkohol"},
                        "update" : {$inc: {qty: -Math.abs(qty_alkohol)}}
                    }
                },
                {
                    updateOne:{
                        "filter" : {nama_bahan: "Aloevera"},
                        "update" : {$inc: {qty: -Math.abs(qty_aloevera)}}
                    }
                },
                {
                    updateOne:{
                        "filter" : {nama_bahan: "Hidrogen Peroxide"},
                        "update" : {$inc: {qty: -Math.abs(qty_hidrogen)}}
                    }
                }
            ]);
        })

        const response = {
            status: "success",
            message: "Mixture input received!"
        }

        res.status(200).send(response);
    } catch (error) {
        console.log(error);
        const response = {
            status: "db_query_failed",
            message: "Failed to run database query"
        }

        res.status(500).send(response);
    } finally {
        session.endSession();
    }
});


//!Start Mix
app.post("/mix/:campuran_id", async (req, res) => {
    if (database === null || campuran_coll === null || recent_coll === null || history_coll === null) {
        const response = {
            "status": "database_connect_failed",
            "message": "Server failed to connect to database"
        };

        res.status(500).send(response);
        return;
    }

    if(req.params.campuran_id === null) {
        const response = {
            status: "invalid_params",
            message: "One of the required fields are null",
        }

        res.status(400).send(response);
        return;
    }

    const campuran_id = req.params.campuran_id;

    const ref_campuran = await campuran_coll.findOne({_id : ObjectId(campuran_id)});

    if(!ref_campuran) {
        const response = {
            status: "not_found",
            message: "Campuran with that ID is not found",
        }

        res.status(404).send(response);
        return;
    }

    const session = client.startSession();

    try {
        await session.withTransaction(async () => {
            await history_coll.findOneAndUpdate({
                id_campuran: ObjectId(campuran_id),
            } , {$set: {
                "Timestamp.start_mix": Date(),
            }}, {upsert: true});

            const history_entry = await history_coll.findOne({id_campuran: ObjectId(campuran_id)});

            await recent_coll.findOneAndUpdate({}, {$set: {
                PIC: "dummy_user",
                id_campuran: history_entry.id_campuran,
                id_hasil: null,
                Timestamp: history_entry.Timestamp,
            }}, {upsert: true});
        });

        const response = {
            status: "success",
            message: "Mixture Signal received!"
        }

        res.status(200).send(response);
    } catch (error) {
        console.log(error);
        const response = {
            status: "db_query_failed",
            message: error.message || "Failed to run database query"
        }

        res.status(500).send(response);
    } finally {
        session.endSession();
    }
});


//!Hasil
// GET all hasil
app.get("/hasil", authenticateAnyUser, async (req, res) => {
    if (database === null || hasil_coll === null) {
        const response = {
            "status": "database_connect_failed",
            "message": "Server failed to connect to database"
        };

        res.status(500).send(response);
        return;
    }

    const coll = hasil_coll.find();
    let result = [];

    try {
        await coll.forEach(doc => result.push(doc));

        const response = {
            status: "success",
            count: result.count,
            data: result,
        }

        res.status(200).send(response);
    } catch (error) {
        console.log(error);
        const response = {
            status: "db_query_failed",
            message: "Failed to run database query"
        }

        res.status(500).send(response);
    }
});

// GET hasil dengan id :hasil_id
app.get("/hasil/:hasil_id", authenticateAnyUser, async (req, res) => {
    if (database === null || hasil_coll === null) {
        const response = {
            "status": "database_connect_failed",
            "message": "Server failed to connect to database"
        };

        res.status(500).send(response);
        return;
    }

    try {
        const doc = await hasil_coll.findOne({ // Untuk Query Spesifik
            _id: ObjectId(req.params.hasil_id)
        });

        console.log(doc);

        const status_code = doc ? 200 : 404;

        const response = {
            status: "success",
            data: doc,
        }

        res.status(status_code).send(response);
    } catch (error) {
        console.log(error);
        const response = {
            status: "db_query_failed",
            message: "Failed to run database query"
        }

        res.status(500).send(response);
    }
})

// Register hasil baru
app.post("/hasil", async (req, res) => {
    if (database === null || campuran_coll === null || hasil_coll === null || recent_coll === null || history_coll === null) {
        const response = {
            "status": "database_connect_failed",
            "message": "Server failed to connect to database"
        };

        res.status(500).send(response);
        return;
    }

    let {
        campuran_id,
        kekentalan,
        kadar_alkohol,
        isi_bersih
    } = req.body;

    if (
        campuran_id === null ||
        kekentalan === null ||
        kadar_alkohol === null ||
        isi_bersih === null
    ) {
        const response = {
            status: "invalid_params",
            message: "One of the required fields are null",
        }

        res.status(400).send(response);
        return;
    }

    if (
        Number.parseInt(kekentalan) === Number.NaN ||
        Number.parseInt(kadar_alkohol) === Number.NaN ||
        Number.parseInt(isi_bersih) === Number.NaN
    ) {
        const response = {
            status: "not_a_number",
            message: "One of the parameters given is not a number",
        }

        res.status(400).send(response);
        return;
    } else {
        kekentalan = parseInt(kekentalan);
        kadar_alkohol = parseInt(kadar_alkohol);
        isi_bersih = parseInt(isi_bersih);
    }

    const session = client.startSession();

    try {
        //TODO: Implement sesuai dgn flow yg ditetapkan
        //0. Cari campuran yg jadi reference V
        //1. Write ke Collection Hasil
        //Opsional: Masukin history
        //2. Update Timestamp dari Recent

        const ref_campuran = await campuran_coll.findOne({_id : ObjectId(campuran_id)});

        if(!ref_campuran) throw new Error('Cannot find Campuran with that ID');

        const new_hasil = {
            id_campuran: ref_campuran._id,
            kekentalan: kekentalan,
            kadar_alkohol: kadar_alkohol,
            isi_bersih: isi_bersih,
        }

        await session.withTransaction(async () => {
            const result = await hasil_coll.insertOne(new_hasil);

            await history_coll.findOneAndUpdate({
                id_campuran: ObjectId(campuran_id),
            } , {
                $set: {
                    id_hasil: result.insertedId,
                    "Timestamp.finished_mix": Date(),
                }
            }, {upsert: true});

            const history_entry = await history_coll.findOne({id_campuran: ObjectId(campuran_id)});

            await recent_coll.findOneAndUpdate({}, {$set: {
                PIC: "dummy_user",
                id_campuran: history_entry.id_campuran,
                id_hasil: history_entry.id_hasil,
                Timestamp: history_entry.Timestamp,
            }}, {upsert: true});
        });

        const response = {
            status: "success",
            message: "Mixture input received!"
        }

        res.status(200).send(response);
    } catch (error) {
        console.log(error);
        const response = {
            status: "db_query_failed",
            message: error.message || "Failed to run database query"
        }

        res.status(500).send(response);
    } finally {
        session.endSession();
    }
});


//!Recent
// GET all bahan
app.get("/recent", authenticateAnyUser, async (req, res) => {
    if (database === null || recent_coll === null) {
        const response = {
            "status": "database_connect_failed",
            "message": "Server failed to connect to database"
        };

        res.status(500).send(response);
        return;
    }

    try {
        const aggr = await recent_coll.aggregate([
            {
                $lookup: {
                    from: "campuran",
                    localField: "id_campuran",
                    foreignField: "_id",
                    as: "campuran"
                }
            }
        ]);

        const doc = await aggr.next();

        const status_code = doc ? 200 : 404;

        const response = {
            status: "success",
            data: doc,
        }

        res.status(status_code).send(response);
    } catch (error) {
        console.log(error);
        const response = {
            status: "db_query_failed",
            message: "Failed to run database query"
        }

        res.status(500).send(response);
    }
});


//!Subscribe
// Untuk Push Notification (di web)
app.post('/subscribe/notification', authenticateAnyUser, async (req, res) => {
    const subscriptionDetails = req.body;
    
    if(notificationSubscriptions.findIndex(val => val.uid = subscriptionDetails.uid) === -1){
        console.log("New subscription");
        notificationSubscriptions.push(subscriptionDetails);
    } else {
        console.log("Duplicate Subscription");
    }

    console.log(notificationSubscriptions)

    const response = {
        status: 'success',
        message: 'Subscribed for notifications from the server!',
    }

    res.status(200).send(response);
})


//!MQTT Client
