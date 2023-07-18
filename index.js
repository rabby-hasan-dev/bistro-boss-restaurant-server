const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config()
const stripe = require('stripe')(process.env.VITE_payment_secrate_key)
const app = express();
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json())

const verifyJWT = (req, res, next) => {
    // console.log(req.headers);
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ error: true, message: 'unauthorized access' });
    }
    // bearer token
    const token = authorization.split(' ')[1];
    jwt.verify(token, process.env.ACCESS_TOKEN_SECREATE, (error, decoded) => {
        if (error) {
            return res.status(401).send({ error: true, message: 'unauthorized access' })
        }
        req.decoded = decoded;
        next();
    })
}


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.p6rgmv3.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();
        const usersCollection = client.db("bistroDB").collection('users');
        const menuCollection = client.db("bistroDB").collection('menu');
        const reviewsCollection = client.db("bistroDB").collection('reviews');
        const cartCollection = client.db("bistroDB").collection('carts');
        const paymentCollection = client.db("bistroDB").collection('payments');

        // jwt api
        app.post('/jwt', (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECREATE, { expiresIn: '1h' });
            res.send({ token });
        })
        //  warning: use verifyJWT before using verifyAdmin
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);
            if (user?.role !== 'admin') {
                return res.status(403).send({ error: true, message: 'forbidden access' })
            }

            next();


        }

        /**
         * 0. don not show the secure links to those who should not  see the links
         * 1.use jwt token:verifyJWT
         * 2. use verify admin middleware
         * */
        // users related api
        app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result)
        })

        app.post('/users', async (req, res) => {
            const users = req.body;
            const query = { email: users.email };
            const existingUser = await usersCollection.findOne(query);
            if (existingUser) {
                return res.send({ message: 'User already exist' })

            }
            const result = await usersCollection.insertOne(users);
            res.send(result);
        })



        // admin related api
        app.patch('/users/admin/:id', async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) }
            const updateDoc = {
                $set: {
                    role: 'admin'
                },
            };
            const result = await usersCollection.updateOne(filter, updateDoc);
            res.send(result);
        })

        // Security layer: verifyJWt
        // email same
        // check admin

        app.get('/users/admin/:email', verifyJWT, async (req, res) => {
            const email = req.params.email;

            if (req.decoded.email !== email) {
                res.send({ admin: false })
            }

            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const result = { admin: user?.role === 'admin' };
            res.send(result);
        })

        // menu related api 
        app.get('/menu', async (req, res) => {
            const result = await menuCollection.find().toArray();
            res.send(result)
        })

        app.post('/menu', verifyJWT, verifyAdmin, async (req, res) => {
            const newItem = req.body;
            const result = await menuCollection.insertOne(newItem);
            res.send(result);

        })

        app.delete('/menu/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await menuCollection.deleteOne(query);
            res.send(result);
        })


        // reviews related api
        app.get('/reviews', async (req, res) => {
            const result = await reviewsCollection.find().toArray();
            res.send(result)
        })

        // cart  related api
        app.get('/carts', verifyJWT, async (req, res) => {

            const email = req.query.email;
            if (!email) {
                return res.send([]);
            }

            const decodedEmail = req.decoded.email;
            if (email !== decodedEmail) {
                return res.status(403).send({ error: true, message: 'forbidden access' })

            }

            const query = { email: email }
            const result = await cartCollection.find(query).toArray();
            res.send(result)
        })
        app.post('/carts', async (req, res) => {
            const item = req.body;
            const result = await cartCollection.insertOne(item);
            res.send(result);
        })

        app.delete('/carts/:id', async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await cartCollection.deleteOne(query);
            res.send(result)
        })

        // Create payment intent
        app.post("/create-payment-intent", verifyJWT, async (req, res) => {

            const { price } = req.body;
            const amount = parseInt(price * 100);

            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: "usd",
                payment_method_types: ["card"],

            })

            res.send({
                clientSecret: paymentIntent.client_secret
            })

        });

        // payment related api
        app.post('/payments', async (req, res) => {
            const payment = req.body;
            const insertResult = await paymentCollection.insertOne(payment);

            const query = { _id: { $in: payment.cartItems.map(id => new ObjectId(id)) } }
            const deleteResult = await cartCollection.deleteMany(query);
            res.send({ insertResult, deleteResult });
        })

        app.get('/payments',verifyJWT, async (req, res) => {
            const email = req.query.email;
            if (!email) {
                return res.send([]);
            }

            const decodedEmail = req.decoded.email;
            if (email !== decodedEmail) {
                return res.status(403).send({ error: true, message: 'forbidden access' })

            }

            const query = { email: email }
            const result = await paymentCollection.find(query).toArray();
            res.send(result);
        })

        app.get('/admin-stats', verifyJWT, verifyAdmin, async (req, res) => {
            const users = await usersCollection.estimatedDocumentCount();
            const products = await menuCollection.estimatedDocumentCount();
            const orders = await paymentCollection.estimatedDocumentCount();
            const payments = await paymentCollection.find().toArray();
            const revenue = payments.reduce((sum, payment) => sum + payment.price, 0)
            res.send({
                users,
                products,
                orders,
                revenue
            })
        })

        app.get('/order-stats', async (req, res) => {
            const pipeline = [
                {
                    $lookup: {
                        from: 'menu',
                        localField: 'menuItems',
                        foreignField: '_id',
                        as: 'menuItemsData'
                    }
                },
                {
                    $unwind: '$menuItemsData'
                },
                {
                    $group: {
                        _id: '$menuItemsData.category',
                        count: { $sum: 1 },
                        total: { $sum: '$menuItemsData.price' }
                    }
                },
                {
                    $project: {
                        category: '$_id',
                        count: 1,
                        total: { $round: ['$total', 2] },
                        _id: 0
                    }
                }
            ];

            const result = await paymentCollection.aggregate(pipeline).toArray()
            res.send(result)

        })

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('Server is running');

})

app.listen(port, () => {
    console.log(`BISTRO BOSS RESTAURANT SERVER RUNNING PORT IS:${port}`)
})

/**
 * 
 * ------------------------------------------------
 *          Naming convention
 * -------------------------------------------
 * users:collection
 * app.get('/users')
 * app.get('/users/:id')
 * app.post('/users')
 * app.put('/users/:id')
 * app.patch('/users/:id')
 * app.delete('/users/:id')
 * 
 * */ 