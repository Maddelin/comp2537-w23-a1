require('./utils.js');

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

// we use the environment variable PORT to set the port if it is set
const port = process.env.PORT || 3000;

const app = express();

const Joi = require('joi');

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection.js');

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session(
    {
        secret: node_session_secret,
        store: mongoStore, // default is memory store)
        saveUninitialized: false,
        resave: true
    }
));

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        res.send(`
        <h1>Hello!</h1>
        <form action='/signup' method='get'>
            <button>Sign up</button>
        </form>
        <form action='/login' method='get'>
            <button>Log in</button>
        </form>
        `);
    } else {
        res.send(`
        <h1>Hello ${req.session.name}!</h1>
        <form action='/members' method='get'>
            <button>Go to Members Area</button>
        </form>
        <form action='/logout' method='post'>
            <button>Log out</button>
        </form>
        `);
    }
});

app.get('/nosql-injection', async (req, res) => {
    var email = req.query.user;

    if (!email) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + email);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, email: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${result.name}</h1>`);
});

app.get('/about', (req, res) => {
    var color = req.query.color;

    res.send("<h1 style='color:" + color + ";'>The color of this text changes!</h1>");
});

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: " + email);
    }
});


app.get('/signup', (req, res) => {
    var html = `
    <h1>Sign up</h1>
    <form action='/submitUser' method='post'>
        <input name='name' type='text' placeholder='name'>
        <input name='email' type='text' placeholder='email'>
        <input name='password' type='password' placeholder='password'>
        <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    var missingFields = [];

    for (var field of ["name", "email", "password"]) {
        if (!req.body[field]) {
            missingFields.push(field);
        }
    }

    if (missingFields.length > 0) {
        var html = `${missingFields.join(", ")} required. <br>`;
        html += `<a href='/signup'>Try again</a>`
        res.send(html);
    } else {
        const schema = Joi.object(
            {
                name: Joi.string().alphanum().max(20).required(),
                email: Joi.string().email().required(),
                password: Joi.string().max(20).required()
            });

        const validationResult = schema.validate({ name, email, password });
        if (validationResult.error != null) {
            console.log(validationResult.error);
            res.redirect("/signup");
            return;
        }

        var hashedPassword = await bcrypt.hash(password, saltRounds);

        await userCollection.insertOne({ name: name, email: email, password: hashedPassword });
        console.log("Inserted user");

        req.session.authenticated = true;
        req.session.email = email;
        req.session.name = name;
        req.session.cookie.maxAge = expireTime;

        console.log("Successfully created user");
        res.redirect("/members");
    }
});

app.get('/login', (req, res) => {
    var html = `
        Log in
        <form action='/loggingin' method='post'>
            <input name='email' type='text' placeholder='email'>
            <input name='password' type='password' placeholder='password'>
            <button>Submit</button>
        </form>
        `;
    res.send(html);
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    var missingFields = [];

    for (var field of ["email", "password"]) {
        if (!req.body[field]) {
            missingFields.push(field);
        }
    }

    if (missingFields.length > 0) {
        var html = `${missingFields.join(", ")} required. <br>`;
        html += `<a href='/login'>Try again</a>`
        res.send(html);
    } else {

        const schema = Joi.string().max(20).required();
        const validationResult = schema.validate(email);
        if (validationResult.error != null) {
            console.log(validationResult.error);
            res.redirect("/login");
            return;
        }

        const users = await userCollection.find({ email: email }).project({ name: 1, email: 1, password: 1, _id: 1 }).toArray();

        console.log(users);
        if (users.length != 1) {
            var html = "User not found. <br>";
            html += `<a href='/login'>Try again</a>`
            res.send(html);
        } else {
            if (await bcrypt.compare(password, users[0].password)) {
                console.log("correct password");
                req.session.authenticated = true;
                req.session.email = email;
                req.session.name = users[0].name;
                req.session.cookie.maxAge = expireTime;

                res.redirect('/members');
                return;
            }
            else {
                var html = "Incorrect password. <br>";
                html += `<a href='/login'>Try again</a>`
                res.send(html);
            }
        }
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }

    const catNumber = Math.floor(Math.random() * (3 - 1 + 1) + 1);
    if (catNumber == 1) {
        kitty = "/black-kitten.jpg";
    } else if (catNumber == 2) {
        kitty = "/ragdoll-kitten.jpg";
    } else {
        kitty = "/siamese-kitten.jpg";
    }

    var html = `
        <h1>Hello ${req.session.name}!</h1>
        <img src=${kitty} style='width:250px;'><br>
        <form action='/logout' method='post'>
            <button>Log out</button>
        </form>
        `;
    res.send(html);
});

app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


app.get('/cat/:id', (req, res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("The cute void: <img src='/black-kitten.jpg' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("The angel: <img src='/ragdoll-kitten.jpg' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: " + cat);
    }
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404 <br> <img src='/lost-cat.jpg' style='width:250px;'>");
})

app.listen(port, () => {
    console.log("Server is running on port " + port);
});