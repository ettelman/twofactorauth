// Two-factor authentication with Node.js, Express, MongoDB and Speakeasy
// Freja Eid login made with Eid
// Made by: Björn Ettelman

// setup for npm packages
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const eid = require("eid");
const cookieParser = require('cookie-parser');

// getting User model for mongodb
const User = require("./models/User");

// envoirment variables
require("dotenv").config();

// reading the private and public key for jwt
const privateKey = fs.readFileSync('./cert/private_key.pem', 'utf8');
const publicKey = fs.readFileSync('./cert/public_key.pem', 'utf8');

// using express
const app = express();

// using cors and body-parser for parsing data
// using cookie-parser for handling cookies
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// using express.static to serve the client
app.use(express.static(path.join(__dirname, 'dist')));

// connecting to mongodb
const DB_location = process.env.DBLOC;


mongoose.connect(DB_location, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Middleware function to authenticate JWT - Can be used in any route
// Only used in one route in this project
function authenticateToken(req, res, next) {
  // Get the token from cookie
  
  const token = req.cookies.token;
  // If there's no token, return an error
  if (!token) {
    return res.status(403).json({ error: "Token saknas" });
  }

  // Verify the token
  
  jwt.verify(token, publicKey, { algorithms: ['RS256'] }, (err, user) => {
    if (err) {
      // If the token is invalid, return an error
      
      return res.status(401).json({ error: "Medskickad token är inte giltig" });
    }

    // If the token is valid, set the user in the request and call the next middleware function
    req.user = user.email;
    next();
  });
}

// route for registering a user
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  // checking if email and password are provided. This is done on the client side as well
  if (!email || !password) {
    return res.status(400).json({ error: "Epost och lösenord krävs" });
  }
// checking if user already exists
  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      res.status(400).json({ error: "En användare med denna epost finns redan" });
    } else {
      // creating new user with mongoose model
      const newUser = new User({ email, password });
      await newUser.save();
      res.status(200).json({ message: "Användare skapad med epost" + email });
    }
  } catch (error) {
    console.error("Något gick fel vid registreringen, felkod: ", error);
    res.status(500).json({ error: "Något gick fel vid registreringen" });
  }
});

// route for logging in a user
app.post("/login", async (req, res) => {
  const { email, password, twoFactorToken } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "Det finns ingen användare med denna epostadress" });
    }
    // using bcrypt to compare password
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
      return res.status(401).json({ error: "Fel lösenord och/eller epostadress" });
    }
    // checking if user has a twofactor secret.
    // If they do, verify the token they provide
    if (user.twoFactorSecret) {
      const checkToken = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: "base32",
        token: twoFactorToken,
      }); 

      if (!checkToken) {
        return res.status(401).json({ error: "Fel tvåstegskod, försök igen.", twoFactorRequired: true });
      }
    }
    // creating a jwt token with the user email
    const token = jwt.sign({ email: user.email }, privateKey, { algorithm: 'RS256', expiresIn: '1h' });
    // sending the token to the client as a cookie
    console.log(token);
    res.cookie("token", token, { httpOnly: true }).json({ status: "success" });
  } catch (error) {
    // if something goes wrong, log the error and send error message to the client
    console.error("Errorcode:", error);
    res.status(500).json({ error: "Något gick fel vid inloggningen", details: error.message });
  }
});
// Logout, clearing the cookie with the jwt inside
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ status: 'success' });
});

// route for checking if a user has two-factor authentication enabled before they login
// used with a blur event on the email input field. Can be used in other ways as well
app.post("/check", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      // returns false if user is not found. This is used to hide the two-factor input field
      return res.json({ twoFactor: false });
    }

    res.json({ twoFactor: !!user.twoFactorSecret });
  } catch (error) {
    console.error("Errorcode:", error);
    res.status(500).json({ error: "Något gick fel med tvåstegsinloggningen. (check)" });
  }
});

// route for setting up two-factor authentication
app.post("/setup", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Epost och lösenord krävs" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Användaren finns inte" });
    }
    const checkPassword = await bcrypt.compare(password, user.password);
  if (!checkPassword) {
    return res.status(401).json({ error: "Fel lösenord" });
  }
    // generating a secret for the user
    const secret = speakeasy.generateSecret({ length: 20 });
    user.twoFactorSecret = secret.base32;
    await user.save();

    // setting up the otpauth url for the QR code
    const url = speakeasy.otpauthURL({ secret: secret.ascii, label: "Bonnier", issuer: "Exjobb" });
    const qrCodeImageUrl = await qrcode.toDataURL(url);
    // sending the QR code image url to the client
    res.json({ qrCodeImageUrl });
  } catch (error) {
    console.error("Error during two-factor setup:", error);
    res.status(500).json({ error: "Ett fel har inträffat vid konfiguration av tvåstegsinloggning. Kontakta support ()" });
  }
});

// route for verifying the token provided by the user
// used to verify the token after the user has scanned the QR code
app.post("/verify", async (req, res) => {
  const { email, token } = req.body;
  
  if (!email || !token) {
    return res.status(400).json({ error: "Epost och tvåstegskod krävs för att validera" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Användaren finns inte" });
    }
    // verifying the token provided by the user
    const { twoFactorSecret } = user;
    const verified = speakeasy.totp.verify({ secret: twoFactorSecret, encoding: "base32", token });

    if (verified) {
      res.status(200).json({ status: "success" });
    } else {
      res.status(400).json({ error: "Fel tvåstegskod, kontrollera så att koden inte gått ut." });
    }
  } catch (error) {
    console.error("Error during two-factor verification:", error);
    res.status(500).json({ error: "Ett fel har inträffat vid konfiguration av tvåstegsinloggning. Kontakta support ()" });
  }
});

app.post("/freja", async (req, res) => {
  let { login, type } = req.body;
  // checks if login is empty
  if (!login) {
    return res.status(400).json({ error: "Epost eller personnummer måste anges" });
  }
  // if type is empty, set type to ssn (default)
  if (!type) {
    type="ssn";
  }
  // setting up eid
  // this is just a test setup but can be changed to connect to production API
  var config = eid.configFactory({
    clientType: "frejaeid",
    endpoint: "https://services.test.frejaeid.com",
    enviroment: "testing",
    client_cert: fs.readFileSync(path.join(__dirname, "/cert", "bonnier-news-test.pfx")),
    password: process.env.FREJA,
    default_country: "SE",
    id_type: type,
  });
  
   // ssn or email here
  var client = eid.clientFactory(config);
  
  
  client.authRequest(login).then(function (result) {
    if (result.status === "completed") {
      // this is where you would add the user to the database (or check if user exists) if you want to keep track of who is logged in

      const token = jwt.sign({ email: result.extra.primaryEmail }, privateKey, { algorithm: 'RS256', expiresIn: '1h' });
      // sending the token to the client as a cookie
      res.cookie("token", token, { httpOnly: true }).json({ status: "success", user: result });
    } else {
      res.status(401).json({ error: result});
    }
    console.log("*** ", result);
  });


});

/* verify jwt token with middleware
   use this route to check if a user is logged in
   returns user data if the token is valid */
app.get("/authenticate", authenticateToken, (req, res) => {
  
  res.json({ status: "success", email: req.user });
});

// Serving VUE frontend if no route is specified
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});