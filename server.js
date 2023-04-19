// Two-factor authentication with Node.js, Express, MongoDB and Speakeasy
// Made by: Björn Ettelman

// setup for all npm packages
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// getting User model for mongodb
const User = require('./models/User');

// using express
const app = express();

// using cors and body-parser for parsing data
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// connecting to mongodb
const DB_location = "mongodb://localhost:27017/twofacdb";

mongoose.connect(DB_location, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// route for registering a user
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // checking if email and password are provided. This is done on the client side as well
  if (!email || !password) {
    return res.status(400).json({ error: "Epost och lösenord krävs" });
  }
// checking if user already exists
  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      res.status(400).json({ error: 'En användare med denna epost finns redan' });
    } else {
      // creating new user with mongoose model
      const newUser = new User({ email, password });
      await newUser.save();
      res.status(200).json({ message: 'Användare skapad med epost' + email });
    }
  } catch (error) {
    console.error('Något gick fel vid registreringen, felkod: ', error);
    res.status(500).json({ error: 'Något gick fel vid registreringen' });
  }
});

// route for logging in a user
app.post('/login', async (req, res) => {
  const { email, password, twoFactorToken } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "Det finns ingen användare med denna epostadress" });
    }
    // using bcrypt to compare password
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
      return res.status(401).json({ error: 'Fel lösenord och/eller epostadress' });
    }
    // checking if user has a twofactor secret.
    // If they do, verify the token they provide
    if (user.twoFactorSecret) {
      const checkToken = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorToken,
      }); 

      if (!checkToken) {
        return res.status(401).json({ error: "Fel tvåstegskod, försök igen.", twoFactorRequired: true });
      }
    }
      // return sucess message if everything is ok
      res.json({ status: 'success' });
  } catch (error) {
    // if something goes wrong, log the error and send error message to the client
    console.error('Errorcode:', error);
    res.status(500).json({ error: 'Något gick fel vid inloggningen', details: error.message });
  }
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
    console.error('Errorcode:', error);
    res.status(500).json({ error: 'Något gick fel med tvåstegsinloggningen. (check)' });
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
      return res.status(404).json({ error: 'Användaren finns inte' });
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
    const url = speakeasy.otpauthURL({ secret: secret.ascii, label: 'Bonnier', issuer: 'Exjobb' });
    const qrCodeImageUrl = await qrcode.toDataURL(url);
    // sending the QR code image url to the client
    res.json({ qrCodeImageUrl });
  } catch (error) {
    console.error('Error during two-factor setup:', error);
    res.status(500).json({ error: 'Ett fel har inträffat vid konfiguration av tvåstegsinloggning. Kontakta support ()' });
  }
});

// route for verifying the token provided by the user
// used to verify the token after the user has scanned the QR code
app.post('/verify', async (req, res) => {
  const { email, token } = req.body;
  
  if (!email || !token) {
    return res.status(400).json({ error: 'Epost och tvåstegskod krävs för att validera' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Användaren finns inte" });
    }
    // verifying the token provided by the user
    const { twoFactorSecret } = user;
    const verified = speakeasy.totp.verify({ secret: twoFactorSecret, encoding: 'base32', token });

    if (verified) {
      res.status(200).json({ status: 'success' });
    } else {
      res.status(400).json({ error: "Fel tvåstegskod, kontrollera så att koden inte gått ut." });
    }
  } catch (error) {
    console.error('Error during two-factor verification:', error);
    res.status(500).json({ error: 'Ett fel har inträffat vid konfiguration av tvåstegsinloggning. Kontakta support ()' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});