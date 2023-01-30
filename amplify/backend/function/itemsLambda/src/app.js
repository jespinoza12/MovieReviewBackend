const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const cors = require("cors");
const port = 9292;
const bcrypt = require("bcryptjs");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

const awsServerlessExpressMiddleware = require("aws-serverless-express/middleware");
require("dotenv").config();



async function connectToDb() {
  const secretData = await secretsManager
    .getSecretValue({ SecretId: 'dev/MONGO' })
    .promise();
  const secretValues = JSON.parse(secretData.SecretString);
  const mongoUri = secretValues.MONGO;
  
  return mongoose.connect(mongoUri || process.env.MONGO, { useNewUrlParser: true }).then(() => {
    console.log("DB Connected");
  });
}

connectToDb();

const userSchema = new mongoose.Schema({
  fname: String,
  lname: String,
  street: String,
  city: String,
  state: String,
  zip_code: String,
  email: String,
  phone: String,
  password: String,
  role: String,
});

const User = mongoose.model("User", userSchema);

// declare a new express app
const app = express();
app.use(express.json({ limit: "100mb", extended: true }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(bodyParser.json());
app.use(awsServerlessExpressMiddleware.eventContext());
app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Authorization", "Content-Type"],
  })
);
// Enable CORS for all methods
app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "*", "Authorization");
  next();
});

const authenticate = async (req, res, next) => {
  const authHeader =
    req.headers["authorization"] || req.headers["Authorization"];
  if (!authHeader) {
    return res.send({ message: "Unauthorized: No token provided" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.send({ message: "Unauthorized: Invalid token" });
  }

  try {
    const secretData = await secretsManager
      .getSecretValue({ SecretId: 'dev/JWT_SECRET' })
      .promise();
    const secretValues = JSON.parse(secretData.SecretString);
    const jwtSecret = secretValues.JWT_SECRET;

    const decoded = jwt.verify(token, jwtSecret || process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.send({ message: "Unauthorized: Invalid token" });
  }
};

app.get("/items/user", authenticate, (req, res) => {
  res.send({ user: req.user });
});


app.get("/items/admin/allUsers", authenticate, async (req, res) => {
  try {
    const user = req.user;
    if (user.role !== "Admin") {
      return res.status(401).json({
        message: "Unauthorized access",
      });
    }
    const allUsers = await User.find({});
    return res.status(200).json({
      users: allUsers,
      message: `Welcome Admin ${user.lname}`
    });
  } catch (error) {
    return res.status(500).json({
      message: "An error occurred while fetching the users",
    });
  }
});


async function authenticateUser(email, password) {
  return new Promise((resolve, reject) => {
    User.findOne({ email: email }, async (err, user) => {
      if (user) {
        bcrypt.compare(password, user.password, async function (err, result) {
          if (result) {
            const secretData = await secretsManager
              .getSecretValue({ SecretId: 'dev/JWT_SECRET' })
              .promise();
            const secretValues = JSON.parse(secretData.SecretString);
            const jwtSecret = secretValues.JWT_SECRET;

            //create a JWT token
            const token = jwt.sign({ user }, jwtSecret || process.env.JWT_SECRET, {
              expiresIn: "1h",
            });
            resolve({
              message: "Login Successfull",
              user: user,
              token: token
            });
          } else {
            reject({ message: "Email or Password Incorrect" });
          }
        });
      } else if (!user) {
        reject({ message: "User not found" });
      }
    });
  });
}

app.post("/items/login", function (req, res, next) {
  const { email, password } = req.body;
  authenticateUser(email, password)
    .then(result => {
      res.send(result);
    })
    .catch(error => {
      res.status(404).send(error);
    });
});

app.post("/items/register", function (req, res) {
  // Add your code here
  const {
    fname,
    lname,
    street,
    city,
    state,
    zip_code,
    email,
    phone,
    password,
  } = req.body;
  User.findOne({ email: email }, (err, user) => {
    if (user) {
      res.send({ message: "User already exists" });
    } else if (!user) {
      bcrypt.genSalt(saltRounds, function (err, salt) {
        bcrypt.hash(password, salt, function (err, hash) {
          const user = new User({
            fname: fname,
            lname: lname,
            street: street,
            city: city,
            state: state,
            zip_code: zip_code,
            email: email,
            phone: phone,
            password: hash,
            role: "user",
          });
          user.save((err) => {
            if (err) {
              res.send(err);
            } else {
              res.send({ message: "Successfully Registered, Please Login" });
            }
          });
        });
      });
    }
  });
});

app.delete("/items/deleteUser", function (req, res) {
  // Add your code here
  res.json({ success: "delete call succeed!", url: req.url });
});

app.listen(port, function () {
  console.log(`App started ${port}`);
});

// Export the app object. When executing the application local this does nothing. However,
// to port it to AWS Lambda we will create a wrapper around that will load the app from
// this file
module.exports = app;
