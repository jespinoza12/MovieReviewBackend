/*
Copyright 2017 - 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
    http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
*/

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const port = 9292;
const bcrypt = require('bcryptjs');
const saltRounds = 10;


const awsServerlessExpressMiddleware = require('aws-serverless-express/middleware')
require('dotenv').config()

mongoose.connect(process.env.MONGO).then(()=>{console.log('DB Connected')})

const userSchema = new mongoose.Schema({
  fname: String,
  lname: String,
  steet: String,
  city: String,
  state: String,
  zip_code: String,
  email: String,
  phone: String,
  password: String
});


const User  = mongoose.model('User', userSchema);

// declare a new express app
const app = express()
app.use(express.json({limit: '100mb', extended: true}))
app.use(express.urlencoded({limit: '100mb', extended: true}))
app.use(cors())
app.use(bodyParser.json())
app.use(awsServerlessExpressMiddleware.eventContext())

// Enable CORS for all methods
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*")
  res.header("Access-Control-Allow-Headers", "*")
  next()
});


app.get('/items/login', function(req, res) {
  // Add your code here

  res.json({success: 'get call succeed!', url: req.url});
});

app.post('/items/register', function(req, res) {
  // Add your code here
  const {fname, lname, steet, city, state, zip_code, email, phone, password} = req.body;
  User.findOne({email: email}, (err, user) => {
    if (user) {
      res.send({message: 'User already exists'})
    } else if (!user){
      bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(fname, salt, function(err, fnhash) {
          bcrypt.genSalt(saltRounds, function(err, salt) {
            bcrypt.hash(lname, salt, function(err, lnhash) {
              bcrypt.genSalt(saltRounds, function(err, salt) {
                bcrypt.hash(steet, salt, function(err, streethash) {
                  bcrypt.genSalt(saltRounds, function(err, salt) {
                    bcrypt.hash(city, salt, function(err, chash) {
                      bcrypt.genSalt(saltRounds, function(err, salt) {
                        bcrypt.hash(state, salt, function(err, statehash) {
                          bcrypt.genSalt(saltRounds, function(err, salt) {
                            bcrypt.hash(zip_code, salt, function(err, zhash) {
                              bcrypt.genSalt(saltRounds, function(err, salt) {
                                bcrypt.hash(email, salt, function(err, emailhash) {
                                  bcrypt.genSalt(saltRounds, function(err, salt) {
                                    bcrypt.hash(phone, salt, function(err, phash) {
                                      bcrypt.genSalt(saltRounds, function(err, salt) {
                                        bcrypt.hash(password, salt, function(err, hash) {
                                          const user = new User({
                                            fname: fnhash,
                                            lname: lnhash,
                                            steet: streethash,
                                            city: chash,
                                            state: statehash,
                                            zip_code: zhash,
                                            email: emailhash,
                                            phone: phash,
                                            password: hash
                                          });
                                          user.save(err => {
                                            if(err) {
                                                res.send(err)
                                            } else {
                                                res.send( { message: "Successfully Registered, Please Login" } )
                                            }
                                          });
                                        });
                                      });
                                    });
                                  });
                                });
                              });
                            });
                          });
                        });
                      });
                    });
                  });
                });
              });
    
            });
          });
        });
      });
    }
    else {
      res.send({message: 'Oopsie something happened thats not supposed to'})
    }
  });
});

app.put('/items', function(req, res) {
  // Add your code here
  res.json({success: 'put call succeed!', url: req.url, body: req.body})
});

app.delete('/items/deleteUser', function(req, res) {
  // Add your code here
  res.json({success: 'delete call succeed!', url: req.url});
});

app.listen(port, function() {
    console.log(`App started ${port}`)
});

// Export the app object. When executing the application local this does nothing. However,
// to port it to AWS Lambda we will create a wrapper around that will load the app from
// this file
module.exports = app
