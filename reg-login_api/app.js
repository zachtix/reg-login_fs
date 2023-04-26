require('dotenv').config()
const ENV = process.env

const express = require('express')
const cors = require('cors')

const jwt = require('jsonwebtoken')
const secret = ENV.SECRET

const bcrypt = require('bcrypt')
const saltRounder = 10

const bodyParser = require('body-parser')
const jsonparser = bodyParser.json()

const mysql = require('mysql2')
const connection = mysql.createConnection({
  host: ENV.HOST,
  user: ENV.USER,
  database: ENV.DB
});

const app = express()

app.use(cors())

app.get('/', function(req, res, next) {
  res.json({msg:'This is CORS-enabled for all origin!'})
})

app.post('/register', jsonparser, function(req, res, next) {
  // res.json({msg:'This is register api'})
  const data = req.body
  bcrypt.hash(data.password, saltRounder, function(err, hash) {
    connection.execute(
      'INSERT INTO users (email, password, fname, lname) VALUES (?, ?, ?, ?)',
      [data.email, hash, data.fname, data.lname],
      function(err, results, fields) {
        if (err) {
          res.json({status: 'error', message: err})
          return
        }
        res.json({status: 'ok'})
      }
    )
  })
})

app.post('/login', jsonparser, function(req, res, next) {
  // res.json({msg:'This is register api'})
  const data = req.body
  connection.execute(
    'SELECT * FROM users WHERE email=?',
    [data.email],
    function(err, users, fields) {
      if (err) {
        res.json({status: 'error', message: err})
        return
      }
      if (users.length == 0) {
        res.json({status: 'error', message: 'no user found'})
        return
      }
      bcrypt.compare(data.password, users[0].password, function(err, isLogin) {
        if (isLogin) {
          res.json({status:'ok', message:'login success'})
          return
        } else {
          res.json({status:'error', message:'login failed'})
          return
        }
      })
      // res.json({status: 'ok'})
    }
  )
})

app.listen(8000, function() {
  console.log('CORS-enabled web server listening on port 8000')
})