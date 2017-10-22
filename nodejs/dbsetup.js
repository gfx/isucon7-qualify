/*
  $ node
  > pool = require('./dbsetup')
  ...
  > pool.query('select * from user limit 1').then(r => console.log(r))
*/

const mysql = require('mysql');
const util = require('util');

const pool = mysql.createPool({
  connectionLimit: 20,
  host: process.env.ISUBATA_DB_HOST || 'db',
  port: process.env.ISUBATA_DB_PORT || '3306',
  user: process.env.ISUBATA_DB_USER || 'isucon',
  password: process.env.ISUBATA_DB_PASSWORD || 'isucon',
  database: 'isubata',
  charset: 'utf8mb4',
})
pool.query = util.promisify(pool.query, pool)

module.exports = pool
