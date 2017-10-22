const http = require('http')
const mysql = require('mysql')
const promisify = require('es6-promisify')

const pool = mysql.createPool({
  connectionLimit: 20,
  host: process.env.ISUBATA_DB_HOST || 'localhost',
  port: process.env.ISUBATA_DB_PORT || '3306',
  user: process.env.ISUBATA_DB_USER || 'root',
  password: process.env.ISUBATA_DB_PASSWORD || '',
  database: 'isubata',
  charset: 'utf8mb4',
})
pool.query = promisify(pool.query, pool)

pool.query('SELECT * FROM image WHERE id <= 1001')
  .then((images) => {
    images.forEach((image) => {
      console.log(`save image ${image.id}: ${image.name}`);
      const req = http.request({
        method: 'PUT',
        host: 'db',
        path: '/icons/' + image.name
      }, (res) => {
        res.on('error', (err) => {
          console.error(err)
        })
        res.on('end', () => {
          console.log('ok')
        })
      });
      req.write(image.data)
      req.end()
    })
  })
