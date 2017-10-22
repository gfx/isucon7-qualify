"use strict";

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const express = require('express')
const session = require('cookie-session')
const bodyParser = require('body-parser')
const multer = require('multer')
const mysql = require('mysql')
const ECT = require('ect')
const promisify = require('es6-promisify')
const http = require('http')

const STATIC_FOLDER = path.join(__dirname, '..', 'public')
const ICONS_FOLDER = path.join(STATIC_FOLDER, 'icons')
const AVATAR_MAX_SIZE = 1 * 1024 * 1024
const PORT = 5000

const ect = new ECT({
  root: path.join(__dirname, 'views'),
  ext : '.html',
})
const upload = multer({ dest: '/tmp' })
const app = express()

app.set('view engine', 'html')
app.engine('html', ect.render)
app.use(express.static(STATIC_FOLDER))
app.use(bodyParser.urlencoded({ extended: true }))
app.use(session({
  name: 'session',
  keys: ['tonymoris'],
  maxAge: 360000,
}))
app.use((err, req, res, next) => {
  res.status(500).end()
})

const pool = mysql.createPool({
  connectionLimit: 20,
  host: process.env.ISUBATA_DB_HOST || 'db',
  port: process.env.ISUBATA_DB_PORT || '3306',
  user: process.env.ISUBATA_DB_USER || 'isucon',
  password: process.env.ISUBATA_DB_PASSWORD || 'isucon',
  database: 'isubata',
  charset: 'utf8mb4',
})
pool.query = promisify(pool.query, pool)

app.get('/initialize', getInitialize)
async function getInitialize(req, res) {
  await pool.query('DELETE FROM user WHERE id > 1000');
  await pool.query('DELETE FROM image WHERE id > 1001');
  await pool.query('DELETE FROM channel WHERE id > 10');
  await pool.query('DELETE FROM message WHERE id > 10000');
  // await pool.query('DELETE FROM haveread');
  await pool.query('DELETE FROM haveread_count');

  const rows = await pool.query('select channel_id as id, count(*) as count from message group by channel_id');
  for (const row of rows) {
      await pool.query('update channel set message_count=? where id=?',[row.count,row.id]);
  }

  return res.status(204).send('');
}

function dbGetUser(conn, userId) {
  return conn.query('SELECT * FROM user WHERE id = ?', [userId])
    .then(([result]) => result)
}

async function dbAddMessage(conn, channelId, userId, content) {
   const ret = await conn.query('INSERT INTO message (channel_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())', [channelId, userId, content]);
   await conn.query('update channel set message_count = message_count + 1 where id=?',[channelId]);
   return ret;
}

function loginRequired(req, res, next) {
  if (!req.session.userId) {
    res.redirect(303, '/login')
    return
  }

  req.userId = req.session.userId
  return dbGetUser(pool, req.userId)
    .then(user => {
      req.user = user
      next()
    })
}

function randomString(len) {
  const seed = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
  let str = ''
  while (--len) {
    str += seed[~~(Math.random() * seed.length)]
  }
  return str
}

function register(conn, user, password) {
  const salt = randomString(20)
  const passDigest = crypto.createHash('sha1')
    .update(salt + password)
    .digest('hex')

  return conn.query(`INSERT INTO user (name, salt, password, display_name, avatar_icon, created_at)
    VALUES (?, ?, ?, ?, ?, NOW())`,
    [user, salt, passDigest, user, 'default.png'])
    .then(({ insertId }) => insertId)
}

app.get('/', getIndex)
function getIndex(req, res) {
  if (req.session.userId) {
    res.redirect(303, '/channel/1')
  } else {
    res.render('index', { req })
  }
}

function getChannelListInfo (conn, focusChannelId = null) {
  return conn.query('SELECT * FROM channel ORDER BY id')
    .then(channels => {
      let description = ''
      channels.forEach((channel) => {
        if (channel.id == focusChannelId) {
          description = channel.description
        }
      })

      return { channels, description }
    })
}

app.get('/channel/:channelId', loginRequired, getChannel)
function getChannel(req, res) {
  const { channelId } = req.params
  return getChannelListInfo(pool, channelId)
    .then(({ channels, description }) => {
      res.render('channel', {
        req,
        channels,
        description,
        channelId,
      })
    })
}

app.get('/register', getRegister)
function getRegister(req, res) {
  res.render('register', { req })
}

app.post('/register', postRegister)
function postRegister(req, res) {
  const { name, password } = req.body
  if (!name || !password) {
    res.status(400).end()
    return
  }

  return register(pool, name, password)
    .then(userId => {
      req.session.userId = userId
      res.redirect(303, '/')
    })
    .catch(e => {
      res.status(409).end()
    })
}

app.get('/login', getLogin)
function getLogin(req, res) {
  res.render('login', { req })
}

app.post('/login', postLogin)
function postLogin(req, res) {
  return pool.query('SELECT * FROM user WHERE name = ?', [req.body.name])
    .then(([row]) => {
      if (!row) {
        res.status(403).end()
        return
      }

      const { salt, password, id } = row
      const shasum = crypto.createHash('sha1')
      shasum.update(salt + req.body.password)
      const digest = shasum.digest('hex')
      if (password === digest) {
        req.session.userId = id
        res.redirect(303, '/')
      } else {
        res.status(403).end()
      }
    })
}

app.get('/logout', getLogout)
function getLogout(req, res) {
  req.session = null
  res.redirect(303, '/')
}

app.post('/message', postMessage)
function postMessage(req, res) {
  const { userId } = req.session

  const { channel_id, message } = req.body
  if (!userId || !channel_id || !message) {
    res.status(403).end()
    return
  }

  return dbAddMessage(pool, channel_id, userId, message)
    .then(() => res.status(204).end(''))
}

function zeroPadd (num, digit) {
  return ('0'.repeat(digit) + num).slice(-digit)
}

function formatDate (dateStr) {
  const d = new Date(dateStr)
  const datePart = [d.getFullYear(), zeroPadd(d.getMonth() + 1, 2), zeroPadd(d.getDate(), 2)].join('/')
  const timePart = [zeroPadd(d.getHours(), 2), zeroPadd(d.getMinutes(), 2), zeroPadd(d.getSeconds(), 2)].join(':')
  return datePart + ' ' + timePart
}

app.get('/message', getMessage)
async function getMessage(req, res) {
  const { userId } = req.session
  if (!userId) {
    res.status(403).end()
    return
  }

  const { channel_id, last_message_id } = req.query

  const rows = await pool.query(
    `
      select
        message.*
        , user.name as user_name
        , user.display_name as user_display_name
        , user.avatar_icon as user_avatar_icon
      from message
      join user on message.user_id = user.id
      where message.id > ? and message.channel_id = ? order by message.id desc limit 100
    `, [last_message_id, channel_id]);

  const response = rows.map(row => {
    return {
      id: row.id,
      date: formatDate(row.created_at),
      content: row.content,

      user: {
        name: row.user_name,
        display_name: row.user_display_name,
        avatar_icon: row.user_avatar_icon,
      },
    };
  });
  response.reverse();

  const maxMessageId = rows.length ? Math.max(...rows.map(r => r.id)) : 0;

  const [num] = await pool.query('SELECT COUNT(*) as count from message WHERE channel_id = ?', [channel_id])
  await pool.query(`INSERT INTO haveread_count (user_id, channel_id, num)
  VALUES (?, ?, ?)
  ON DUPLICATE KEY UPDATE num = ?`,
  [userId, channel_id, num.count, num.count]);

  res.json(response); // TODO: insert into haveread の前でもいいかも
}

function sleep (seconds) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve()
    }, seconds * 1000)
  })
}

app.get('/fetch', fetchUnread)
function fetchUnread(req, res) {
  const { userId } = req.session
  if (!userId) {
    res.status(403).end()
    return
  }

  return sleep(0.1)
    .then(() => pool.query('select channel_id as id, count(*) as count from message group by channel_id'))
    .then(channels => {
      return Promise.all([
        Promise.resolve(channels),
        pool.query('SELECT * FROM haveread_count WHERE user_id = ?', [userId]),
      ]);
    }).then(([channels, havereadCounts]) => {
      const havereadCountsMap = {};
      for (const haveread of havereadCounts) {
        havereadCountsMap[haveread.channel_id] = haveread.num;
      }

      const results = []
      let p = Promise.resolve()

      channels.forEach(channel => {
        const havereadCount = havereadCountsMap[channel.id]

        p = p.then(() => {
            if (havereadCount) {
              return Promise.resolve([{ count: channel.count - havereadCount }])
            } else {
              return Promise.resolve([{ count: channel.count }])
            }
          })
          .then(([unread]) => {
            results.push({
              channel_id: channel.id,
              unread: unread.count,
            })
          })
      })

      return p.then(() => results)
    })
    .then(results => res.json(results)).catch((error) => console.error(error));
}

app.get('/history/:channelId', loginRequired, getHistory)
async function getHistory(req, res) {
  const { channelId } = req.params
  const page = parseInt(req.query.page || '1')

  const N = 20
  const [{ count }] = await pool.query('SELECT COUNT(*) as count FROM message WHERE channel_id = ?', [channelId])

  const maxPage = Math.max(Math.ceil(count / N), 1)

  if (isNaN(page) || page < 1 || page > maxPage) {
    res.status(400).end()
    return
  }

  const rows = await pool.query(
    `
      select
        message.*
        , user.name as user_name
        , user.display_name as user_display_name
        , user.avatar_icon as user_avatar_icon
      from message
      join user on message.user_id = user.id
      where message.channel_id = ? order by message.id desc
      limit ? offset ?
    `, [channelId, N, (page - 1) * N]);


  const messages = []

  for (const row of rows) {
    messages.push({
      id: row.id,
      date: formatDate(row.created_at),
      content: row.content,

      user: {
        name: row.user_name,
        display_name: row.user_display_name,
        avatar_icon: row.user_avatar_icon,
      },
    });
  }

  messages.reverse();

  const { channels, description } = await getChannelListInfo(pool, channelId)
  res.render('history', {
    req, channels, channelId, messages, maxPage, page,
  });
}

app.get('/profile/:userName', loginRequired, getProfile)
function getProfile(req, res) {
  const { userName } = req.params
  return getChannelListInfo(pool)
    .then(({ channels }) => {
      return pool.query('SELECT * FROM user WHERE name = ?', [userName])
        .then(([user]) => {
          if (!user) {
            res.status(404).end()
            return
          }

          const selfProfile = req.user.id == user.id
          return res.render('profile', { req, channels, user, selfProfile })
        })
    })
}

app.get('/add_channel', loginRequired, getAddChannel)
function getAddChannel(req, res) {
  return getChannelListInfo(pool)
    .then(({ channels }) => {
      res.render('add_channel', { req, channels })
    })
}

app.post('/add_channel', loginRequired, postAddChannel)
function postAddChannel(req, res) {
  const { name, description } = req.body
  if (!name || !description) {
    res.status(400).end()
    return
  }

  return pool.query('INSERT INTO channel (name, description, updated_at, created_at) VALUES (?, ?, NOW(), NOW())', [name, description])
    .then(({ insertId }) => {
      res.redirect(303, '/channel/' + insertId)
    })
}

app.post('/profile', loginRequired, upload.single('avatar_icon'), postProfile)
function postProfile(req, res) {
  const { userId } = req.session
  if (!userId) {
    res.status(403).end()
    return
  }

  return dbGetUser(pool, userId)
    .then(user => {
      if (!user) {
        res.status(403).end()
        return
      }

      const { display_name } = req.body
      const avatar_icon = req.file
      let avatarName, avatarData

      let p = Promise.resolve()
      if (avatar_icon) {
        if (avatar_icon.originalname) {
          const ext = path.extname(avatar_icon.originalname) || ''
          if (!['.jpg', '.jpeg', '.png', '.gif'].includes(ext)) {
            res.status(400).end()
            return
          }

          if (avatar_icon.size > AVATAR_MAX_SIZE) {
            res.status(400).end()
            return
          }

          const data = fs.readFileSync(avatar_icon.path)
          const shasum = crypto.createHash('sha1')
          shasum.update(data)
          const digest = shasum.digest('hex')

          avatarName = digest + (ext ? ext : '')
          avatarData = data
        }
      }
      if (avatarName && avatarData) {
        p = p.then(() => pool.query('UPDATE user SET avatar_icon = ? WHERE id = ?', [avatarName, userId]))
        p = p.then(() => {
          return new Promise((resolve, reject) => {
            const req = http.request({
              method: 'PUT',
              host: 'db',
              path: '/icons/' + avatarName
            }, (res) => {
              res.on('data', (data) => {
              })
              res.on('error', (err) => {
                reject(err)
              })
              res.on('end', () => {
                resolve()
              })
            })
            req.write(avatarData)
            req.end()
          })
        })
      }

      if (display_name) {
        p = p.then(() => pool.query('UPDATE user SET display_name = ? WHERE id = ?', [display_name, userId]))
      }

      return p.then(() => res.redirect(303, '/'))
    })
}

app.listen(PORT, () => {
  console.log('Example app listening on port ' + PORT + '!')
})
