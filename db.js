const Sequelize = require('sequelize');
const { STRING } = Sequelize;
const config = {
  logging: false,
};
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const saltRounds = 7;

if (process.env.LOGGING) {
  delete config.logging;
}
const conn = new Sequelize(
  process.env.DATABASE_URL || 'postgres://localhost/acme_db',
  config
);

const User = conn.define('user', {
  username: STRING,
  password: STRING,
});

const Note = conn.define('note', {
  text: STRING,
});

User.byToken = async (token) => {
  try {
    const decodedId = await jwt.verify(token, 'superSecret');
    const user = await User.findByPk(decodedId.userId);
    if (user) {
      return user;
    }
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  } catch (ex) {
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
};

User.authenticate = async ({ username, password }) => {
  const user = await User.findOne({
    where: {
      username,
    },
  });
  const hashedPassword = user.password;
  if (bcrypt.compareSync(password, hashedPassword)) {
    const token = await jwt.sign({ userId: user.id }, 'superSecret');
    return token;
  }
  const error = Error('bad credentials');
  error.status = 401;
  throw error;
};

User.beforeCreate(async (user) => {
  const salt = bcrypt.genSaltSync(saltRounds);
  const hash = bcrypt.hashSync(user.password, salt);
  user.password = hash;
});

Note.belongsTo(User);
User.hasMany(Note);

const syncAndSeed = async () => {
  await conn.sync({ force: true });

  const credentials = [
    { username: 'lucy', password: 'lucy_pw' },
    { username: 'moe', password: 'moe_pw' },
    { username: 'larry', password: 'larry_pw' },
  ];

  const notes = [
    { text: 'Hello world' },
    { text: 'Something here' },
    { text: 'Hello world 2' },
    { text: 'Hello world 3' },
  ];

  const [note1, note2, note3, note4] = await Promise.all(
    notes.map((note) => {
      Note.create(note);
    })
  );

  const [lucy, moe, larry] = await Promise.all(
    credentials.map((credential) => {
      User.create(credential);
    })
  );

  return {
    users: {
      lucy,
      moe,
      larry,
    },
    notes: {
      note1,
      note2,
      note3,
      note4,
    },
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User,
    Note,
  },
};
