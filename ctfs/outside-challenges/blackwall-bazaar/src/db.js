const { MongoClient } = require('mongodb');

const MONGO_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017';
const DB_NAME = process.env.DB_NAME || 'blackwall';

let _db = null;

async function connect() {
  if (_db) return _db;
  const client = new MongoClient(MONGO_URL);
  await client.connect();
  _db = client.db(DB_NAME);
  return _db;
}

function db() {
  if (!_db) throw new Error('db not connected yet');
  return _db;
}

module.exports = { connect, db };
