import Database from 'better-sqlite3';
import crypto from 'node:crypto';

export const LicenseStore = {
  async init() {
    const dbPath = process.env.SQLITE_DB || 'server/data/licenses.db';
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');

    db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  pwHash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS licenses (
  key TEXT PRIMARY KEY,
  userId TEXT NOT NULL,
  status TEXT NOT NULL,
  plan TEXT NOT NULL,
  seats INTEGER NOT NULL DEFAULT 1,
  expireAt INTEGER NOT NULL,
  scopes TEXT NOT NULL,
  FOREIGN KEY(userId) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS revocations (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL, -- 'license' or 'jti'
  target TEXT NOT NULL,
  ts INTEGER NOT NULL
);
`);

    // seed if empty
    const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
    if (!userCount) {
      const userId = crypto.randomUUID();
      db.prepare('INSERT INTO users(id,username,pwHash) VALUES(?,?,?)').run(userId,'alice', hashPw('password123'));
      db.prepare('INSERT INTO licenses(key,userId,status,plan,seats,expireAt,scopes) VALUES(?,?,?,?,?,?,?)')
        .run('LIC-TRIAL-123', userId, 'active', 'trial', 5, Date.now()+30*24*3600*1000, JSON.stringify(['rpc:invoke','module:get','module:get:analytics','module:get:pricing']));
    }

    function hashPw(pw){ return 'sha256$'+crypto.createHash('sha256').update(pw).digest('hex'); }
    function verifyPw(pw, digest){ return hashPw(pw) === digest; }

    function checkPassword(username, password) {
      const row = db.prepare('SELECT * FROM users WHERE username=?').get(username);
      if (!row || !verifyPw(password, row.pwHash)) throw new Error('Invalid credentials');
      return { id: row.id, username: row.username };
    }

    function listUserLicenses(userId) {
      return db.prepare('SELECT key, plan, status, expireAt, scopes FROM licenses WHERE userId=?').all(userId)
        .map(r => ({ key: r.key, plan: r.plan, status: r.status, expireAt: r.expireAt, scopes: JSON.parse(r.scopes) }));
    }

    function checkLicenseForUser(key, userId) {
      const r = db.prepare('SELECT * FROM licenses WHERE key=? AND userId=?').get(key, userId);
      if (!r) throw new Error('License not found for user');
      if (r.status !== 'active') throw new Error('License inactive');
      if (r.expireAt <= Date.now()) throw new Error('License expired');
      return r;
    }

    function isRevoked(target) {
      const r = db.prepare('SELECT 1 FROM revocations WHERE target=? LIMIT 1').get(target);
      return !!r;
    }

    function revokeLicense(key) {
      const exists = db.prepare('SELECT 1 FROM licenses WHERE key=?').get(key);
      if (!exists) throw new Error('Unknown license');
      db.prepare('INSERT OR IGNORE INTO revocations(id,type,target,ts) VALUES(?,?,?,?)')
        .run(crypto.randomUUID(),'license',key,Date.now());
      db.prepare('UPDATE licenses SET status=? WHERE key=?').run('revoked', key);
    }


    function createUser(username, password) {
      const exists = db.prepare('SELECT 1 FROM users WHERE username=?').get(username);
      if (exists) {
        const row = db.prepare('SELECT id FROM users WHERE username=?').get(username);
        return { id: row.id, created: false };
      }
      const id = crypto.randomUUID();
      db.prepare('INSERT INTO users(id,username,pwHash) VALUES(?,?,?)').run(id, username, hashPw(password));
      return { id, created: true };
    }

    function claimLicense(key, userId) {
      const lic = db.prepare('SELECT key FROM licenses WHERE key=?').get(key);
      if (!lic) throw new Error('Unknown license');
      db.prepare('UPDATE licenses SET userId=? WHERE key=?').run(userId, key);
      return true;
    }

    return { checkPassword, listUserLicenses, checkLicenseForUser, isRevoked, revokeLicense, createUser, claimLicense, db };
  }
};
