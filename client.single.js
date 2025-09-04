import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { WebSocket } from 'ws';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
dotenv.config();

const CONFIG = {
  url: process.env.URL || `wss://${process.env.HOST||'127.0.0.1'}:${process.env.PORT||8443}`,
  protocolVersion: '1.1',
  username: process.env.USERNAME || 'alice',
  password: process.env.PASSWORD || 'password123',
  machineId: hash(`${os.platform()}|${os.arch()}|${os.hostname()}`),
  pinPath: './client.pin',
  tokenLoginPath: './client.login.token',
  tokenLicPath: './client.lic.token',
  bindWindowMs: 60_000,
  caPath: process.env.CLIENT_CA || '' // path to CA bundle if not system
};

function mulberry32(seed) {
  return function() {
    let t = seed += 0x6D2B79F5;
    t = Math.imul(t ^ t >>> 15, t | 1);
    t ^= t + Math.imul(t ^ t >>> 7, t | 61);
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}

function choice(rng, arr) {
  return arr[Math.floor(rng() * arr.length)];
}
function randBool(rng, p = 0.5) {
  return rng() < p;
}
function randInt(rng, min, max) {
  return Math.floor(rng() * (max - min + 1)) + min;
}

// ---------- Safe Eval ----------
function safeEval(expr) {
  try {
    // eslint-disable-next-line no-new-func
    return Function(`"use strict"; return (${expr});`)();
  } catch {
    return Symbol("BAD");
  }
}

// ---------- Wrapper Checker ----------
function wrapChecked(expr, rng, target) {
  const candidates = [
    e => `+( ${e} )`,
    e => `((${e}) ^ 0)`,
    e => `((()=>(${e}))())`,
    e => `(!![] ? ${e} : ${e})`,
    e => `(0, ${e})`,
    e => `(~[] + 1 ? ${e} : ${e})`,
    e => `(function(){ return ${e}; })()`
  ];

  for (const wrap of candidates) {
    if (randBool(rng, 0.3)) {
      const candidate = wrap(expr);
      const val = safeEval(`(${candidate})|0`);
      if (val === target) expr = candidate;
    }
  }
  return expr;
}

// ---------- Schema Wrapper ----------
function wrapSchema(fn) {
  return (n, rng, depth = 0, maxDepth = 3) => {
    const expr = fn(n, rng, depth, maxDepth);
    if (!expr) return null;
    const val = safeEval(`(${expr})|0`);
    return val === n ? expr : null;
  };
}

// ---------- Schemas ----------
function schema_addSub(n, rng, depth, maxDepth) {
  const a = randInt(rng, -0x7fffffff, 0x7fffffff);
  const b = n - a;
  return `${emitSub(a, rng, depth, maxDepth)} + ${emitSub(b, rng, depth, maxDepth)}`;
}

function schema_xorCancel(n, rng, depth, maxDepth) {
  const mask = randInt(rng, -0x7fffffff, 0x7fffffff);
  const part = n ^ mask;
  return `(${emitSub(part, rng, depth, maxDepth)} ^ ${emitSub(mask, rng, depth, maxDepth)})`;
}

function schema_pow2Offset(n, rng, depth, maxDepth) {
  const p = Math.max(1, Math.floor(Math.log2(Math.max(2, Math.abs(n)))));
  const base = 1 << p;
  const off = n - base;
  return `${emitSub(base, rng, depth, maxDepth)} + ${emitSub(off, rng, depth, maxDepth)}`;
}

function schema_bitmaskSplit(n, rng, depth, maxDepth) {
  const hi = n & 0xffff0000;
  const lo = n & 0x0000ffff;
  return `${emitSub(hi, rng, depth, maxDepth)} | ${emitSub(lo, rng, depth, maxDepth)}`;
}

function schema_nybbleRecompose(n, rng, depth, maxDepth) {
  const parts = [];
  for (let i = 0; i < 8; i++) {
    const nibble = (n >> (i * 4)) & 0xf;
    parts.push(`${emitSub(nibble, rng, depth, maxDepth)} << ${i * 4}`);
  }
  return parts.join(" | ");
}

function schema_rotateLike(n, rng, depth, maxDepth) {
  const shift = randInt(rng, 1, 31);
  const expr = `((${emitSub(n >>> shift, rng, depth, maxDepth)}) << ${shift}) | ${n & ((1 << shift) - 1)}`;
  return expr;
}

function schema_parseIntRadix(n, rng, depth, maxDepth) {
  const radix = randInt(rng, 2, 36);
  const str = Math.abs(n).toString(radix);
  const baseExpr = `parseInt("${str}", ${radix})`;
  return n < 0 ? `-${baseExpr}` : baseExpr;
}

// ---------- Recursive Helper ----------
function emitSub(n, rng, depth, maxDepth) {
  if (depth >= maxDepth) return `${n}`;
  return emitNumber(n, rng, depth + 1, maxDepth);
}

// ---------- Emitter Core ----------
function emitNumber(n, rng, depth = 0, maxDepth = 8) {
  const schemas = [
    wrapSchema(schema_addSub),
    wrapSchema(schema_xorCancel),
    wrapSchema(schema_pow2Offset),
    wrapSchema(schema_bitmaskSplit),
    wrapSchema(schema_nybbleRecompose),
    wrapSchema(schema_rotateLike),
    wrapSchema(schema_parseIntRadix)
  ];

  // randomly shuffle schema order
  const pool = schemas.slice().sort(() => rng() - 0.5);

  while (pool.length) {
    const schema = pool.pop();
    const expr = schema(n, rng, depth, maxDepth);
    if (expr != null) {
      let wrapped = wrapChecked(expr, rng, n);
      wrapped = `((${wrapped})|0)`;
      if (safeEval(wrapped) === n) {
        return wrapped;
      }
    }
  }
  throw new Error("No valid schema found for " + n);
}


// ---------- Validator ----------
function validate(n, rng) {
  const expr = emitNumber(n, rng);
  const val = safeEval(expr);
  if (val !== n) {
    return validate(n, rng())
  }
  return expr;
}

function packString( str) {
	let newStr = "(()=>{ return [";
	for (let i = 0; i < str.length; i++){
		newStr += validate(str.charCodeAt(i), mulberry32(Math.random()%10000000000|0))+","
	};
	newStr+= "].map(s=>String.fromCharCode(s)).join('');})()";
	return newStr;
}

/* String packer end */

function canonical(obj) {
  const sort = (v) => Array.isArray(v) ? v.map(sort) :
    (v && typeof v==='object' && v.constructor===Object ? Object.keys(v).sort().reduce((a,k)=>{a[k]=sort(v[k]);return a;},{}) : v);
  return JSON.stringify(sort(obj));
}
const nowMs = ()=>Date.now();
const b64 = (b)=>Buffer.from(b).toString('base64');
const b64ToBuf = (s)=>Buffer.from(s,'base64');
function hash(s){ return crypto.createHash('sha256').update(s).digest('hex'); }
function header(typ){ return { msgId: uuidv4(), nonce: uuidv4(), ts: nowMs(), typ, ver: CONFIG.protocolVersion }; }

const PinStore = {
  ensurePinned(pubB64){
    if (!fs.existsSync(CONFIG.pinPath)) fs.writeFileSync(CONFIG.pinPath, pubB64,'utf8');
    const curr = fs.readFileSync(CONFIG.pinPath,'utf8').trim();
    if (curr !== pubB64) throw new Error('Pinned key mismatch');
  },
  get(){ return fs.existsSync(CONFIG.pinPath) ? fs.readFileSync(CONFIG.pinPath,'utf8').trim() : null; }
};

async function verifyServerSig(pinnedSpkiB64, kid, payloadStr, sigB64) {
  const spkiPem = Buffer.from(pinnedSpkiB64,'base64').toString('utf8');
  const pubKey = crypto.createPublicKey(spkiPem);
  return crypto.verify(null, Buffer.from(payloadStr,'utf8'), pubKey, Buffer.from(sigB64,'base64'));
}

async function run() {
  const ws = new WebSocket(CONFIG.url, {
    // Do NOT disable verification. Use system CAs plus optional custom CA.
    ca: CONFIG.caPath && fs.existsSync(CONFIG.caPath) ? fs.readFileSync(CONFIG.caPath) : undefined
  });

  const pending = new Map();
  let pinned = PinStore.get();
  let loginTok = fs.existsSync(CONFIG.tokenLoginPath) ? fs.readFileSync(CONFIG.tokenLoginPath,'utf8') : null;
  let licTok = fs.existsSync(CONFIG.tokenLicPath) ? fs.readFileSync(CONFIG.tokenLicPath,'utf8') : null;
  let modules = [];

  ws.on('message', async (raw)=>{
    const msg = JSON.parse(raw.toString('utf8'));
    if (msg.typ === 'hello') {
      console.log('[hello]', msg);
      PinStore.ensurePinned(msg.ed25519PublicKeyB64);
      pinned = msg.ed25519PublicKeyB64;
      modules = msg.modules || [];
      // optional register
      await registerIfNeeded(ws);
      // login
      await ensureLogin(ws);
      // choose a license and activate
      const lic = await chooseLicense(ws);
      await activate(ws, lic.key);
      // choose module (env MODULE_ID or first)
      const moduleId = process.env.MODULE_ID || modules[0] || 'analytics';
      console.log('Loading module:', moduleId);
      const mod = await fetchModule(ws, moduleId);
      // Load encrypted, signed bytenode module (.jsc) from temp
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(),'mod-'));
      const encPath = path.join(tmpDir, moduleId+'.jsc');
      fs.writeFileSync(encPath, mod.bytes);
      const bytenode = await import('bytenode');
      const loaded = await import(pathToFileURL(encPath).href);
      //console.log('[module loaded] keys:', Object.keys(loaded));
	  try {
		  await loaded.run( sendAndWait, { userId: (loadCreds().userId||null), username: (loadCreds().username||CONFIG.username), machineId: CONFIG.machineId, licenseKey: process.env.LICENSE_KEY||null });
	  } catch (err){
		  throw new Error(err);
		  process.exit(1);
	  }
      ws.close();
      return;
    }
    const res = pending.get(msg.msgId);
    if (res) { pending.delete(msg.msgId); res(msg); }
  });
  ws.on('open', ()=>console.log('WS open'));
  ws.on('error', (e)=>console.error('WS error', e));
  ws.on('close', ()=>console.log('WS closed'));

  function sendAndWait(obj, expectTyp){
    return new Promise((resolve, reject)=>{
      const id = obj.msgId;
      pending.set(id, (msg)=>{
        if (expectTyp && msg.typ !== expectTyp) return reject(new Error(`Unexpected ${msg.typ}`));
        resolve(msg);
      });
      ws.send(JSON.stringify(obj));
      setTimeout(()=>{ if (pending.has(id)){ pending.delete(id); reject(new Error('Timeout')); } }, 15000);
    });
  }

  async function ensureLogin(ws) {
    if (loginTok) return;
    // Try saved token
    let savedTok; try { savedTok = fs.readFileSync(CONFIG.tokenLoginPath,'utf8'); } catch {}
    const saved = loadCreds();
    const keyHash = saved.keyHash || (process.env.LICENSE_KEY ? keyHashFor(process.env.LICENSE_KEY) : undefined);
    if (savedTok) {
      try {
        const res = await sendAndWait({ ...header('login_token'), token: savedTok, keyHash }, 'login_ok');
        loginTok = res.token; fs.writeFileSync(CONFIG.tokenLoginPath, loginTok);
        saveCreds({ userId: res.userId, username: res.username, keyHash });
        console.log('[auth] resumed via saved token');
        return;
      } catch {}
    }

    if (loginTok) return;
    const msg = { ...header('login'), username: CONFIG.username, password: CONFIG.password, keyHash, deviceInfo:{
      os: os.platform(), arch: os.arch(), appVer: '2.0.0', hwHash: hash(os.cpus().map(c=>c.model).join('|'))
    }};
    const res = await sendAndWait(msg, 'login_ok');
    loginTok = res.token;
    fs.writeFileSync(CONFIG.tokenLoginPath, loginTok);
    saveCreds({ userId: res.userId, username: res.username, keyHash });
    console.log('Licenses:', res.licenses);
  }

  
  async function registerIfNeeded(ws) {
    if (!process.env.REGISTER) return;
    const key = process.env.LICENSE_KEY;
    if (!key) throw new Error('LICENSE_KEY required for register');
    const keyHash = keyHashFor(key);
    const msg = { ...header('register'), username: CONFIG.username, password: CONFIG.password, licenseKey: key, keyHash };
    const res = await sendAndWait(msg, 'login_ok');
    loginTok = res.token;
    fs.writeFileSync(CONFIG.tokenLoginPath, loginTok);
    saveCreds({ userId: res.userId, username: res.username, keyHash });
    console.log('[register] completed');
  }

  async function chooseLicense(ws) {
    // For demo pick first license from server via login_ok response…
    // If not available, re-login to fetch list
    if (!loginTok) await ensureLogin(ws);
    // Request not necessary; we cached from hello handler via login_ok.
    // Here we assume server seeded one license.
    return { key: process.env.LICENSE_KEY || 'LIC-TRIAL-123' };
  }

  async function activate(ws, licenseKey) {
    const msg = { ...header('activate'), licenseKey, machineId: CONFIG.machineId, token: loginTok };
    const res = await sendAndWait(msg, 'activated');
    licTok = res.token;
    fs.writeFileSync(CONFIG.tokenLicPath, licTok);
  }

  async function fetchModule(ws, moduleId) {
    // X25519 ephemeral
    const { privateKey: clientPriv, publicKey: clientPub } = crypto.generateKeyPairSync('x25519');
    const clientPubPem = clientPub.export({ type:'spki', format:'pem' });
    const bind = { exp: nowMs() + CONFIG.bindWindowMs, watermark, keyHash: (loadCreds().keyHash || (process.env.LICENSE_KEY ? keyHashFor(process.env.LICENSE_KEY) : undefined)): `lic:${process.env.LICENSE_KEY||'LIC-TRIAL-123'}|mac:${CONFIG.machineId}` };
    const msg = { ...header('get_module'), token: licTok, clientPubX25519Pem: clientPubPem, bind, moduleId };
    const res = await sendAndWait(msg, 'module');
    // verify envelope
    const payloadStr = JSON.stringify({ enc: res.enc, bind, serverPubX25519: res.serverKeys.pubX25519Pem }, Object.keys({enc:1,bind:1,serverPubX25519:1}).sort());
    const ok = await verifyServerSig(pinned, res.serverKeys.kid, payloadStr, res.envSigB64);
    if (!ok) throw new Error('Bad server signature on module envelope');
    // decrypt
    const serverPub = crypto.createPublicKey(res.serverKeys.pubX25519Pem);
    const secret = crypto.diffieHellman({ privateKey: clientPriv, publicKey: serverPub });
    const key = crypto.hkdfSync('sha256', secret, Buffer.from('mod_v2'), Buffer.alloc(0), 32);
    const iv = Buffer.from(res.enc.iv,'base64');
    const ctFull = Buffer.from(res.enc.ciphertext,'base64');
    const ct = ctFull.slice(0, ctFull.length-16);
    const tag = ctFull.slice(ctFull.length-16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    // --- Advanced Watermark Checks ---
    const sutf8 = plain.toString('utf8');
	
	sutf8 = (new Function(sutf8))(); // returns a string from an expession.
	
    // 0) Basic presence
    if (!sutf8.includes(bind.watermark)) throw new Error('Watermark missing');
    if (!sutf8.includes(String(bind.exp))) throw new Error('Expiration missing');
    if (!sutf8.includes(msg.msgId)) throw new Error('Nonce mismatch');

    // 1) Parse prelude fields
    function extract(tag){
      const m = sutf8.match(new RegExp(String.raw`/\*${tag}:([^*]+)\*/`));
      return m ? m[1].trim() : null;
    }
    const wmHash = extract('wmHash');
    const wmSigB64 = extract('wmSigB64');
    const wmBlockRaw = extract('wmBlock');
    const modHash = extract('modHash');

    if (!wmHash || !wmSigB64 || !wmBlockRaw || !modHash) {
      throw new Error('Watermark prelude fields missing');
    }

    // 2) Recompute hash and compare
    const recomputedHash = crypto.createHash('sha256')
      .update(`${bind.watermark}|${bind.exp}|${msg.msgId}`)
      .digest('hex');
    if (wmHash !== recomputedHash) throw new Error('Watermark hash mismatch');

    // 3) Verify signature over wmBlock using pinned Ed25519
    const okSig = await verifyServerSig(pinned, res.serverKeys.kid, wmBlockRaw, wmSigB64);
    if (!okSig) throw new Error('Watermark signature invalid');

    // 4) Verify module hash (over full decrypted bytes minus prelude)
    const endIdx = sutf8.indexOf('/*__WM_END__*/');
    if (endIdx === -1) throw new Error('Watermark delimiter missing');
    const headerUtf8 = sutf8.slice(0, endIdx + '/*__WM_END__*/'.length + 1); // include newline
    const bodyBytes = plain.slice(Buffer.from(headerUtf8, 'utf8').length);
    const bodyHash = crypto.createHash('sha256').update(bodyBytes).digest('hex');
    if (bodyHash !== modHash) throw new Error('Module integrity mismatch');

    // 5) Expiration enforcement
    if (Date.now() > bind.exp) throw new Error('Module expired');


    // strong watermark checks
    const s = plain.toString('utf8');
    const wm = /\/\*watermark:([^*]+)\*\//.exec(s);
    const wmSalt = /\/\*wm_salt:([^*]+)\*\//.exec(s);
    const wmHmac = /\/\*wm_hmac:([^*]+)\*\//.exec(s);
    if (!wm || !wmSalt || !wmHmac) throw new Error('Watermark fields missing');
    const keyHash = (loadCreds().keyHash || (process.env.LICENSE_KEY ? hash(process.env.LICENSE_KEY) : ''));
    const perClientKey = crypto.hkdfSync('sha256', Buffer.from(keyHash,'hex'), Buffer.from('wm:'+bind.watermark), Buffer.from('wm_v1'), 32);
    const modBody = bytes; // original bytes (unmodified)
    const expHmac = crypto.createHmac('sha256', perClientKey).update(modBody).update(Buffer.from(wm[1])).digest('base64');
    if (expHmac !== wmHmac[1]) throw new Error('Watermark HMAC mismatch');
    return { bytes: plain };
  }
}

import { pathToFileURL } from 'url';
run().catch(e=>{ console.error('Client error:', e); process.exit(1); });

  function loadCreds() {
    try { return JSON.parse(fs.readFileSync(CONFIG.credsPath,'utf8')); } catch { return {}; }
  }
  function saveCreds(obj) {
    const cur = loadCreds();
    fs.writeFileSync(CONFIG.credsPath, JSON.stringify({ ...cur, ...obj }, null, 2));
  }
  function keyHashFor(key) { return hash(String(key||'')); }
