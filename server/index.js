import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import https from 'node:https';
import http2 from 'node:http2';
import { WebSocketServer } from 'ws';
import { v4 as uuidv4 } from 'uuid';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import dotenv from 'dotenv';
import { KeyManager } from './lib/keyManager.js';
import { LicenseStore } from './lib/licenseStore.js';
import { RateLimiter } from './lib/rateLimiter.js';
import { CircuitBreaker } from './lib/circuitBreaker.js';
import { ModuleRegistry } from './lib/moduleRegistry.js';
import { TokenService } from './lib/tokenService.js';

dotenv.config();

const CONFIG = {
  host: process.env.HOST || '127.0.0.1',
  port: Number(process.env.PORT || 8443),
  protocolVersion: '1.1',
  skewMs: 60_000,
  msgSizeCap: 64 * 1024,
  rotateHintSec: 600,
  moduleBindMaxMs: 60_000,
};

/* string packer start */

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
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === 'object' && v.constructor === Object) {
      return Object.keys(v).sort().reduce((acc, k) => { acc[k]=sort(v[k]); return acc; }, {});
    }
    return v;
  };
  return JSON.stringify(sort(obj));
}
const nowMs = () => Date.now();
const b64 = (b) => Buffer.from(b).toString('base64');
const b64ToBuf = (s) => Buffer.from(s, 'base64');
const assert = (c,m='Assertion failed') => { if(!c) throw new Error(m); };

// ---- Audit log ----
const AUDIT_LOG_PATH = path.resolve('server/audit.log');
let lastAuditHashHex = '';
if (fs.existsSync(AUDIT_LOG_PATH)) {
  const lines = fs.readFileSync(AUDIT_LOG_PATH,'utf8').trim().split(/\r?\n/);
  const last = lines.at(-1);
  if (last) lastAuditHashHex = JSON.parse(last).hash;
}
function auditAppend(record) {
  const base = { ts: new Date().toISOString(), ...record };
  const prev = lastAuditHashHex;
  const h = crypto.createHash('sha256');
  h.update(prev + canonical(base));
  const hash = h.digest('hex');
  lastAuditHashHex = hash;
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify({ ...base, prev, hash }) + '\n', 'utf8');
}

// ---- TLS servers ----
const tls = {
  key: fs.readFileSync(process.env.TLS_KEY || 'certs/server.key'),
  cert: fs.readFileSync(process.env.TLS_CERT || 'certs/server.crt'),
  allowHTTP1: true,
  honorCipherOrder: true,
  minVersion: 'TLSv1.3',
};
const h2 = http2.createSecureServer(tls);
const httpsServer = https.createServer(tls, (req, res) => {
  res.setHeader('Strict-Transport-Security','max-age=63072000; includeSubDomains; preload');
  res.writeHead(200);
  if (req.url === '/metrics') { try { const m = keyManager.metrics; res.writeHead(200, {'Content-Type':'text/plain'}); res.end(`kms_sign_count ${m.kms_sign_count}\n`+`kms_rotate_count ${m.kms_rotate_count}\n`); } catch { res.writeHead(500); res.end('metrics_error'); } return; } res.end('WS Auth Pro server online\n');
});

setInterval(()=>{ try { keyManager.rotateIfNeeded && keyManager.rotateIfNeeded(); } catch(e){} }, 60_000);
httpsServer.listen(CONFIG.port, CONFIG.host, ()=>{
  console.log(`HTTPS/WSS on wss://${CONFIG.host}:${CONFIG.port}`);
});

const wss = new WebSocketServer({ server: httpsServer, maxPayload: CONFIG.msgSizeCap });

// ---- Schemas ----
const ajv = new Ajv({ strict: true, removeAdditional:'failing', allErrors: true });
addFormats(ajv);
const Header = {
  type:'object', required:['msgId','nonce','ts','typ','ver'],
  properties:{ msgId:{type:'string'}, nonce:{type:'string'}, ts:{type:'integer'}, typ:{type:'string'}, ver:{const:CONFIG.protocolVersion} },
  additionalProperties:true
};
const LoginReqSchema = { allOf:[ Header, { type:'object', required:['username','password','deviceInfo'],
  properties:{ typ:{const:'login'}, username:{type:'string'}, password:{type:'string'},
    deviceInfo:{ type:'object', required:['os','arch','appVer','hwHash'], additionalProperties:false,
      properties:{ os:{type:'string'}, arch:{type:'string'}, appVer:{type:'string'}, hwHash:{type:'string'} } } } } ] };
const ActivateReqSchema = { allOf:[ Header, { type:'object', required:['licenseKey','machineId','token'],
  properties:{ typ:{const:'activate'}, licenseKey:{type:'string'}, machineId:{type:'string'}, token:{type:'string'} } } ] };
const RpcReqSchema = { allOf:[ Header, { type:'object', required:['token','method'], properties:{ typ:{const:'rpc'}, token:{type:'string'}, method:{type:'string'}, params:{} } } ] };
const GetModuleReqSchema = { allOf:[ Header, { type:'object', required:['token','clientPubX25519Pem','bind','moduleId'],
  properties:{ typ:{const:'get_module'}, token:{type:'string'}, clientPubX25519Pem:{type:'string'}, moduleId:{type:'string'},
    bind:{ type:'object', required:['exp','watermark'], additionalProperties:false, properties:{ exp:{type:'integer'}, watermark:{type:'string'} } } } } ] };

const validate = {
  login: ajv.compile(LoginReqSchema),
  activate: ajv.compile(ActivateReqSchema),
  rpc: ajv.compile(RpcReqSchema),
  getModule: ajv.compile(GetModuleReqSchema),
};

// ---- Services ----
const keyManager = await KeyManager.init();
const licenseStore = await LicenseStore.init();
const rateLimiter = await RateLimiter.init();
const breaker = CircuitBreaker.create();
const tokenService = TokenService.create(keyManager);

// ---- WS ----
wss.on('connection', async (ws, req) => {
  const ip = req.socket.remoteAddress;
  const hello = {
    typ:'hello', ver:CONFIG.protocolVersion, ts: nowMs(),
    ed25519PublicKeyB64: await keyManager.getActivePublicSPKIb64(),
    modules: ModuleRegistry.listModules(),
    proto:'1.1'
  };
  ws.send(JSON.stringify(hello));

  ws.on('message', async (raw) => {
    let obj; try { obj = JSON.parse(raw.toString('utf8')); } catch { return sendErr('bad_json','Invalid JSON'); }
    function sendErr(code,message){ ws.send(JSON.stringify({ msgId: uuidv4(), nonce: uuidv4(), ts: nowMs(), ver: CONFIG.protocolVersion, typ:'error', code, message })); }

    try {
      if (raw.length > CONFIG.msgSizeCap) return sendErr('too_large','Message too large');
      assert(obj.ver === CONFIG.protocolVersion, 'Bad protocol version');

      // rate limit by IP pre-check (lightweight)
      await rateLimiter.allow(`ip:${ip}`, 1);

      switch (obj.typ) {

        case 'login': {
          if (!validate.login(obj)) throw new Error('Schema validation failed (login)');
          const key = `act:${ip}:${obj.username}`;
          if (breaker.blocked(key)) throw new Error('Temporarily blocked, try later');

          try {
            const user = licenseStore.checkPassword(obj.username, obj.password);
            const tok = await tokenService.issueLogin(user.id, obj.deviceInfo);
            auditAppend({ actor: obj.username, action:'login_ok' });
            const res = { msgId: uuidv4(), nonce: obj.nonce, ts: nowMs(), ver: CONFIG.protocolVersion, typ:'login_ok',
              token: tok, rotateAfter: 900, licenses: licenseStore.listUserLicenses(user.id) };
            ws.send(JSON.stringify(res));
          } catch (e) {
            breaker.fail(key);
            throw e;
          }
          break;
        }

        case 'activate': {
          if (!validate.activate(obj)) throw new Error('Schema validation failed (activate)');
          const { payload } = await tokenService.verifyLogin(obj.token);
          // license must belong to user
          licenseStore.checkLicenseForUser(obj.licenseKey, payload.sub);
          // rate limit by compound
          await rateLimiter.allow(`ip:${ip}:lic:${obj.licenseKey}`, 1);
          const tok = await tokenService.issueLicense(obj.licenseKey, obj.machineId);
          auditAppend({ actor: obj.licenseKey, action:'activate', meta:{ user: payload.sub, machineId: obj.machineId } });
          const res = { msgId: uuidv4(), nonce: obj.nonce, ts: nowMs(), ver: CONFIG.protocolVersion, typ:'activated',
            token: tok, exp: Math.floor(Date.now()/1000)+15*60,
            ed25519PublicKeyB64: await keyManager.getActivePublicSPKIb64(), rotateAfter: 600 };
          ws.send(JSON.stringify(res));
          break;
        }

        case 'rpc': {
          if (!validate.rpc(obj)) throw new Error('Schema validation failed (rpc)');
          const { payload } = await tokenService.verifyLicense(obj.token);
          await rateLimiter.allow(`ip:${ip}:lic:${payload.sub}`, 1);
          assert(payload.scopes?.includes('rpc:invoke'), 'Missing scope rpc:invoke');
          const result = ModuleRegistry.dispatchRpc(obj.method, obj.params);
          const response = { msgId: uuidv4(), nonce: obj.nonce, ts: nowMs(), ver: CONFIG.protocolVersion, typ:'rpc_result', result };
          const pay = canonical({ method: obj.method, result, nonce: response.nonce, ts: response.ts });
          const sig = await keyManager.sign(Buffer.from(pay,'utf8'),'rpc_envelope');
          response.sigB64 = Buffer.from(sig).toString('base64');
          response.kid = (await keyManager.getActive()).kid;
          auditAppend({ actor: payload.sub, action:'rpc', meta:{ method: obj.method } });
          ws.send(JSON.stringify(response));
          break;
        }

        case 'get_module': {
          if (!validate.getModule(obj)) throw new Error('Schema validation failed (get_module)');
          const { payload } = await tokenService.verifyLicense(obj.token);
          await rateLimiter.allow(`ip:${ip}:lic:${payload.sub}`, 1);
          assert(payload.scopes?.includes('module:get:'+obj.moduleId) || payload.scopes?.includes('module:get'), 'Missing scope');
          assert(obj.bind.exp > nowMs(), 'bind.exp must be future');
          assert(obj.bind.exp - nowMs() <= CONFIG.moduleBindMaxMs, 'bind window too large');

          // ephemeral X25519
          const { privateKey: serverPriv, publicKey: serverPub } = crypto.generateKeyPairSync('x25519');
          const serverPubPem = serverPub.export({ type:'spki', format:'pem' });

          const bytes = ModuleRegistry.loadCompiled(obj.moduleId); // .jsc or .node bytes
          const watermark = `sub:${payload.sub}|machine:${payload.machineId||'na'}|nonce:${obj.nonce}`;
          const wmSalt = crypto.randomBytes(16).toString('base64');

          // Advanced watermark prelude: include hashes and signed block
          const wmBlock = JSON.stringify({ watermark, exp: obj.bind.exp, nonce: obj.nonce });
          const wmHash = crypto.createHash('sha256').update(`${watermark}|${obj.bind.exp}|${obj.nonce}`).digest('hex');
          const modHash = crypto.createHash('sha256').update(bytes).digest('hex');
          const wmSigRaw = await keyManager.sign(Buffer.from(wmBlock,'utf8'));
          const wmSigB64 = Buffer.from(wmSigRaw).toString('base64');
          const prelude = Buffer.from(
            packString([
              `/*wmHash:${wmHash}*/`,
              `/*wmSigB64:${wmSigB64}*/`,
              `/*wmBlock:${wmBlock}*/`,
              `/*modHash:${modHash}*/`,
              `/*watermark:${watermark};exp:${obj.bind.exp};nonce:${obj.nonce}*/`,
              `/*wm_salt:${wmSalt}*/`,
              `/*wm_hmac:${wmInner}*/`,
              `/*__WM_END__*/`
            ].join('\n') + '\n'),
          'utf8');
          const boundBytes = Buffer.concat([prelude, bytes]);

          const secret = crypto.diffieHellman({ privateKey: serverPriv, publicKey: crypto.createPublicKey(obj.clientPubX25519Pem) });
          const key = crypto.hkdfSync('sha256', secret, Buffer.from('mod_v2'), Buffer.alloc(0), 32);
          const iv = crypto.randomBytes(12);
          const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
          const ct = Buffer.concat([cipher.update(boundBytes), cipher.final()]);
          const tag = cipher.getAuthTag();
          const enc = { iv: b64(iv), ciphertext: b64(Buffer.concat([ct, tag])) };

          const { kid } = await keyManager.getActive();
          const payloadSig = JSON.stringify({ enc, bind: obj.bind, serverPubX25519: serverPubPem }, Object.keys({enc:1, bind:1, serverPubX25519:1}).sort());
          const envSig = await keyManager.sign(Buffer.from(payloadSig,'utf8'));

          const res = { msgId: uuidv4(), nonce: obj.nonce, ts: nowMs(), ver: CONFIG.protocolVersion, typ:'module',
            moduleId: obj.moduleId, enc, envSigB64: Buffer.from(envSig).toString('base64'),
            serverKeys: { pubX25519Pem: serverPubPem, kid, ed25519PublicKeyB64: await keyManager.getActivePublicSPKIb64() } };
          auditAppend({ actor: payload.sub, action:'module_delivered', meta:{ module: obj.moduleId } });
          ws.send(JSON.stringify(res));
          break;
        }

        default:
          return sendErr('bad_type','Unsupported typ');
      }

    } catch (e) {
      ws.send(JSON.stringify({ msgId: uuidv4(), nonce: uuidv4(), ts: nowMs(), ver: CONFIG.protocolVersion, typ:'error', code:'bad_request', message: e.message }));
    }
  });
});
