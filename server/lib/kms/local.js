import { generateKeyPair } from 'jose';
import { exportSPKI } from 'jose';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'node:crypto';

export const LocalKms = {
  async init() {
    let current = null;
    async function rotateEd25519() {
      const { publicKey, privateKey } = await generateKeyPair('Ed25519');
      const pubSpkiPem = await exportSPKI(publicKey);
      const kid = 'ed25519-' + uuidv4();
      current = { kid, alias: kid, pubSpkiPem, privateKey };
      return current;
    }
    async function signEd25519(alias, bytes) {
      if (!current || alias !== current.alias) throw new Error('Alias not found');
      return crypto.sign(null, Buffer.from(bytes), current.privateKey);
    }
    return { rotateEd25519, signEd25519 };
  }
};
