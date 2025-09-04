import fs from 'node:fs';
import path from 'node:path';

const MODULES = {
  analytics: 'server/modules/analytics.jsc',
  pricing: 'server/modules/pricing.jsc',
  scoring: 'server/modules/scoring.jsc',
  mineflayerBot: 'server/modules/mineflayerBot.jsc'
};

export const ModuleRegistry = {
  listModules() {
    return Object.keys(MODULES);
  },
  loadCompiled(moduleId) {
    const p = MODULES[moduleId];
    if (!p) throw new Error('Unknown moduleId');
    if (!fs.existsSync(p)) throw new Error(`Compiled module missing (${p}). Run: npm run compile:modules`);
    return fs.readFileSync(p);
  },
  dispatchRpc(method, params) {
    switch (method) {
      case 'priceModel': {
        const { base=10, multiplier=1.2 } = params||{};
        return { price: Math.round(base*multiplier*100)/100 };
      }
      case 'scoreUser': {
        const { age=30, activity=0.5 } = params||{};
        return { score: Math.max(0, Math.min(100, age*activity)) };
      }
      case 'module_run': {
        const { moduleId, auth } = params||{};
        console.log(`[module_run] ${moduleId} started by`, auth);
        return { ok: true };
      }
      default: throw new Error('Unknown method');
    }
  }
};
