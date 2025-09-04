
import { parentPort, workerData } from 'node:worker_threads';

(async()=>{
  const { moduleName, modulePath } = workerData;
  const mod = await import(modulePath);
  const ctx = {
    sendAndWait: (payload)=>{
      parentPort.postMessage({ type:'callSendAndWait', payload });
      return new Promise((resolve)=>{
        const on = (msg)=>{ if (msg.type==='resp') { parentPort.off('message', on); resolve(msg.resp); } };
        parentPort.on('message', on);
      });
    },
    sendMetrics: (payload)=> parentPort.postMessage({ type:'callSendMetrics', payload }),
  };
  if (typeof mod.run === 'function') {
    const t0 = Date.now();
    try {
      const res = await mod.run(ctx);
      const dt = Date.now() - t0;
      ctx.sendMetrics({ module: moduleName, kind: 'module_exec_seconds', seconds: dt / 1000 });
      parentPort.postMessage({ type:'done', ok:true, res });
    } catch (e) {
      const dt = Date.now() - t0;
      ctx.sendMetrics({ module: moduleName, kind: 'module_exec_seconds', seconds: dt / 1000 });
      parentPort.postMessage({ type:'done', ok:false, error: e?.message || 'worker_error' });
    }
  } else {
    parentPort.postMessage({ type:'done', ok:false, error:'no_run_export' });
  }
})().catch(e=> parentPort.postMessage({ type:'done', ok:false, error:e?.message||'worker_boot_error' }));
