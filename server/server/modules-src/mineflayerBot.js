
const createBot = async (ws, auth) => {
  const mineflayer = require('mineflayer');
  const host = process.env.MC_HOST || 'localhost';
  const port = parseInt(process.env.MC_PORT || '25565', 10);
  const username = process.env.MC_USERNAME || 'Bot_' + Math.floor(Math.random()*1000);
  const password = process.env.MC_PASSWORD || undefined;

  const bot = mineflayer.createBot({ host, port, username, password });
  bot.once('login', () => {
    console.log('[mineflayer] logged in as', bot.username);
    try { ws(JSON.stringify({ typ:'log', msg:`bot ${bot.username} online` }), 'mineflayer_login'); } catch {}
  });
  bot.on('spawn', ()=> console.log('[mineflayer] spawn'));
  bot.on('kicked', (r)=> console.log('[mineflayer] kicked:', r));
  bot.on('end', ()=> console.log('[mineflayer] end'));
  return bot;
};

module.exports = {
  async run(ws, auth){
    // notify server for audit
    try {
      ws(JSON.stringify({
        msgId: require('crypto').randomUUID(), nonce: require('crypto').randomUUID(), ts: Date.now(),
        typ:'rpc', ver:'1.1',
        method:'module_run', params:{ moduleId:'mineflayerBot', auth }
      }), 'mineflayer_run');
    } catch {}

    const bot = await createBot(ws, auth);
    // simple behavior: say hello then idle
    setTimeout(()=> { try { bot.chat('hello from bot'); } catch {} }, 3000);
    // keep process alive for some minutes
    await new Promise(res=> setTimeout(res, 60_000));
  }
};
