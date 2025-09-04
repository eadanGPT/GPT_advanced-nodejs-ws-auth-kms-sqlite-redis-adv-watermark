module.exports = { doWork(){ return 'analytics:ok' },
	async run( ws){
		console.log("Analytics Running. on websocket:", ws.url);
	},

 };
