module.exports = { doWork(){ return 'analytics:ok' },
	async run( ws, auth){
		console.log("Analytics Running. on websocket:", ws.url);
	},

 };
