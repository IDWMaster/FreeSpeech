
/**
 * Extensible Service Framework for Free Speech Project
 */
var XSF = {
		/**
		 * Sends an HTTP web request to the current server
		 * @param request The parameters to send
		 * @param callback A callback function containing a response from the server
		 */
		SendRequest:function(request,callback) {
			request.session = SessionKey;
			var req = new XMLHttpRequest();
			req.open('POST', '/api', true);
			req.addEventListener('load',function(){
				if(callback) {
					callback(JSON.parse(req.responseText));
				}
			});
			req.send(JSON.stringify(request));
		},
		addPublicServer:function(port,callback) {
			this.SendRequest({opcode:0,port:port}, callback);
		},
		getPublicServerList:function(callback){
			this.SendRequest({opcode:1}, callback);
		},
		debugRun:function(func,varargs) {
			
			var args = new Array();
			for(var i = 1;i<arguments.length;i++) {
				args.push(arguments[i]);
			}
			args.push(function(result){
				console.log(result);
			});
			func.apply(this,args);
		}
};


function pageload() {

}