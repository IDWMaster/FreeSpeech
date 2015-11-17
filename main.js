var httpserver = require('openserver');
var Stream = require('stream');
var crypto = require('crypto');
var fs = require('fs');
var net = require('net');
var child_process = require('child_process');
var mongo = require('mongodb');
var uuid = require('node-uuid');
var dgram = require('dgram');
var NodeRSA = require('node-rsa');

NodeRSA.prototype.thumbprint = function() {
	var pubbin = this.exportKey('pkcs8-public-der');
	var hash = crypto.createHash('sha256');
	hash.update(pubbin);
	return hash.digest('hex');
};

var db;
var defaultKey;

var sid = uuid.v4().toString();



var CryptCreateKeyPair = function(bitStrength) {
	return new NodeRSA({b:bitStrength});
};

var EncryptionKeys = {
	enumPrivateKeys:function(callback) {
		db.collection('keys').find({hasPrivate:true}).each(function(err,doc){
			if(err) {
				callback(null);
				return false;
			}
			if(doc) {
				var key = new NodeRSA();;
				
				key.importKey(doc.key.buffer,'pkcs1-der');
				return callback(key);
			}else {
				return callback(null);
			}
		});
	},
	getDefaultKey:function(callback){
		db.collection('keys').find({hasPrivate:true,isDefault:true}).each(function(err,doc){
			if(!doc) {
				callback(null);
				return false;
			}else {
				var key = new NodeRSA();
				key.importKey(doc.key.buffer,'pkcs1-der');
				return callback(key);
			}
		});
	},
	add:function(key,callback,isDefault) {
		var binkey = key.exportKey('pkcs1-der');
		var doc = {
				hasPrivate:!key.isPublic(true),
				key:binkey,
				thumbprint:key.thumbprint(),
				isDefault:(isDefault == true)
		};
		db.collection('keys').insertOne(doc,function(err,r){
			if(err) {
				callback(false);
			}else {
				callback(true);
			}
		});
	}
};

/**
 * @class
 */
var Session = function() {
	var callbacks = new Array();
	
	var Protected = {};
	var retval = {
		send:function(data){},
		/**
		 * Registers a callback which is invoked when a packet is received
		 */
		registerReceiveCallback:function(callback) {
			return callbacks.push(callback)-1;
		},
		/**
		 * Unregisters a callback
		 */
		unregisterReceiveCallback:function(id) {
			callbacks.splice(id,1);
		},
		/**
		 * Subclasses this instance
		 */
		subclass:function(callback){
			callback(Protected);
			return this;
		},
		send:function(data) {
			throw 'NotImplemented';
		},
		close:function() {
			throw 'NotImplemented';
		}
	};
	Protected.ntfyPacket = function(packet) {
		for(var i = 0;i<callbacks.length;i++) {
			callbacks[i](packet);
		}
	}
	return retval;
};




/**
 * Cleartext server
 */
var CleartextServer = function(onReady,onClientConnect) {
	var activeSessions = new Object();
	
	
	var s = dgram.createSocket('udp4');
	
	s.bind(function(){
		var portno = s.address().port;
		onReady(portno);
		
	});
	
	s.on('message',function(msg,rinfo){
		var entry = rinfo.address+':'+rinfo.port;
		if(!activeSessions[entry]) {
			var session = Session();
			session.subclass(function(_protected){
				activeSessions[entry] = function(data) {
					_protected.ntfyPacket(data);
				}
				session.send = function(data) {
					s.send(data,0,data.length,rinfo.address,rinfo.port);
				}
				session.close = function() {
					delete activeSessions[entry];
				}
			});
			onClientConnect(session);
		}
		activeSessions[entry](msg);
	});
	
	return {
		close:function(callback){
			s.close(callback);
		}
	};
};



var CleartextClient = function(remoteHostname,remotePort) {
	var retval = Session();
	retval.subclass(function(_protected){
		var socket = dgram.createSocket('udp4');
		socket.on('message',function(msg,rinfo){
			_protected.ntfyPacket(msg);
		});

		retval.send = function(data) {
			socket.send(data,0,data.length,remoteHostname,remotePort);
		};
		retval.close = function() {
			socket.close();
		};
		
	});
	return retval;
};


var EncryptedSession = function(parentSocket) {
	var retval = Session();
	retval.subclass(function(_protected){
		
	});
	return retval;
};



/**
 * Free Speech API
 */
var API = {
		process:function(request,response){
			if(request.session != sid) {
				throw 'up';
			}
			switch(request.opcode) {
			case 0:
				//Establish native session
				break;
				default:
					throw 'sideways';
			}
		}
};




var initHttpServer = function() {

	console.log('Your default thumbprint is: '+defaultKey.thumbprint());
	
		
	var server = net.createServer(function(client){});
	server.listen(0,'::');
	server.on('listening',function(){
		var portno = server.address().port;
		server.once('close',function(){
			
			var server = httpserver.startServer({ip:'127.0.0.1',port:portno});
			console.log('Server running at http://127.0.0.1:'+portno);
			server.RegPath('/fsos',function(request,response){
				response.respondWithHtml('fsos.html');
			});
			
			server.RegPath('/', function(request,response){
				server.setModel({
					sessionID:sid
				});
				response.respondWithHtml('index.html');
				
			});
			
			server.RegPath('/api',function(request,response){
				if(request.method == 'POST') {
					var txt = '';
					request.readInput(function(data){
						if(data) {
							txt+=data.toString();
						}else {
							try {
								var req = JSON.parse(txt);
								API.process(req, response);
							}catch(er) {
								response.respond(JSON.stringify({err:er.toString()}));
							}
						}
					});
					
				}
			});
			
			
		});
		server.close();
	});
	
	
}


process.stdin.resume();
var exitHandlers = new Array();
function exitHandler(options, err) {

	for(var i = 0;i<exitHandlers.length;i++) {
		try {
			exitHandlers[i]();
		}catch(er){

		}
	}


	if (options.exit){ 
		process.exit();
	}

}

//do something when app is closing
process.on('exit', exitHandler.bind(null,{cleanup:true}));


console.log('==============================');
console.log('Initializing Free Speech!')
console.log('==============================');
console.log('Creating db directory....');
fs.mkdir('db', function(){
	console.log('Initializing networking subsystem....');

	var server = net.createServer(function(client){});
	server.listen(0,'::');
	server.on('listening',function(){
		var portno = server.address().port;
		server.close();
		server.once('close',function(){
			console.log('Starting MongoDB on port '+portno+'....');
			var proc = child_process.spawn('mongod', ['--port',portno,'--dbpath','db','--bind_ip','127.0.0.1']);
			proc.on('error',function(er){
				throw er;
			});
			exitHandlers.push(function(){
				proc.kill();
			});
			setTimeout(function(){
				mongo.MongoClient.connect('mongodb://127.0.0.1:'+portno+'/FreeSpeech',function(err,mdb){
					if(err != null) {
						console.log('Error establishing database connection.');
						throw err;
					}
					db = mdb;
					
					EncryptionKeys.getDefaultKey(function(key){
						if(!key) {
							//We need key please
							console.log('Generating default identity file (key length == 4096 bits), this may take a long time....');
							var keypair = CryptCreateKeyPair(4096);
							console.log('Keypair created. Adding to database....');
							EncryptionKeys.add(keypair,function(success){
								if(!success) {
									throw 'counterclockwise';
								}

								console.log('Bringing up the frontend....');
								defaultKey = keypair;
								initHttpServer();
							},true);
							
						}else {
							defaultKey = key;
							initHttpServer();
						}
						return false;
					});
					
				});	
			}, 2000);


		});
	});




});