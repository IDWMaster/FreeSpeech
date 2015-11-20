/**
 * IMMEDIATE TODO LIST
 * Make sure that clients can authenticate to first-hop servers.
 * For clients advertising a thumbprint; the thumbprint and public key should be stored in the local database.
 * For clients not supplying a thumbprint; no information whatsoever should be recorded with regards to the connection.
 * If a client does not supply a thumbprint; it is a request for anonymity, which should be honored in order to keep the network secure
 */


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


var ActiveConnections = new Object();

var PublicEndpoints = {
		servers:new Object(),
		add:function(portno,noUpdate) {
			if(this.servers[portno]) {
				return;
			}
			if(!noUpdate) {
				db.collection('servers').insertOne({port:portno},function(){});
			}
			this.servers[portno] = startServer(portno);
		},
		remove:function(portno) {
			servers[portno].close();
			delete servers[portno];
		},
		init:function() {
			db.collection('servers').find().each(function(err,doc){
				if(doc) {
					PublicEndpoints.add(doc.port,true);
				}
				return true;
			});
		}
};



/**
 * Information about "first hop servers" -- nodes that have been identified as good candidates for initial session establishment.
 */
var FirstHopServers = {
		add:function(ip,portno,thumbprint){
			db.collection('firsthops').insertOne({ip:ip,portno:portno,thumbprint:thumbprint});
		},
		remove:function(thumbprint) {
			db.collection('firsthops').deleteMany({thumbprint:thumbprint},function(err,delcount){});
		},
		enumerate:function(callback) {
			db.collection('firsthops').find().each(function(err,doc){
				if(doc) {
					callback(doc);
				}else {
					callback(null);
				}
			});
		}
};



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
		findKey:function(thumbprint,callback){
			db.collection('keys').find({thumbprint:thumbprint}).each(function(err,doc){
				if(doc) {
					var key = new NodeRSA();
					key.importKey(doc.key.buffer,'pkcs1-der');
					return callback(key);
				}
				callback(null);
				return false;
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
var CleartextServer = function(onReady,onClientConnect, customPort) {
	var activeSessions = new Object();

	var s = dgram.createSocket('udp4');
	if(customPort) {
		s.bind(customPort,function(){
			var portno = s.address().port;
			onReady(portno);
		});
	}else {
		s.bind(function(){
			var portno = s.address().port;
			onReady(portno);

		});
	}

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
		},connect:function(remoteAddress,remotePort) {
			var retval = Session();
			var entry = remoteAddress+':'+remotePort;
			retval.subclass(function(_protected){
				activeSessions[entry] = function(data) {
					_protected.ntfyPacket(data);
				}
				retval.send = function(data) {
					s.send(data,0,data.length,remoteAddress,remotePort);
				}
				retval.close = function() {
					delete activeSessions[entry];
				}
			});
			return retval;
		}
	};
};


/**
 * Begins an encrypted session with a remote host
 * @param parentSocket The socket with which to establish an encrypted session
 * @param publicKey The public key of the destination computer
 * @param thumbprint A string containing the thumbprint with which to authenticate, or an empty string for no thumbprint
 * @param callback A callback method which will be invoked when a connection has been successfully established.
 */
var startEncryptedSession = function(parentSocket,publicKey,thumbprint,callback) {
	//TODO: Create encrypted handshake packet
	var retval = Session();
	var rnd = new Uint32Array(1+8); //First 32 bits for pseudo-random integer, next for key
	crypto.getRandomValues(mray);

	var thumbstr = new Buffer(thumbprint,'utf-8');


	//Note: Buffers are not initialized to all-zeroes; they can be used as a source of non-secure cryptographic pseudo-randomness
	//although we need to be careful about accidentally leaking sensitive data.
	var timeout = setTimeout(function(){
		callback(null);
	},2000);
	var packet = new Buffer(4+1+thumbstr.length+1+32+1);
	rnd.copy(packet,0,0,4);
	packet[4] = 0;
	thumbstr.copy(packet,4+1);
	packet[4+1+thumbstr.length] = 0;
	rnd.copy(packet,4+1+thumbstr.length+1,4);
	packet[4+1+thumbstr.length+1+32] = 1;
	parentSocket.registerReceiveCallback(function(data) {

	});
	//TODO: Encrypt before sending
	var key = new Buffer(32);
	rnd.copy(key,0,4);
	packet = publicKey.encrypt(packet);
	parentSocket.send(packet);

};


var startServer = function(portno) {
	var server = CleartextServer(function(portno){

	}, function(session){
		//We have a possible active connection
		session.registerReceiveCallback(function(data){
			try {
				if(session.key) {
					//Use active session key
				}else {
					//Must be addressed to us, decode it
					var packet = defaultKey.decrypt(packet);
					//Opcode MUST be zero. If not, somebody's probably up to something....
					if(packet[4] != 0) {
						throw 'Illegal OPCODE';
					}
					var thumbprint = '';
					var i;
					for(i = 5;i<packet.length;i++) {
						if(packet[i] == 0) {
							break;
						}
						thumbprint+=packet[i];
					}
					
					
				}
			}catch(er) {
				session.close(); //Terminate session on error.
			}
		});
	}, portno);
	return server;
};


/**
 * Free Speech API
 */
var API = {
		process:function(request,response){
			var respondWithJson = function(obj) {
				response.respond(JSON.stringify(obj));
			}
			if(request.session != sid) {
				throw 'up';
			}
			switch(request.opcode) {
			case 0:
				//Create publicly accessible server
				PublicEndpoints.add(request.port);
				respondWithJson({status:'OK'});
				break;
			case 1:
				//Get list of public endpoints
				var serverlist = new Array();
				for(var i in PublicEndpoints.servers) {
					serverlist.push(i);
				}
				respondWithJson(serverlist);
				break;
			default:
				throw 'sideways';
			}
		}
};




var initHttpServer = function() {

	console.log('Your default thumbprint is: '+defaultKey.thumbprint());


	//Run background configuration tasks
	PublicEndpoints.init();
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

				}else {
					response.respond(JSON.stringify({err:'Illegal request'}));
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
			var proc = child_process.spawn('mongod', ['--port',portno,'--dbpath','db','--bind_ip','127.0.0.1','--logpath','db/log.txt']);
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
			}, 8000);


		});
	});




});