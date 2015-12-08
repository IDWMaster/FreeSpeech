/**
 * IMMEDIATE TODO LIST
 * ASAP: Refactor this code into multiple NodeJS modules
 * For example; the various Session components should be refactored.
 * 
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
var Session = require('freespeech-session').Session;
var CleartextServer = require('freespeech-session').CleartextServer;
var UDPClient;


/**
 * Encrypt using AES encryption
 * @param {Buffer} key
 * @param {Buffer} data
 * @returns {Buffer}
 */
var aesEncrypt = function (key, data) {
    var iv = new Buffer(16);
    key.copy(iv);
    var cipher = crypto.createCipheriv('aes-256-cbc', key,iv);
    var encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return encrypted;
};
/**
 * Decrypt using AES encryption
 * @param {Buffer} key
 * @param {Buffer} data
 * @returns {Buffer}
 */
var aesDecrypt = function (key, data) {
    var iv = new Buffer(16);
    key.copy(iv);
    var cipher = crypto.createDecipheriv('aes-256-cbc', key,iv);
    var decrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return decrypted;
};


NodeRSA.prototype.thumbprint = function () {
    var pubbin = this.exportKey('pkcs8-public-der');
    var hash = crypto.createHash('sha256');
    hash.update(pubbin);
    return hash.digest('hex');
};

var db;
var defaultKey;

var sid = uuid.v4().toString();


var ActiveConnections = {};

var PublicEndpoints = {
    servers: new Object(),
    add: function (portno, noUpdate) {
        if (this.servers[portno]) {
            return;
        }
        if (!noUpdate) {
            db.collection('servers').insertOne({port: portno}, function () {});
        }
        this.servers[portno] = startServer(portno);
    },
    remove: function (portno) {
        this.servers[portno].close();
        delete this.servers[portno];
    },
    init: function () {
        db.collection('servers').find().each(function (err, doc) {
            if (doc) {
                PublicEndpoints.add(doc.port, true);
            }
            return true;
        });
    }
};



/**
 * Information about "first hop servers" -- nodes that have been identified as good candidates for initial session establishment.
 */
var FirstHopServers = {
    add: function (ip, portno, thumbprint) {
        db.collection('firsthops').insertOne({ip: ip, portno: portno, thumbprint: thumbprint});
    },
    remove: function (thumbprint) {
        db.collection('firsthops').deleteMany({thumbprint: thumbprint}, function (err, delcount) {});
    },
    enumerate: function (callback) {
        db.collection('firsthops').find().each(function (err, doc) {
            if (doc) {
                callback(doc);
            } else {
                callback(null);
            }
        });
    }
};



var CryptCreateKeyPair = function (bitStrength) {
    return new NodeRSA({b: bitStrength});
};

var EncryptionKeys = {
    enumPrivateKeys: function (callback) {
        db.collection('keys').find({hasPrivate: true}).each(function (err, doc) {
            if (err) {
                callback(null);
                return false;
            }
            if (doc) {
                var key = new NodeRSA();
                ;
                key.importKey(doc.key.buffer, 'pkcs1-der');
                return callback(key);
            } else {
                return callback(null);
            }
        });
    },
    getDefaultKey: function (callback) {
        db.collection('keys').find({hasPrivate: true, isDefault: true}).each(function (err, doc) {
            if (!doc) {
                callback(null);
                return false;
            } else {
                var key = new NodeRSA();
                key.importKey(doc.key.buffer, 'pkcs1-der');
                return callback(key);
            }
        });
    },
    findKey: function (thumbprint, callback) {
        db.collection('keys').find({thumbprint: thumbprint}).each(function (err, doc) {
            if (doc) {
                var key = new NodeRSA();
                key.importKey(doc.key.buffer, 'pkcs1-der');
                return callback(key);
            }
            callback(null);
            return false;
        });
    },
    add: function (key, callback, isDefault) {
        var binkey = key.exportKey('pkcs1-der');
        var doc = {
            hasPrivate: !key.isPublic(true),
            key: binkey,
            thumbprint: key.thumbprint(),
            isDefault: (isDefault == true)
        };
        db.collection('keys').insertOne(doc, function (err, r) {
            if (err) {
                callback(false);
            } else {
                callback(true);
            }
        });
    }
};



/**
 * Call this function after a session has been successfully established
 * @param {Session} session
 * @returns {undefined}
 */
var sessionInit = function(session) {
    session.registerReceiveCallback(function(data){
        
    console.log('DEBUG: Received encrypted packet');
        try {
            switch(data[0]) {
                case 0:
                    //Request public key for fingerprint
                    break;
                case 1:
                    //Send public key
                    break;
                case 2:
                    //Connect to node with specified fingerprint
                    break;
                case 3:
                    //Response to request to open encrypted session
                    break;
                case 4:
                    //Send raw packet to node
                    break;
                case 5:
                    //Ping request
                    console.log('DEBUG: Received ping request');
                    session.sendPacket(new Buffer([6]));
                    break;
                case 6:
                    //Ping response
                    console.log('DEBUG: Peer has responded to ping request');
                    break;
            }
        }catch(er) {
        }
    });
    
    //Send ping
    session.sendPacket(new Buffer([5]));
}





/**
 * Begins an encrypted session with a remote host
 * @param parentSocket The socket with which to establish an encrypted session
 * @param publicKey The public key of the destination computer
 * @param thumbprint A string containing the thumbprint with which to authenticate, or an empty string for no thumbprint
 * @param callback A callback method which will be invoked when a connection has been successfully established.
 */
var startEncryptedSession = function (parentSocket, publicKey, callback) {
    //TODO: Create encrypted handshake packet
    var retval = Session();

    crypto.randomBytes(4 + 32, function (er, rnd) {
        //Note: Buffers are not initialized to all-zeroes; they can be used as a source of non-secure cryptographic pseudo-randomness
        //although we need to be careful about accidentally leaking sensitive data.
        var recvCBHandle;
        
        var timeout = setTimeout(function () {
            parentSocket.unregisterReceiveCallback(recvCBHandle);
            callback(null);
        }, 2000);
        var packet = new Buffer(4 + 1 + 32 + 1);
        rnd.copy(packet, 0, 0, 4);
        packet[4] = 0;
        rnd.copy(packet, 4 + 1, 4);
        packet[4 + 1 + 32] = 1;
        var encKey = new Buffer(32);
        rnd.copy(encKey,0,4);
        var sessionEstablished = false;
        var sessionID;
        recvCBHandle = parentSocket.registerReceiveCallback(function (data) {
            try {
            if(sessionEstablished) {
                data = aesDecrypt(encKey,data);
                retval.decodePacket(data);
            }else {
                var packet = aesDecrypt(encKey,data);
                if(packet.readUInt32LE(0) == rnd.readUInt32LE(0)) {
                    if(packet[4] == 1) {
                      sessionID = packet.readUInt16LE(4+1);
                      retval.setSessionID(sessionID);
                        clearTimeout(timeout);
                        callback(retval);
                      sessionEstablished = true;
                      var _send = retval.send;
                            retval.send = function(packet) {
                          _send(packet);
                          var alignedBuffer = new Buffer(Math.ceil(packet.length/16)*16);
                          packet.copy(alignedBuffer);
                              
                          parentSocket.send(aesEncrypt(encKey,alignedBuffer));
                      };
                            sessionInit(retval);
                    }
                }
            }
        }catch(er) {
            console.log('DEBUG: Session server error '+er);
        }
        });
        //TODO: Encrypt before sending
        var key = new Buffer(32);
        rnd.copy(key, 0, 4);
        packet = publicKey.encrypt(packet);
        parentSocket.send(packet);

    });


};



var startServer = function (portno, optionalCallback) {
    var server = CleartextServer(function (portno) {
        if (optionalCallback) {
            optionalCallback(portno);
        }
    }, function (session) {
        console.log('DEBUG: Session start');
        var encryptedSession = Session();
            var _send = encryptedSession.send;
            var _close = encryptedSession.close;
            encryptedSession.send = function(data) {
                //Align data buffer
                _send(data);
                var alignedBuffer = new Buffer(Math.ceil(data.length/16)*16);
                data.copy(alignedBuffer);
                session.send(aesEncrypt(encryptedSession.key,alignedBuffer));
                
            };
            encryptedSession.close = function() {
                _close();
            };
            
        //We have a possible active connection
        session.registerReceiveCallback(function (data) {
            try {
                if (encryptedSession.key) {
                    //TODO: Use active session key
                    encryptedSession.decodePacket(aesDecrypt(encryptedSession.key,data));
                } else {
                    //Must be addressed to us, decode it
                    var packet = defaultKey.decrypt(data);
                    //Opcode MUST be zero. If not, somebody's probably up to something....
                    if (packet[4] != 0) {
                        throw 'Illegal OPCODE';
                    }
                    //Get AES session key, and create crypto object for it
                    var aeskey = new Buffer(32);
                    packet.copy(aeskey, 0, 5, 5 + 32);
                    var includeIPInformation = packet[5 + 32];
                    encryptedSession.key = aeskey;
                    console.log('DEBUG: Session parsed');
                    //Send response to connection
                    var response = new Buffer(16);
                    //TODO: To prevent replay attacks, the first four bytes in this frame should match the random data
                    //in the initial handshake request.
                        packet.copy(response,0,0,4);
                        response[4] = 1;
                        response.writeUInt16LE(encryptedSession.getSessionID(),4+1);
                        //TODO: Optional IP and port numbers
                        console.log('DEBUG TODO add IP and port numbers here');
                        session.send(aesEncrypt(encryptedSession.key,response));
                        sessionInit(encryptedSession);
                }
            } catch (er) {
                console.log('DEBUG SESSION ERR: '+er);
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
    process: function (request, response) {
        var respondWithJson = function (obj) {
            response.respond(JSON.stringify(obj));
        }
        if (request.session != sid) {
            throw 'up';
        }
        switch (request.opcode) {
            case 0:
                //Create publicly accessible server
                PublicEndpoints.add(request.port);
                respondWithJson({status: 'OK'});
                break;
            case 1:
                //Get list of public endpoints
                var serverlist = new Array();
                for (var i in PublicEndpoints.servers) {
                    serverlist.push(i);
                }
                respondWithJson(serverlist);
                break;
            default:
                throw 'sideways';
        }
    }
};




var initHttpServer = function () {

    console.log('Your default thumbprint is: ' + defaultKey.thumbprint());


    //Run background configuration tasks
    PublicEndpoints.init();
    UDPClient = startServer(null, function (portno) {
        var loopbackClient = startServer();
        var loopbackConnection = loopbackClient.connect('127.0.0.1', portno);
        loopbackConnection = startEncryptedSession(loopbackConnection, defaultKey, function (session) {
            if (!session) {
                console.log('WARN: Loopback connection failed.');
            }else {
                console.log('DEBUG: Loopback connection established');
                sessionInit(session);
                
            }
        });
    });



    var server = net.createServer(function (client) {});
    server.listen(0, '::');
    server.on('listening', function () {
        var portno = server.address().port;
        server.once('close', function () {

            var server = httpserver.startServer({ip: '127.0.0.1', port: portno});
            console.log('Server running at http://127.0.0.1:' + portno);
            server.RegPath('/fsos', function (request, response) {
                response.respondWithHtml('fsos.html');
            });

            server.RegPath('/', function (request, response) {
                server.setModel({
                    sessionID: sid
                });
                response.respondWithHtml('index.html');

            });

            server.RegPath('/api', function (request, response) {
                if (request.method == 'POST') {
                    var txt = '';
                    request.readInput(function (data) {

                        if (data) {
                            txt += data.toString();
                        } else {
                            try {
                                var req = JSON.parse(txt);
                                API.process(req, response);
                            } catch (er) {
                                response.respond(JSON.stringify({err: er.toString()}));
                            }
                        }
                    });

                } else {
                    response.respond(JSON.stringify({err: 'Illegal request'}));
                }
            });


        });
        server.close();
    });


}


process.stdin.resume();
var exitHandlers = new Array();
function exitHandler(options, err) {

    for (var i = 0; i < exitHandlers.length; i++) {
        try {
            exitHandlers[i]();
        } catch (er) {

        }
    }


    if (options.exit) {
        process.exit();
    }

}

//do something when app is closing
process.on('exit', exitHandler.bind(null, {cleanup: true}));

console.log('==============================');
console.log('Initializing Free Speech!')
console.log('==============================');
console.log('Creating db directory....');
fs.mkdir('db', function () {
    console.log('Initializing networking subsystem....');

    var server = net.createServer(function (client) {});
    server.listen(0, '::');
    server.on('listening', function () {
        var portno = server.address().port;
        server.close();
        server.once('close', function () {
            console.log('Starting MongoDB on port ' + portno + '....');
            var proc = child_process.spawn('mongod', ['--port', portno, '--dbpath', 'db', '--bind_ip', '127.0.0.1', '--logpath', 'db/log.txt']);
            proc.on('error', function (er) {
                throw er;
            });
            exitHandlers.push(function () {
                proc.kill();
            });
            setTimeout(function () {
                mongo.MongoClient.connect('mongodb://127.0.0.1:' + portno + '/FreeSpeech', function (err, mdb) {
                    if (err != null) {
                        console.log('Error establishing database connection.');
                        throw err;
                    }
                    db = mdb;

                    EncryptionKeys.getDefaultKey(function (key) {
                        if (!key) {
                            //We need key please
                            console.log('Generating default identity file (key length == 4096 bits), this may take a long time....');
                            var keypair = CryptCreateKeyPair(4096);
                            console.log('Keypair created. Adding to database....');
                            EncryptionKeys.add(keypair, function (success) {
                                if (!success) {
                                    throw 'counterclockwise';
                                }
                                console.log('Bringing up the frontend....');
                                defaultKey = keypair;
                                initHttpServer();


                            }, true);

                        } else {
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