var CryptLib = require('freespeech-cryptography');
var SessionLib = require('freespeech-session');
var CryptDB = require('freespeech-database');
CryptDB.onDbReady(function () {
    var EncryptionKeys = CryptDB.EncryptionKeys;

    var Session = SessionLib.Session;
    var CleartextServer = SessionLib.CleartextServer;



    var defaultKey; //Default encryption key (public identity). Thumbprint of default key can be used to decrypt incoming communications
//but this key should ONLY be shared with trusted parties if you want anonymity features.

    console.log('Welcome to Free Speech! A decentralized network enabling simple, P2P private conversations and social networking!');

    EncryptionKeys.getDefaultKey(function (key) {
        if (key) {
            defaultKey = key;
        } else {
            console.log('Generating a 4096-bit key. This may take some time. Please be patient.');
            defaultKey = CryptLib.generateRSAKey(4096);
            EncryptionKeys.add(defaultKey,function(s){
                console.log('Added key?');
                if(!s) {
                    throw 'up';
                }
                
            },true);
        }
        var mainServer = new CleartextServer(function (portno) {
            console.log('SERVER INFORMATION\nPort number: ' + portno + '\nThumbprint: ' + defaultKey.thumbprint());
            console.log('NOTICE: The above information (combined with IP address) can be used to uniquely identify you. If you desire anonymity, do not share these details with third-parties.');

        }, function (clearSession) {
            CryptLib.negotiateServerConnection(clearSession, defaultKey, function (session) {
                console.log('Session established');
            });
        });
        return false;
    });
});