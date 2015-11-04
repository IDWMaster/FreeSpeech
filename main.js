var httpserver = require('openserver');


var datamodel = {
		pages:{'Home page':'/','Async request demo':'/asyncdemo'}
};


var server = httpserver.startServer({ip:'::',port:8080});
server.RegPath('/', function(request,response){
	server.setModel(datamodel);
	response.respondWithHtml('index.html');
});
server.RegPath('/asyncdemo',function(request,response){
	server.setModel(datamodel);
	response.respondWithHtml('asyncdemo.html');
});
