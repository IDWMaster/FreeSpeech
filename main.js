var httpserver = require('openserver');





var server = httpserver.startServer({ip:'::',port:8080});
server.RegPath('/', function(request,response){
	response.respondWithHtml('index.html');
});