var httpserver = require('openserver');





var server = httpserver.startServer({ip:'::',port:8080});
server.RegPath('/', function(request,response){
	server.renderHtml('index.html', function(html) {
		response.writeHead(200, {'Content-Type':'text/html'});
		response.write(html);
		
		response.end();
	});
});