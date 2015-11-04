var httpserver = require('openserver');


var datamodel = {
		pages:{'Home page':'/','Async request demo':'/asyncdemo','Contact us':'/contact'}
};




var server = httpserver.startServer({ip:'::',port:8080});

library('lib/simpleweb.js');


var testform = new SimpleWeb.Form();
testform.addControl(new SimpleWeb.HTMLElement('input').setAttribute('id','firstname').setAttribute('placeholder','Enter your first name'),'First name');
testform.addControl(new SimpleWeb.HTMLElement('input').setAttribute('id','lastname').setAttribute('placeholder','Enter your last name'),'Last name');


datamodel.testform = testform;

server.RegPath('/', function(request,response){
	server.setModel(datamodel);
	response.respondWithHtml('index.html');
});
server.RegPath('/asyncdemo',function(request,response){
	server.setModel(datamodel);
	response.respondWithHtml('asyncdemo.html');
});
server.RegPath('/contact',function(request,response){
	server.setModel(datamodel);
	response.respondWithHtml('contact.html');
});