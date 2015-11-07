var httpserver = require('openserver');
var Stream = require('stream');

var datamodel = {
		pages:{'Home page':'/','Async request demo':'/asyncdemo','Contact us':'/contact'}
};




var server = httpserver.startServer({ip:'::',port:8080});

var SimpleWeb = server.loadLibrary('lib/simpleweb.js');

server.RegPath('/basetest',function(request,response){
	response.respond('This page can be used as a baseline performance test.');
});


server.RegPath('/', function(request,response){
	server.setModel(datamodel);
	response.respondWithHtml('index.html');
});
server.RegPath('/asyncdemo',function(request,response){
	server.setModel(datamodel);
	response.respondWithHtml('asyncdemo.html');
});
server.RegPath('/contact',function(request,response){
	
	
	var contactForm = new SimpleWeb.Form(server);
	var firstName = contactForm.addTextControl('First name','Enter your first name');
	var lastName = contactForm.addTextControl('Last name','Enter your last name');
	datamodel.testform = contactForm;
	server.setModel(datamodel);
	response.respondWithHtml('contact.html');
});