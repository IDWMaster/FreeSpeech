var httpserver = require('openserver');
var Promise = httpserver.Promise;
var Escape = require('escape-html');

var SimpleWeb = {
		version:1.0,
		HTMLElement:function(tagName){

			var textValue = null;
			var attributes = new Object();
			var children = new Array();
			return {
				render:function(){
					if(textValue) {
						return textValue;
					}
					var retval = '<'+tagName;
					for(var i in attributes) {
						retval+=' '+i+'="'+attributes[i]+'"';
					}
					if(children.length>0) {
						retval+='>';
						for(var i = 0;i<children.length;i++) {
							retval+='\n'+children[i].render();
						}
						retval+='</'+tagName+'>';
					}else {
						retval+=' />'
					}
					return retval;
				},
				addChild:function(other) {
					if(other.render) {
						children.push(other);
					}else {
						var elem = new SimpleWeb.HTMLElement();
						elem.setText(other);
						children.push(elem);
					}
					return this;
				},
				setAttribute:function(key,value) {
					attributes[key] = value;
					return this;
				},
				setText:function(text) {
					textValue = text;
					return this;
				},
				getAttribute:function(key){
					return attributes[key];
				}
			};
		},
		/**
		 * An HTML form, containing data controls
		 */
		Form:function(server){
			var databound_controls = new Object();


			var element = new SimpleWeb.HTMLElement('form').setAttribute('method','post');
			var elem_form = new SimpleWeb.HTMLElement('div');
			element.addChild(elem_form);
			var elemend = new SimpleWeb.HTMLElement('div');
			element.addChild(elemend);
			elemend.addChild(SimpleWeb.HTMLElement('input').setAttribute('type','submit').setAttribute('class','btn btn-default'));
			var cid = 0;



			return {
				element:element,
				/**
				 * Adds a raw control to the HTML page. Recommended for advanced users only.
				 */
				addControl:function(control,friendlyName){
					var group = new SimpleWeb.HTMLElement('div');
					group.setAttribute('class', 'form-group');
					var label = new SimpleWeb.HTMLElement('label');
					label.setAttribute('for', control.getAttribute('id'));
					label.addChild(friendlyName);
					elem_form.addChild(group);
					group.addChild(label);
					group.addChild(control);
					control.setAttribute('name',control.getAttribute('id'));
					databound_controls[control.getAttribute('id')] = control;
				},
				addTextControl:function(friendlyName,placeholder){
					var elem = new SimpleWeb.HTMLElement('input').setAttribute('id',cid);
					cid++;
					elem.setAttribute('type','text').setAttribute('class','form-control');
					if(placeholder) {
						elem.setAttribute('placeholder',placeholder);
					}
					this.addControl(elem,friendlyName);
					return elem;

				},
				promise:{
					done:function(callback){

						var doRender = new Promise();

						server.getContext().request.getForm(function(form){
							if(form) {
								for(var i in form) {
									databound_controls[i].setAttribute('value',Escape(form[i]));
								}
								doRender.post(element.render());
							}else {
								doRender.post(element.render());
							}
						});
						doRender.done(callback);
					}
				}
			};
		}
};


module.exports = SimpleWeb;