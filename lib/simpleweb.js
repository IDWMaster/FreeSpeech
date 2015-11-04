SimpleWeb = {
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
		Form:function(){
			var element = new SimpleWeb.HTMLElement('form').setAttribute('method','post');
			var elem_form = new SimpleWeb.HTMLElement('div');
			element.addChild(elem_form);
			var elemend = new SimpleWeb.HTMLElement('div');
			element.addChild(elemend);
			elemend.addChild(SimpleWeb.HTMLElement('input').setAttribute('type','submit').setAttribute('class','btn btn-default'));
			
			
			return {
				element:element,
				addControl:function(control,friendlyName){
					var group = new SimpleWeb.HTMLElement('div');
					group.setAttribute('class', 'form-group');
					var label = new SimpleWeb.HTMLElement('label');
					label.setAttribute('for', control.getAttribute('id'));
					label.addChild(friendlyName);
					control.setAttribute('class','form-control');
					elem_form.addChild(group);
					group.addChild(label);
					group.addChild(control);
					
				},
				toString:function(){
					
					return element.render();
				}
			};
		}
};