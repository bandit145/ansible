import json
from six.moves import urllib
from ansible.module_utils.urls import Request

class TenableAPI:
	ignore_params = ['username', 'password','validate_certs','state','server']

	def __init__(self, server, module, validate_certs):
		self.session = Request(validate_certs=validate_certs,headers={'Content-Type':'application/json'})
		self.server = server
		self.module = module

	def login(self, username, password):
		try:
			response = self.session.post(self.server+'/rest/token', data=(json.dumps({'username':username,'password':password})))
			self.session.headers['X-SecurityCenter'] = str(json.loads(response.read())['response']['token'])
		except urllib.error.HTTPError as error:
			self.handle_http_error(error)
	
	def exists(self,item,data):
		if self.get_item_by_name(item, data['name']) != None:
			return True
		return False

	def create(self, item, data):
		try:
			response = self.session.post(self.server+'/rest/'+item,data=json.dumps(data))
		except urllib.error.HTTPError as error:
			self.handle_http_error(error)

	# recursivley walk the dictonary checking if data is the same
	def is_different(self,data, existing_data):
		difference = False
		for item in data.keys():
			# if dict pass onto function again
			if type(data[item]) == dict:
				difference = self.is_different(data[item], existing_data[item])
			# if list, loop through that and pass onto function
			elif type(data[item]) == list:
				if len(existing_data[item]) == 0:
					difference = True
					break
				for dictionary in data[item]:
					for dicts in existing_data[item]:
						if dictionary['id'] == ['id']:
							id_dict = dicts
							break
						id_dict = None
					if id_dict:
						difference = self.is_different(dictionary,
							id_dict)
			# this evaluates the items at the end
			elif str(data[item]) != existing_data[item]:
				difference = True
				break
		return difference

	# this method updates the item you are working on
	# but only if it is different
	def update(self, item, data, existing_data):
		try:
			if self.is_different(data, existing_data):
				response = self.session.patch(self.server+'/rest/'+item+'/'+existing_data['id'],data=json.dumps(data))
				return True
			else:
				return False
		except urllib.error.HTTPError as error:
			self.handle_http_error(error)

	# only return data for use that is not the alias or the specifcally ignored paramaters
	# that are the same across all the modules
	def clean_data(self,data):
		arg_spec = [x for x in self.module.argument_spec.keys() if x not in self.ignore_params]
		return {key: value for key, value in data.items() if key in arg_spec and value}

	def remove(self, item, data, existing_data):
		try:
			response =  self.session.delete(self.server+'/rest/'+item+'/'+existing_data['id'])
			return True
		except urllib.error.HTTPError as error:
			self.handle_http_error(error)

	# translates item by name to id
	def get_item_by_name(self, item, name):
		try:
			response = self.session.get(self.server+'/rest/'+item)
			response_json = json.loads(response.read())
			if type(response_json['response']) == dict:
				for obj in response_json['response']['manageable']:
					if obj['name'] == name:
						response = self.session.get(self.server+'/rest/'+item+'/'+obj['id'])
						return json.loads(response.read())['response']
			else:
				for obj in response_json['response']:
					if obj['name'] == name:
						response = self.session.get(self.server+'/rest/'+item+'/'+obj['id'])
						return json.loads(response.read())['response']
			return None
		except urllib.error.HTTPError as error:
			self.handle_http_error(error)

	# helper method that subs a user paramter using a name with the id for the api call
	def build_id_field(self, item, name):
		return {'id': int(self.get_item_by_name(item, name)['id'])}

	def handle_http_error(self,error):
		self.module.fail_json(msg=str(error.code) +' '+ error.reason) #['error_msg'])
