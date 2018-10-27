import json
from six.moves import urllib
from ansible.module_utils.urls import Request

class TenableAPI:
    ignore_params = ['username', 'password','validate_certs','state','server']

    def __init__(self, module):
        self.session = Request(validate_certs=module.params['validate_certs'],headers={'Content-Type':'application/json'})
        self.module = module


    def login(self):
        try:
            response = self.session.post(self.module.params['server']+'/rest/token', data=(json.dumps({'username':self.module.params['username'],
                'password':self.module.params['password']})))
            self.session.headers['X-SecurityCenter'] = str(json.loads(response.read())['response']['token'])
        except urllib.error.HTTPError as error:
            self.__handle_http_error__(error)
    
    def exists(self,item,data):
        if self.get_item_by_name(item, data['name']) != None:
            return True
        return False

    def create(self, item, data):
        try:
            response = self.session.post(self.module.params['server']+'/rest/'+item,data=json.dumps(data))
        except urllib.error.HTTPError as error:
            self.__handle_http_error__(error)

    # This is a mess but It's nice if you don't have to rewrite a checker per module
    # recursivley walk the dictonary checking if data is the same
    def is_different(self,data, existing_data):
        difference = False
        for item in data.keys():
            # if dict pass onto function again
            if item not in existing_data.keys():
                return True
            elif type(data[item]) == dict:
                difference = self.is_different(data[item], existing_data[item])
            # if list, loop through that and pass dicts onto function
            elif type(data[item]) == list:
                if len(existing_data[item]) == 0:
                    difference = True
                    break
                for dictionary in data[item]:
                    id_dict = None
                    for dicts in existing_data[item]:
                        if str(dictionary['id']) == dicts['id']:
                            id_dict = dicts
                            break
                    if id_dict:
                        difference = self.is_different(dictionary,id_dict)
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
                response = self.session.patch(self.module.params['server']+'/rest/'+item+'/'+existing_data['id'],data=json.dumps(data))
                return True
            else:
                return False
        except urllib.error.HTTPError as error:
            self.__handle_http_error__(error)

    # only return data for use that is not the alias or the specifcally ignored paramaters
    # that are the same across all the modules
    def clean_data(self):
        arg_spec = [x for x in self.module.argument_spec.keys() if x not in self.ignore_params]
        return {key: value for key, value in self.module.params.items() if key in arg_spec and value}

    def remove(self, item, data, existing_data):
        try:
            response =  self.session.delete(self.module.params['server']+'/rest/'+item+'/'+existing_data['id'])
            return True
        except urllib.error.HTTPError as error:
            self.__handle_http_error__(error)

    # translates item by name to id
    def get_item_by_name(self, item, name,objtype='manageable'):
        try:
            response = self.session.get(self.module.params['server']+'/rest/'+item)
            response_json = json.loads(response.read())
            if type(response_json['response']) == dict:
                for obj in response_json['response'][objtype]:
                    if obj['name'] == name:
                        response = self.session.get(self.module.params['server']+'/rest/'+item+'/'+obj['id'])
                        return json.loads(response.read())['response']
            else:
                for obj in response_json['response']:
                    if obj['name'] == name:
                        response = self.session.get(self.module.params['server']+'/rest/'+item+'/'+obj['id'])
                        return json.loads(response.read())['response']
            return None
        except urllib.error.HTTPError as error:
            self.__handle_http_error__(error)

    def build_id_fields(self,id_maps, params,objtype='usable'):
        for item in id_maps.keys():
            if item in params.keys():
                if self.module.argument_spec[item]['type'] == list:
                    id_param_list = []
                    for name in params[item]:
                        id_param_list.append(self.__build_id_field__(id_maps[item]['endpoint'],name,objtype))
                        params[item] = id_param_list 
                else:
                    params[item] = self.__build_id_field__(id_maps[item]['endpoint'],params[item],objtype)

    # helper method that subs a user paramter using a name with the id for the api call
    def __build_id_field__(self, item, name,objtype='usable'):
        return {'id': int(self.get_item_by_name(item, name,objtype)['id'])}

    def __handle_http_error__(self,error):
        self.module.fail_json(msg=str(error.code) +' '+ error.reason)
