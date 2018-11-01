import json
from six.moves import urllib
from ansible.module_utils.urls import Request
import copy
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

class SecurityCenterAPI:
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

    # recursivley walk the dictonary checking if data is the same
    # this just got real bad with edge cases
    def is_different(self,data, existing_data):
        different = False
        for item in data.keys():
            # if dict pass onto function again
            if type(data[item]) == dict:
                different = self.is_different(data[item], existing_data[item])
            # if list, loop through that and pass onto function
            elif type(data[item]) == list:
                if len(existing_data[item]) == 0:
                    different =  True
                    break
                dict_dif = []
                for dictionary in data[item]:
                    nested_match =[]
                    for dicts in existing_data[item]:
                        nested_match.append(self.is_different(dictionary,dicts))
                    if False in nested_match:
                        dict_dif.append(False)
                    else:
                        dict_dif.append(True)
                if True in dict_dif:
                    different = True
                    break
            elif str(data[item]) != existing_data[item]:
                different =  True
                break
        return different

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
    def clean_data(self,data):
        arg_spec = [x for x in self.module.argument_spec.keys() if x not in self.ignore_params]
        new_params = {}
        for item in data.keys():
            if item in arg_spec and data[item]:
                if '_' in item:
                    new_item = []
                    last_char = ''
                    for char in item:
                        if last_char == '_':
                            new_item.append(char.upper())
                        elif char == '_':
                            pass
                        else:
                            new_item.append(char)
                        last_char = char
                    new_params[''.join(new_item)] = data[item]
                else:
                    new_params[item] = data[item]
        return new_params

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
                    for list_item in params[item]:
                        if type(list_item) == dict:
                            nested_dict = {key:value for key, value in list_item.items() if key != 'name'}
                            nested_dict['id'] = self.__build_id_field__(id_maps[item]['endpoint'],list_item['name'],objtype)['id']
                            id_param_list.append(nested_dict)
                        else:
                            id_param_list.append(self.__build_id_field__(id_maps[item]['endpoint'],list_item,objtype))
                        params[item] = id_param_list
                else:
                    params[item] = self.__build_id_field__(id_maps[item]['endpoint'],params[item],objtype)

    # helper method that subs a user paramter using a name with the id for the api call
    def __build_id_field__(self, item, name,objtype='usable'):
        id_item = self.get_item_by_name(item, name,objtype)
        if not id_item:
            self.module.fail_json(msg='{item} does not exist on security center server'.format(item=item))
        return {'id': int(id_item['id'])}

    def __handle_http_error__(self,error):
        self.module.fail_json(msg=str(error.code) +' '+ error.reason)
