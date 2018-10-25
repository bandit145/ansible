#!/usr/bin/env python
from ansible.module_utils.basic import *
from ansible.module_utils.net_tools.tenable import TenableAPI

# paramaters that require id mapping
ID_MAPS = {
	'repository':{'endpoint':'repository'},
	'zone':{'endpoint':'zone'},
	'policy':{'endpoint':'policy'},
	'credentials':{'endpoint':'credential'},
	'assets':{'endpoint':'asset'}
	}

def ensure(module):
	tenable = TenableAPI(module)
	tenable.login()
	# get cleaned data
	new_params = tenable.clean_data()
	# check for existing scan
	existing_scan = tenable.get_item_by_name('scan',new_params['name'])
	if module.params['state'] == 'present':
		if 'ipList' in new_params.keys():
			new_params['ipList'] = ','.join(new_params['ipList'])
		# build id mappings from names provided
		tenable.build_id_fields(ID_MAPS,new_params)
		if existing_scan:
			module.exit_json(changed=tenable.update('scan', new_params, existing_scan))
		else:
			tenable.create('scan', new_params)
			module.exit_json(changed=True)
	else:
		if existing_scan:
			tenable.remove('scan', new_params, existing_scan)
			module.exit_json(changed=True)
		else:
			module.exit_json(changed=False)

def main():

	module = AnsibleModule(
				argument_spec = dict(
					server = dict(type=str, required=True),
					name = dict(type=str, required=True),
					username = dict(type=str,required=True),
					password = dict(type=str, required=True,no_log=True),
					type = dict(type=str, required=False, choices=['plugin', 'policy']),
					zone = dict(type=str, required=False),
					dhcpTracking = dict(type=bool, required=False, aliases=['dhcp_tracking']),
					classifyMitigatedAge = dict(type=int, required=False, default=0, 
						aliases=['classify_mitagated_age']),
					schedule = dict(type=dict, required=False,
						default={'type':'template'}),
					reports = dict(type=list, required=False),
					repository = dict(type=str,required=False),
					assets = dict(type=list, required=False),
					credentials = dict(type=list, required=False),
					emailOnLaunch = dict(type=bool, required=False, default=False, choices=[True, False],
						aliases=['email_on_launch']),
					emailOnFinish = dict(type=bool, required=False, default=False, choices=[True, False],
						aliases=['email_on_finish']),
					timeoutAction = dict(type=str, required=False, default='import', 
						choices=['import','discard','import'], aliases=['timeout_action']),
					scanningVirtualHosts = dict(type=bool, required=False, default=False, choices=[True, False],
						aliases=['scanning_virtual_hosts']),
					rolloverType = dict(type=str, required=False, default='template', choices=['nextDay','template'],
						aliases=['rollover_type']),
					policy = dict(type=str,required=False),
					ipList = dict(type=list, required=False,aliases=['ip_list']),
					maxScanTime = dict(type=int, required=False, default=3600, aliases=['max_scan_time']),
					validate_certs = dict(type=bool, required=False, default=True, choices=[True,False]),
					state = dict(type=str,required=False, default='present',choices=['present','absent'])
			),
			supports_check_mode=False
		)
	# verify items
	if module.params['state'] == 'present':
		if module.params['type'] == 'policy' and 'policy' not in module.params.keys():
			module.fail_json(msg='policy must be specified when type is "policy"')
		elif module.params['type'] == 'plugin' and 'plugin' not in module.params.keys():
			module.fail_json(msg='plugin must be specified when type is "plugin"')
		elif not module.params['ipList'] and not module.params['assets']:
			module.fail_json(msg='assets or ip_list must be provided (or both)')
		elif 'type' not in module.params['schedule']:
			module.fail_json(msg='must provide properly formatted dictionat for schedule')
		elif 'repository' not in module.params.keys():
			module.fail_json(msg='"repository" is required when state is present')
	ensure(module)

if __name__ == '__main__':
	main()
