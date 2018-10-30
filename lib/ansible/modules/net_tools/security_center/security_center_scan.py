#!/usr/bin/env python
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from ansible.module_utils.basic import *
from ansible.module_utils.net_tools.security_center import SecurityCenterAPI

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}
DOCUMENTATION = r'''
module: security_center_scan
short_description: Manage scans in Tenable Security Center
description: Manage scans in Tenable Security Center.
version_added: 2.8
author: Philip Bove (@bandit145) <philip.bove@uspsector.com>
options:
  server:
    description:
      - security center server to communicate with
    required: true
    type: string
  username:
    description:
      - log on username for security center
    required: true
    type: string
  password:
    description:
      - log on password for security center
    required: true
    type: string
  state:
    description:
      - Specify state of scan.
    required: true
    default: present
    choices:
      - present
      - absent
    type: string
  name:
    description:
      - name of scan
    required: true 
    type: string
  type:
    description:
      - scan type. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
    required: true
    choices:
      - policy
      - plugin
    type: string
  zone:
    description:
      - zone that scan is for. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
    required: false
    type: string
  dhcp_tracking:
    description:
      - enable dhcp tracking. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
    required: false
    type: bool
    aliases:
      - dhcpTracking
  classify_mitigated_age:
    description:
      - mitigated age. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
    required: false
    type: int
  schedule:
    description:
      - scan schedule. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
    required: false
    type: dict
    suboptions:
        type: 
          description:
            - schedule type. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
        choices:
          - dependant
          - ical
          - never
          - rollover
          - template
  reports:
    description:
      - mitigated age. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
    required: false
    type: list
  repository:
    description:
      - repository for scan. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
    required: false
    type: string
  assets:
    description:
      - assets. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
    required: false
    type: list
  credentials:
    description:
      - credentials for scan. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
    required: false
    type: list
  email_on_launch:
    description:
      - email on scan launch. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
    required: false
    type: bool
    choices:
      - true
      - flase
    aliases:
      - emailOnLaunch
  email_on_finish:
    description:
      - email on scan finish. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
    required: false
    type: bool
    choices:
      - true
      - false
    aliases:
      - emailOnFinish
    timeout_action:
      description:
         - timeout action. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
      default: import
      aliases:
         - timeoutAction
      choices:
         - import
         - discard
         - rollover
      required: false
      type: str
    scanning_virtual_hosts:
      description:
         - scanning virtual hosts. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
      required: false
      aliases:
         - scanningVirtualHosts
      choices:
         - true
         - false
      type: bool
    rollover_type:
      description:
         - rollover type. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
      required: false
      default: template
      choices:
         - template
         - nextDay
      aliases:
         - rolloverType
      type: str
    policy:
      description:
         - scan policy. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
      required: false
      type: str
    ip_list:
      description:
         - list of targets by ip. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
      required: false
      aliases:
         - ipList
      type: list
    max_scan_time:
      description:
         - max scan time. See, L(Tenable dcumentation, https://docs.tenable.com/sccv/api/Scan.html)
      default: 3600
      aliases:
         - maxScanTime
      required: false
      type: int
    validate_certs:
      description:
         - validate tls certs.
      required: false
      choices:
         - true
         - false
      type: bool
'''
EXAMPLES = r'''
 - name: Create test-scan
   security_center_scan:
     server: https://server
     username: user
     password: password
     name: tenable-scan-test-scan
     type: policy
     policy: 5.4.x non-Windows DIACAP Vulnerability Scan Policy
     schedule: 
       type: template
     repository: cloud repos high > 10.10.xx.xx
     ip_list:
       - 10.10.27.61
       - 10.10.27.62
     state: present

 - name: Ensure test-scan is absent
   security_center_scan:
     server: https://server
     username: user
     password: password
     name: tenable-scan-test-scan
     state: absent


'''

# paramaters that require id mapping
ID_MAPS = {
    'repository':{'endpoint':'repository'},
    'zone':{'endpoint':'zone'},
    'policy':{'endpoint':'policy'},
    'credentials':{'endpoint':'credential'},
    'assets':{'endpoint':'asset'}
    }

def ensure(module):
    tenable = SecurityCenterAPI(module)
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


schedule_spec = dict(
    type=dict(type=str,required=True,choices=[True,False]),
)
reports_spec = dict(
    name=dict(type=str,required=True),
    report_source=dict(type=str,required=True,
        choices=['cumulative', 'patched', 'individual', 'lce', 'archive', 'mobile'],
        aliases=['ReportSource'])
)

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
                    classifyMitigatedAge = dict(type=int, required=False, 
                        aliases=['classify_mitigated_age']),
                    schedule = dict(type=dict, required=False,options=schedule_spec),
                    reports = dict(type=list,elements=dict, required=False,options=reports_spec),
                    repository = dict(type=str,required=False),
                    assets = dict(type=list, required=False),
                    credentials = dict(type=list, required=False),
                    emailOnLaunch = dict(type=bool, required=False, default=False, choices=[True, False],
                        aliases=['email_on_launch']),
                    emailOnFinish = dict(type=bool, required=False, default=False, choices=[True, False],
                        aliases=['email_on_finish']),
                    timeoutAction = dict(type=str, required=False, default='import', 
                        choices=['import','discard','rollover'], aliases=['timeout_action']),
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
