from ansible.module_utils.net_tools.tenable import TenableAPI
from units.compat.mock import patch, MagicMock, Mock
import unittest
import copy


def get_mock_module():
    module = MagicMock(name='AnsibleModule')
    module.check_mode = False
    module.argument_spec = argument_spec = dict(
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
        )
    module.params= {
        "assets": None,
        "classifyMitigatedAge": 0,
        "credentials": None,
        "dhcpTracking": None,
        "emailOnFinish": False,
        "emailOnLaunch": False,
        "ipList": [
            "10.10.27.61",
            "10.10.27.62"
        ],
        "ip_list": [
            "10.10.27.61",
            "10.10.27.62"
        ],
        "maxScanTime": 3600,
        "name": "tenable-scan-test-scan",
        "password": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
        "policy": "5.4.x non-Windows DIACAP Vulnerability Scan Policy",
        "reports": None,
        "repository": "cloud repos high > 10.10.xx.xx",
        "rolloverType": "template",
        "scanningVirtualHosts": False,
        "schedule": {
            "type": "template"
        },
        "server": "https://server/",
        "state": "present",
        "timeoutAction": "import",
        "type": "policy",
        "username": "user",
        "validate_certs": False,
        "zone": None
    }
    return module

def get_existing_data():
    return {
        "id": "439",
        "name": "tenable-scan-test-scan",
        "description": "",
        "ipList": "10.10.27.61,10.10.27.62",
        "type": "policy",
        "classifyMitigatedAge": "0",
        "timeoutAction": "import",
        "rolloverType": "template",
        "status": "0",
        "createdTime": "1540400625",
        "modifiedTime": "1540400625",
        "maxScanTime": "3600",
        "numDependents": "0",
        "schedule": {
            "id": "409",
            "objectType": "scan",
            "type": "template",
            "start": "",
            "repeatRule": "",
            "nextRun": 0
        },
        "policy": {
            "id": "1000004",
            "context": "",
            "name": "5.4.x non-Windows DIACAP Vulnerability Scan Policy",
            "description": "Nessus Policy exported from SecurityCenter",
            "tags": "",
            "owner": {
            "id": "1",
                    "username": "user",
                    "firstname": "",
                    "lastname": ""
                },
                "ownerGroup": {
                    "id": "0",
                    "name": "Full Access",
                        "description": "Full Access group"
                }
        },
        "repository": {
            "id": "2",
            "name": "cloud repos high > 10.10.xx.xx",
            "description": ""
        },
        "canUse": "true",
        "canManage": "true",
        "plugin": {
                "id": -1,
                "name": "",
                "description": ""
            },
            "ownerGroup": {
                "id": "0",
                "name": "Full Access",
                "description": "Full Access group"
            },
            "creator": {
                "id": "12",
                "username": "user",
                "firstname": "user",
                "lastname": "user"
            },
            "owner": {
                "id": "12",
                "username": "user",
                "firstname": "user",
                    "lastname": "user"
            }
    }

def get_clean_data():
    return  {
            "ipList": [
                "10.10.27.61",
                "10.10.27.62"
            ],
          "maxScanTime": 3600,
          "name": "tenable-scan-test-scan",
          "policy": "5.4.x non-Windows DIACAP Vulnerability Scan Policy",
          "repository": "cloud repos high > 10.10.xx.xx",
          "rolloverType": "template",
          "schedule": {
              "type": "template"
          },
          "timeoutAction": "import",
          "type": "policy",
        }

class TestTenable(unittest.TestCase):

    def test_clean_data(self):
        module = get_mock_module()
        existing_data = get_existing_data()
        tenable = TenableAPI(module)
        self.assertEqual(tenable.clean_data(), get_clean_data())
        
    def test_is_different(self):
        module = get_mock_module()
        existing_data = get_existing_data()
        clean_data = get_clean_data()
        tenable = TenableAPI(module)
        clean_data['ipList'] = ','.join(clean_data['ipList'])
        clean_data['repository'] = {'id': 2}
        clean_data['policy'] = {'id': 1000004}
        self.assertFalse(tenable.is_different(clean_data,existing_data))
        existing_data['ipList'] = '192.168.1.1'
        self.assertTrue(tenable.is_different(clean_data,existing_data))
