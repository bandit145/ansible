from ansible.module_utils.tenable import TenableAPI
from units.compat.mock import patch, MagicMock, Mock
import unittest


class TestTenable(unittest.TestCase):

	def set_up(self):
		self.module = MagicMock(name='AnsibleModule')
		self.module.check_mode = False
		self.module.params= {
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
            "policy": "5.4.x non-Windows DIACAP Vulnerability Scan) Policy",
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

    self.sexisting_data = {
    "type": "regular",
    "response": {
        "id": "439",
        "name": "tenable-scan-test-scan",
        "description": "",
        "ipList": "10.10.27.61,10.10.27.62",
        "type": "policy",
        "dhcpTracking": "false",
        "classifyMitigatedAge": "0",
        "emailOnLaunch": "false",
        "emailOnFinish": "false",
        "timeoutAction": "import",
        "scanningVirtualHosts": "false",
        "rolloverType": "template",
        "status": "0",
        "createdTime": "1540400625",
        "modifiedTime": "1540400625",
        "maxScanTime": "3600",
        "reports": [],
        "assets": [],
        "credentials": [],
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
            "name": "5.4.x non-Windows DIACAP Vulnerability Scan) Policy",
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
        "zone": {
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
    },
    "error_code": 0,
    "error_msg": "",
    "warnings": [],
    "timestamp": 1540400647
}


	def test_is_different(self):
		tenable = TenableAPI(self.module)
		self.AssertFalse(Tenable.is_different(self.module.params,self.existing_data))
		diff_data = existing_data.deep_copy()
		diff_data['ipList'] = '192.168.1.1'
		self.AssertTrue(Tenable.is_different(self.module.params,diff_data))

	def test_clean_data(self):
		tenable = TenableAPI(self.module)
		self.AssertEqual(TenableAPI.clean_data(), {
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
            "policy": "5.4.x non-Windows DIACAP Vulnerability Scan) Policy",
            "repository": "cloud repos high > 10.10.xx.xx",
            "rolloverType": "template",
            "schedule": {
                "type": "template"
            },
            "state": "present",
            "timeoutAction": "import",
            "type": "policy",
        })

		
