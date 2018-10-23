import pytest
from ansible.module_utils.tenable import TenableAPI
import unittest

tenable = TenableAPI('server',None,False)
module_params =  {
            "assets": None,
            "classifyMitigatedAge": 0,
            "credentials": None,
            "dhcpTracking": None,
            "emailOnFinish": False,
            "emailOnLaunch": False,
            "ipList": None,
            "maxScanTime": 3600,
            "name": "tenable-scan-test-scan",
            "password": "password",
            "policy": None,
            "reports": None,
            "repository": None,
            "rolloverType": "template",
            "scanningVirtualHosts": False,
            "schedule": {
                "type": "template"
            },
            "server": "https://server",
            "state": "absent",
            "timeoutAction": "import",
            "type": None,
            "username": "philip.bove",
            "validate_certs": False,
            "zone": None
        }

existing_data = {
    "type": "regular",
    "response": {
        "id": "410",
        "name": "tenable-scan-test-scan",
        "description": "",
        "ipList": "10.10.27.61",
        "type": "policy",
        "dhcpTracking": "false",
        "classifyMitigatedAge": "0",
        "emailOnLaunch": "false",
        "emailOnFinish": "false",
        "timeoutAction": "import",
        "scanningVirtualHosts": "false",
        "rolloverType": "template",
        "status": "0",
        "createdTime": "1540306447",
        "modifiedTime": "1540306505",
        "maxScanTime": "3600",
        "reports": [],
        "assets": [],
        "credentials": [
            {
                "id": "1000010",
                "name": "rhel-ngen",
                "description": "",
                "type": "ssh"
            }
        ],
        "numDependents": "0",
        "schedule": {
            "id": "383",
            "objectType": "scan",
            "type": "template",
            "start": "",
            "repeatRule": "",
            "nextRun": 0
        },
        "policy": {
            "id": "1000006",
            "context": "",
            "name": "5.4.x Windows DIACAP Vulnerability Scan) Policy",
            "description": "Nessus Policy exported from SecurityCenter",
            "tags": "",
            "owner": {
                "id": "1",
                "username": "rich",
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
            "id": "0",
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
            "username": "philip.bove",
            "firstname": "Philip",
            "lastname": "Bove"
        },
        "owner": {
            "id": "12",
            "username": "philip.bove",
            "firstname": "Philip",
            "lastname": "Bove"
        }
    },
    "error_code": 0,
    "error_msg": "",
    "warnings": [],
    "timestamp": 1540306556
}


class TestTenable(unittest.TestCase):

	def test_is_different(self):
		self.AssertFalse(Tenable.is_different(module_params,existing_data))

		
