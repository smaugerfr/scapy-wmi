import unittest
from scapy.config import conf
conf.load_extensions.append("scapy-wmi")
conf.exts.loadall()
from scapy_wmi.wmiclient import wmiclient
from scapy.layers.ntlm import NTLMSSP

IP = "192.168.100.100"

class ClientTestCase(unittest.TestCase):
    def setUp(self):
        ntlmssp = NTLMSSP(UPN="Administrator", PASSWORD="StrongPa55!")
        self.cli = wmiclient(IP, ssp=ntlmssp, debug=0, REQUIRE_ENCRYPTION=False, cli=False)

    def test_class_command(self):
        self.cli.getclass("Win32_OperatingSystem")

    def test_class_command_output(self):
        interfaces = self.cli.getclass("Win32_OperatingSystem")
        self.cli.class_output(interfaces)
        input("User Check output")

    def test_list_command(self):
        interfaces = self.cli.list()
        self.assertTrue(len(interfaces) > 0, "No result from list command")

    def test_get_object_request(self):
        self.cli.client.getObject("Win32_Process")

class WMIOTestCase(unittest.TestCase):
    def setUp(self):
        ntlmssp = NTLMSSP(UPN="Administrator", PASSWORD="StrongPa55!")
        self.cli = wmiclient(IP, ssp=ntlmssp, debug=0, REQUIRE_ENCRYPTION=False, cli=False)
    
    def test_instance_type(self):
        interfaces = self.cli.getclass("Win32_OperatingSystem")
        from scapy_wmi.msrpce.mswmio import OBJECT_BLOCK, ENCODING_UNIT
        from scapy.layers.msrpce.msdcom import OBJREF
        for interface in interfaces:
            obj_ = OBJREF(interface.abData)
            # Do thing to get properties
            encodingUnit: ENCODING_UNIT = ENCODING_UNIT(obj_.pObjectData.load)
            objBlk: OBJECT_BLOCK = encodingUnit.ObjectBlock
            self.assertTrue(objBlk.isInstance(), "This class is not of instance type")
            objBlk.parseObject()
            objBlk.printInformation()
            input("User Check output")

    def test_class_type(self):
        interface = self.cli.client.getObject("Win32_Process")
        from scapy_wmi.msrpce.mswmio import OBJECT_BLOCK, ENCODING_UNIT
        from scapy.layers.msrpce.msdcom import OBJREF
        obj_ = OBJREF(interface.abData)
        # Do thing to get properties
        encodingUnit: ENCODING_UNIT = ENCODING_UNIT(obj_.pObjectData.load)
        objBlk: OBJECT_BLOCK = encodingUnit.ObjectBlock
        self.assertTrue(not objBlk.isInstance(), "This class is not of class type")
        objBlk.parseObject()
        objBlk.printInformation()
        input("User Check output")

    def test_list_command_output(self):
        interfaces = self.cli.list()
        self.cli.list_output(interfaces)



if __name__ == '__main__':
    unittest.main()