from scapy.config import conf
conf.load_extensions.append("scapy-wmi")
conf.exts.loadall()
from scapy.layers.ntlm import NTLMSSP
from scapy.layers.kerberos import KerberosSSP
from scapy.layers.spnego import SPNEGOSSP
from scapy.layers.wmiclient import wmiclient
from scapy.main import load_module
from scapy.modules.ticketer import Ticketer


from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from scapy_wmi.wmiclient import wmiclient

if __name__ == "__main__":
    load_module("ticketer")
    t = Ticketer()
    # t.request_tgt("GREP7\Administrator", ip='192.168.100.100', password="StrongPa55!")
    # t.request_st(0, "HOST/WIN-8K15VKV24SG", ip="192.168.100.100")
    # t.save_ccache("ticket", 1)
    t.open_ccache("ticket")
    t.show()

    ntlmssp = NTLMSSP(UPN="Administrator", PASSWORD="StrongPa55!")
    ssp = SPNEGOSSP([
        # ntlmssp,
        t.ssp(0)
    ])

    wmiclient("192.168.100.100", ssp=ssp, debug=1, REQUIRE_ENCRYPTION=True)

    # client = WMI_Client(ntlmssp, DCE_C_AUTHN_LEVEL.PKT_INTEGRITY, verb=False)
    # client.connect("192.168.100.100")

    # namespace = client.get_namespace()
    # ppEnum = client.query(namespace, "SELECT name FROM Win32_PerfRawData_PerfProc_Process")
    # interfaces = client.get_query_result(ppEnum)
    # # ppEnum.release()
    # obj_ = OBJREF(interfaces[0].abData)
    # # Do thing to get properties
    # encodingUnit: ENCODING_UNIT = ENCODING_UNIT(obj_.pObjectData.load)
    # objBlk: OBJECT_BLOCK = encodingUnit.ObjectBlock
    # objBlk.parseObject()
    # record = objBlk.ctCurrent.properties
    # print(record)

    # ppEnum2 = client.query(namespace, "SELECT IDProcess FROM Win32_PerfRawData_PerfProc_Process")
    # interfaces = client.get_query_result(ppEnum2)
    # ppEnum2.release()
    # obj_ = OBJREF(interfaces[0].abData)
    # # Do thing to get properties
    # encodingUnit: ENCODING_UNIT = ENCODING_UNIT(obj_.pObjectData.load)
    # objBlk: OBJECT_BLOCK = encodingUnit.ObjectBlock
    # objBlk.parseObject()
    # record = objBlk.ctCurrent.properties
    # print(record)
    # namespace.release()
    # client.close()
