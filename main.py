from scapy.config import conf
conf.load_extensions.append("scapy-wmi")
conf.exts.loadall()
from scapy.layers.ntlm import NTLMSSP
from scapy.layers.spnego import SPNEGOSSP
from scapy.layers.wmiclient import wmiclient


from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from scapy_wmi.wmiclient import wmiclient

if __name__ == "__main__":
    ntlmssp = NTLMSSP(UPN="Administrator", PASSWORD="StrongPa55!")
    ssp = SPNEGOSSP([
        ntlmssp,
    ])

    wmiclient("192.168.100.100", ssp=ntlmssp, debug=0, REQUIRE_ENCRYPTION=True)
