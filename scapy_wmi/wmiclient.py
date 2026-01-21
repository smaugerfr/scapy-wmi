import uuid
from scapy.utils import (
    CLIUtil,
)
from scapy.layers.spnego import SPNEGOSSP
from scapy.layers.dcerpc import find_com_interface
from scapy.layers.dcerpc import *
from scapy.layers.msrpce.all import *
from scapy.layers.msrpce.msdcom import DCOM_Client, ObjectInstance, OBJREF
import scapy.layers.msrpce.raw.ms_wmi # type: ignore
from scapy.layers.msrpce.raw.ms_wmi import NTLMLogin_Request, FLAGGED_WORD_BLOB, ExecQuery_Request, ExecQuery_Response # type: ignore
from scapy.layers.msrpce.raw.ms_wmi import IENUMWBEMCLASSOBJECT_OPNUMS, MInterfacePointer # type: ignore
from scapy.layers.msrpce.mswmio import ENCODING_UNIT, OBJECT_BLOCK # type: ignore
from scapy_wmi.types.wmi_classes import WMI_Class

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from msrpce.raw.ms_wmi import NTLMLogin_Request, FLAGGED_WORD_BLOB, ExecQuery_Request, ExecQuery_Response
    from msrpce.raw.ms_wmi import IENUMWBEMCLASSOBJECT_OPNUMS, MInterfacePointer
    from msrpce.mswmio import ENCODING_UNIT, OBJECT_BLOCK
    from types.wmi_classes import WMI_Class

# TODO
# Change namespace
# List class
# Implement class, filter
# Impersonification
# SSPNEGO
# Deal with release, it doesnt work on unmarshalled obj
# solve six problem

class WMI_Client(DCOM_Client):
    auth_level: DCE_C_AUTHN_LEVEL
    current_namespace: ObjectInstance
    def __init__(
        self,
        ssp: SSP,
        auth_level: DCE_C_AUTHN_LEVEL,
        verb: bool
    ):
        self.auth_level = auth_level
        super(WMI_Client, self).__init__(
            ssp=ssp,
            auth_level=auth_level,
            verb=verb
        )

    def get_namespace(self, namespace_str: str = "root/cimv2") -> ObjectInstance:
        CLSID_WbemLevel1Login=uuid.UUID("8BC3F05E-D86B-11D0-A075-00C04FB68820")
        IID_IWbemLevel1Login=find_com_interface("IWbemLevel1Login")

        objref = self.RemoteCreateInstance(
            clsid=CLSID_WbemLevel1Login,
            iids=[IID_IWbemLevel1Login],
        )

        result = objref.sr1_req(
            pkt=NTLMLogin_Request(
                wszNetworkResource="//./"+namespace_str,
            ),
            iface=IID_IWbemLevel1Login,
            auth_level=self.auth_level
        )
        # objref.release()
        # If i release this i can't recreate one
        value = result.ppNamespace.value
        objref_wmi = self.UnmarshallObjectReference(
            value,
            iid=find_com_interface("IWbemServices"),
        )

        return objref_wmi
    
    def set_namespace(self, namespace_str: str = "root/cimv2") -> None:
        objref_wmi = self.get_namespace(namespace_str)
        self.current_namespace = objref_wmi

    def query(self, query: str, objref_wmi: ObjectInstance | None = None) -> ObjectInstance:
        lang="WQL\0"
        pktctr=ExecQuery_Request(
                strQueryLanguage=NDRPointer(
                    referent_id=0x72657355,
                    value=FLAGGED_WORD_BLOB(
                        max_count=len(lang),
                        cBytes=len(lang)*2,
                        clSize=len(lang),
                        asData=lang.encode("utf-16le")
                        )
                    ),
                strQuery=NDRPointer(
                    referent_id=0x72657356,
                    value=FLAGGED_WORD_BLOB(
                        max_count=len(query),
                        cBytes=len(query)*2,
                        clSize=len(query),
                        asData=query.encode("utf-16le")
                        )
                    )
            )
        if objref_wmi is None:
            objref_wmi = self.current_namespace

        result_query = objref_wmi.sr1_req(
            pkt=pktctr,
            iface=find_com_interface("IWbemServices"),
            auth_level=self.auth_level
        )

        if not isinstance(result_query, ExecQuery_Response):
            result_query.show()
            raise ValueError("Query failed !")

        # Unmarshall
        ppEnum_value: MInterfacePointer = result_query.ppEnum.value # IEnumWbemClassObject
        obj_ppEnum = self.UnmarshallObjectReference(
            ppEnum_value,
            iid=find_com_interface("IEnumWbemClassObject"),
        )

        return obj_ppEnum
    
    def get_query_result(self, obj_ppEnum: ObjectInstance) -> list[MInterfacePointer]:
        op = IENUMWBEMCLASSOBJECT_OPNUMS[4]   # opnum 4 -> Next
        req_cls = op.request

        nextrq = req_cls(
            lTimeout=-1,
            uCount=1
        )

        interfaces: list[MInterfacePointer] = []
        # Loop next
        while True:
            # Next request
            result_next = obj_ppEnum.sr1_req(
                pkt=nextrq,
                iface=find_com_interface("IEnumWbemClassObject"),
                auth_level=self.auth_level
            )
            
            if result_next.puReturned == 0:
                break
            else:
                # Take only MInterfacePointer
                for obj in result_next.apObjects:
                    for elt in obj.value:
                        for ptr in elt.value:
                            interfaces.append(ptr.value)

        return interfaces
    
    def count_query_result(self, obj_ppEnum: ObjectInstance) -> int:
        op = IENUMWBEMCLASSOBJECT_OPNUMS[4]   # opnum 4 -> Next
        req_cls = op.request

        nextrq = req_cls(
            lTimeout=-1,
            uCount=1
        )

        acc = 0
        # Loop next
        while True:
            # Next request
            result_next = obj_ppEnum.sr1_req(
                pkt=nextrq,
                iface=find_com_interface("IEnumWbemClassObject"),
                auth_level=self.auth_level
            )
            
            if result_next.puReturned == 0:
                break
            else:
                acc += 1
        return acc
    
    def get_query_result_object(self, obj_ppEnum: ObjectInstance) -> list[WMI_Class]:
        op = IENUMWBEMCLASSOBJECT_OPNUMS[4]   # opnum 4 -> Next
        req_cls = op.request

        nextrq = req_cls(
            lTimeout=-1,
            uCount=1
        )

        objects: list[WMI_Class] = []
        # Loop next
        while True:
            # Next request
            result_next = obj_ppEnum.sr1_req(
                pkt=nextrq,
                iface=find_com_interface("IEnumWbemClassObject"),
                auth_level=self.auth_level
            )
            
            if result_next.puReturned == 0:
                break
            else:
                # Take only MInterfacePointer
                for obj in result_next.apObjects:
                    for elt in obj.value:
                        for ptr in elt.value:
                            obj_ = OBJREF(ptr.value.abData)
                            # Do thing to get properties
                            encodingUnit: ENCODING_UNIT = ENCODING_UNIT(obj_.pObjectData.load)
                            objBlk: OBJECT_BLOCK = encodingUnit.ObjectBlock
                            objBlk.parseObject()
                            record = objBlk.ctCurrent.properties
                            objects.append(WMI_Class(record))
        return objects

@conf.commands.register
class wmiclient(CLIUtil):
    r"""
    A simple SMB client CLI powered by Scapy

    :param target: can be a hostname, the IPv4 or the IPv6 to connect to
    :param UPN: the upn to use (DOMAIN/USER, DOMAIN\USER, USER@DOMAIN or USER)
    :param guest: use guest mode (over NTLM)
    :param ssp: if provided, use this SSP for auth.
    :param kerberos_required: require kerberos
    :param port: the TCP port. default 445
    :param password: if provided, used for auth
    :param HashNt: if provided, used for auth (NTLM)
    :param HashAes256Sha96: if provided, used for auth (Kerberos)
    :param HashAes128Sha96: if provided, used for auth (Kerberos)
    :param ST: if provided, the service ticket to use (Kerberos)
    :param KEY: if provided, the session key associated to the ticket (Kerberos)
    :param cli: CLI mode (default True). False to use for scripting

    Some additional SMB parameters are available under help(SMB_Client). Some of
    them include the following:

    :param REQUIRE_ENCRYPTION: requires encryption.
    """
    client: WMI_Client
    objref_wmi: ObjectInstance

    def __init__(
        self,
        target: str,
        UPN: str = None,
        password: str = None,
        guest: bool = False,
        kerberos_required: bool = False,
        HashNt: bytes = None,
        HashAes256Sha96: bytes = None,
        HashAes128Sha96: bytes = None,
        timeout: int = 5,
        debug: int = 0,
        ssp=None,
        ST=None,
        KEY=None,
        cli=True,
        REQUIRE_ENCRYPTION=True,
        **kwargs,
    ):
        if cli:
            self._depcheck()
        assert UPN or ssp or guest, "Either UPN, ssp or guest must be provided !"
        # Do we need to build a SSP?
        if ssp is None:
            # Create the SSP (only if not guest mode)
            if not guest:
                ssp = SPNEGOSSP.from_cli_arguments(
                    UPN=UPN,
                    target=target,
                    password=password,
                    HashNt=HashNt,
                    HashAes256Sha96=HashAes256Sha96,
                    HashAes128Sha96=HashAes128Sha96,
                    ST=ST,
                    KEY=KEY,
                    kerberos_required=kerberos_required,
                )
            else:
                # Guest mode
                ssp = None

        auth_level=DCE_C_AUTHN_LEVEL.PKT_INTEGRITY
        if REQUIRE_ENCRYPTION:
            auth_level = DCE_C_AUTHN_LEVEL.PKT_PRIVACY

        # Create connection
        self.client = WMI_Client(
            ssp=ssp,
            auth_level=auth_level,
            verb=bool(debug)
            )
        self.client.connect(target, timeout)

        self.objref_wmi = self.client.get_namespace()
        self.current_namescape = "root/cimv2"
        
        # Start CLI
        if cli:
            self.loop(debug=debug)


    def ps1(self):
        return r"wmiclient > "

    def close(self):
        self.objref_wmi.release()
        self.client.close()
        print("Connection closed")

    @CLIUtil.addcommand(spaces=True)
    def query(self, raw_query: str):
        ppEnum = self.client.query(self._parsequery(raw_query), self.objref_wmi)
        interfaces = self.client.get_query_result(ppEnum)
        ppEnum.release()
        return interfaces

    @CLIUtil.addoutput(query)
    def query_output(self, interfaces):
        for interface in interfaces:
            obj_ = OBJREF(interface.abData)
            # Do thing to get properties
            encodingUnit: ENCODING_UNIT = ENCODING_UNIT(obj_.pObjectData.load)
            objBlk: OBJECT_BLOCK = encodingUnit.ObjectBlock
            objBlk.parseObject()
            record = objBlk.ctCurrent.properties
            # Get padding, get the longer title
            pad_len = 0
            for col in record:
                if len(col) > pad_len:
                    pad_len = len(col)
            # Display
            for key in record:
                print(f"{key}{" " * (pad_len - len(key))}: ", end="")
                if type(record[key]['value']) is list:
                    for item in record[key]['value']:
                        print(item, end=', ')
                    print()
                else:
                    print('%s' % record[key]['value'])
            print()

    def _parsequery(self, raw_query: str) -> str:
        """
        Docstring for _parsequery
        
        :param self: Transform a raw query to one to send to the server 
        :param raw_query: User input
        :type raw_query: str
        :return: Prepared query
        :rtype: str
        """
        # Strip
        stripped = raw_query.strip("; ")
        return stripped+"\0"
    
    def _list_namespaces(self, parent_namespace: str) -> list:
        objref_wmi: ObjectInstance
        if parent_namespace == self.current_namescape:
            objref_wmi = self.objref_wmi
        else:
            objref_wmi = self.client.get_namespace(parent_namespace)
        ns_interfaces = self.query(objref_wmi, "SELECT * FROM __Namespace")
        names = []
        for elt in ns_interfaces:
            names.append(elt["Name"])
        print(names)
        return names
    
    @CLIUtil.addcommand()
    def namespace(self, namespace: str):
        self.objref_wmi = self.client.get_namespace(namespace)
        self.current_namescape = namespace
        print("Switched to "+namespace)

    @CLIUtil.addcomplete(namespace)
    def namespace_complete(self, namespace: str) -> list:
        print("called")
        if namespace.endswith("/"):
            print("test")
            return self._list_namespaces(namespace.strip("/"))
        else:
            return []
