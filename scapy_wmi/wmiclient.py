from functools import partial
import uuid
from scapy.utils import (
    CLIUtil,
)
from scapy.layers.spnego import SPNEGOSSP
from scapy.layers.gssapi import SSP
from scapy.config import conf
from scapy.layers.dcerpc import (
    find_com_interface,
    DCE_C_AUTHN_LEVEL,
    NDRPointer,
    RPC_C_IMP_LEVEL,
)
from scapy.layers.msrpce.msdcom import DCOM_Client, ObjectInstance, OBJREF
from scapy_wmi.msrpce.raw.ms_wmi import (
    NTLMLogin_Request,
    FLAGGED_WORD_BLOB,
    ExecQuery_Request,
    ExecQuery_Response,
    IENUMWBEMCLASSOBJECT_OPNUMS,
    MInterfacePointer,
    GetObject_Request,
    GetObject_Response,
    ExecMethod_Request,
    ExecMethod_Response,
)
from scapy_wmi.msrpce.mswmio import ENCODING_UNIT, OBJECT_BLOCK
from scapy_wmi.types.wmi_classes import WMI_Class
from scapy.packet import Packet

# TODO
# Implement shell
# Fix ExecQuery with SSP Kerberos
# SSPNEGO, fix two ssp
# Implement class, filter


class IWbemClassObject():
    """
    The IWbemClassObject interface represents a WMI object, such as a WMI class or an object
    instance. All CIM objects (CIM classes and CIM instances) that are passed during WMI calls
    between the client and server are objects of this interface
    """

    encodingUnit: ENCODING_UNIT
    objRef: OBJREF

    fields_desc = []

    def __init__(self, interface: MInterfacePointer):
        self.objRef = OBJREF(interface.abData)

        self.encodingUnit: ENCODING_UNIT = ENCODING_UNIT(self.objRef.pObjectData.load)
        self.encodingUnit.ObjectBlock.parseObject()

        if self.encodingUnit.ObjectBlock.isInstance():
            raise ValueError("This is an instance")
        else:
            self.createMethods(self.getClassName(), self.getMethods())

    def getClassName(self) -> str:
        if self.encodingUnit.ObjectBlock.isInstance():
            return self.encodingUnit.ObjectBlock.InstanceType.CurrentClass.getClassName().split(
                " "
            )[
                0
            ]
        else:
            return self.encodingUnit.ObjectBlock.ClassType.CurrentClass.getClassName().split(
                " "
            )[
                0
            ]

    def getMethods(self):
        if self.encodingUnit.ObjectBlock.ctCurrent is not None:
            return self.encodingUnit.ObjectBlock.ctCurrent["methods"]
        return dict()

    def getProperties(self):
        if self.encodingUnit.ObjectBlock.ctCurrent:
            return self.encodingUnit.ObjectBlock.ctCurrent["properties"]
        return dict()

    def createMethods(self, className: str, methods: dict):
        class FunctionPool:
            def __init__(self, function):
                self.function = function

            def __getitem__(self, item):
                return partial(self.function, item)

        @FunctionPool
        def innerMethod(staticArgs, *args):
            className: str = staticArgs[0] 
            methodDefinition: dict = staticArgs[1]
            print(methodDefinition)

        for methodName in methods:
           innerMethod.__name__ = methodName
           setattr(self,innerMethod.__name__,innerMethod[className,methods[methodName]])
       

class WMI_Client(DCOM_Client):
    auth_level: DCE_C_AUTHN_LEVEL
    current_namespace: ObjectInstance

    def __init__(self, ssp: SSP, auth_level: DCE_C_AUTHN_LEVEL, verb: bool):
        self.auth_level = auth_level
        super(WMI_Client, self).__init__(
            ssp=ssp,
            auth_level=auth_level,
            verb=verb,
            impersonation_type=RPC_C_IMP_LEVEL.IMPERSONATE,
        )

    def get_namespace(self, namespace_str: str = "root/cimv2") -> ObjectInstance:
        """
        Don"t forget to release after usage

        :param self: Description
        :param namespace_str: Description
        :type namespace_str: str
        :return: Description
        :rtype: ObjectInstance
        """
        CLSID_WbemLevel1Login = uuid.UUID("8BC3F05E-D86B-11D0-A075-00C04FB68820")
        IID_IWbemLevel1Login = find_com_interface("IWbemLevel1Login")

        objref = self.RemoteCreateInstance(
            clsid=CLSID_WbemLevel1Login,
            iids=[IID_IWbemLevel1Login],
        )

        result = objref.sr1_req(
            pkt=NTLMLogin_Request(
                wszNetworkResource="//./" + namespace_str,
            ),
            iface=IID_IWbemLevel1Login,
            auth_level=self.auth_level,
        )
        if result.ppNamespace is None:
            raise ValueError("NTLMLogin_Request failed !")
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

    def query(
        self, query: str, objref_wmi: ObjectInstance | None = None
    ) -> ObjectInstance:
        lang = "WQL\0"
        pktctr = ExecQuery_Request(
            strQueryLanguage=NDRPointer(
                referent_id=0x72657355,
                value=FLAGGED_WORD_BLOB(
                    max_count=len(lang),
                    cBytes=len(lang) * 2,
                    clSize=len(lang),
                    asData=lang.encode("utf-16le"),
                ),
            ),
            strQuery=NDRPointer(
                referent_id=0x72657356,
                value=FLAGGED_WORD_BLOB(
                    max_count=len(query),
                    cBytes=len(query) * 2,
                    clSize=len(query),
                    asData=query.encode("utf-16le"),
                ),
            ),
        )
        if objref_wmi is None:
            objref_wmi = self.current_namespace

        result_query = objref_wmi.sr1_req(
            pkt=pktctr,
            iface=find_com_interface("IWbemServices"),
            auth_level=self.auth_level,
        )

        if not isinstance(result_query, ExecQuery_Response):
            result_query.show()
            raise ValueError("Query failed !")

        # Unmarshall
        ppEnum_value: MInterfacePointer = (
            result_query.ppEnum.value
        )  # IEnumWbemClassObject
        obj_ppEnum = self.UnmarshallObjectReference(
            ppEnum_value,
            iid=find_com_interface("IEnumWbemClassObject"),
        )

        return obj_ppEnum

    def getObject(
        self, objectPath: str, objref_wmi: ObjectInstance | None = None
    ) -> MInterfacePointer:
        null_val_ptr = MInterfacePointer(max_count=0, ulCntData=0)
        pktctr = GetObject_Request(
            strObjectPath=NDRPointer(
                referent_id=0x72657355,
                value=FLAGGED_WORD_BLOB(
                    max_count=len(objectPath),
                    cBytes=len(objectPath) * 2,
                    clSize=len(objectPath),
                    asData=objectPath.encode("utf-16le"),
                ),
            ),
            # lFlags=0x00000010,
            pCtx=NDRPointer(
                referent_id=0,
                value=NDRPointer(referent_id=0x72657355, value=null_val_ptr),
            ),
        )

        if objref_wmi is None:
            objref_wmi = self.current_namespace

        result_query = objref_wmi.sr1_req(
            pkt=pktctr,
            iface=find_com_interface("IWbemServices"),
            auth_level=self.auth_level,
        )

        if not isinstance(result_query, GetObject_Response):
            result_query.show()
            raise ValueError("GetObject failed !")

        if result_query.ppObject is None:
            raise ValueError("Returned object pointer is NULL")

        ppEnum_value: MInterfacePointer = result_query.ppObject.value.value

        return ppEnum_value

    def execMethod(
        self,
        objectPath: str,
        method: str,
        obj: OBJREF,
        objref_wmi: ObjectInstance | None = None,
    ):
        pktctr = ExecMethod_Request(
            strObjectPath=NDRPointer(
                referent_id=0x72657355,
                value=FLAGGED_WORD_BLOB(
                    max_count=len(objectPath),
                    cBytes=len(objectPath) * 2,
                    clSize=len(objectPath),
                    asData=objectPath.encode("utf-16le"),
                ),
            ),
            strMethodName=NDRPointer(
                referent_id=0x72657355,
                value=FLAGGED_WORD_BLOB(
                    max_count=len(objectPath),
                    cBytes=len(objectPath) * 2,
                    clSize=len(objectPath),
                    asData=objectPath.encode("utf-16le"),
                ),
            ),
            pCtx=NDRPointer(
                referent_id=0,
                value=NDRPointer(
                    referent_id=0x72657355,
                    value=MInterfacePointer(max_count=0, ulCntData=0),
                ),
            ),
            # pInParams=None,
        )

        if objref_wmi is None:
            objref_wmi = self.current_namespace

        result_query = objref_wmi.sr1_req(
            pkt=pktctr,
            iface=find_com_interface("IWbemServices"),
            auth_level=self.auth_level,
        )

        if not isinstance(result_query, ExecMethod_Response):
            result_query.show()
            raise ValueError("ExecMethod failed !")

    def get_query_result(self, obj_ppEnum: ObjectInstance) -> list[MInterfacePointer]:
        op = IENUMWBEMCLASSOBJECT_OPNUMS[4]  # opnum 4 -> Next
        req_cls = op.request

        nextrq = req_cls(lTimeout=-1, uCount=1)

        interfaces: list[MInterfacePointer] = []
        # Loop next
        while True:
            # Next request
            result_next = obj_ppEnum.sr1_req(
                pkt=nextrq,
                iface=find_com_interface("IEnumWbemClassObject"),
                auth_level=self.auth_level,
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
        op = IENUMWBEMCLASSOBJECT_OPNUMS[4]  # opnum 4 -> Next
        req_cls = op.request

        nextrq = req_cls(lTimeout=-1, uCount=1)

        acc = 0
        # Loop next
        while True:
            # Next request
            result_next = obj_ppEnum.sr1_req(
                pkt=nextrq,
                iface=find_com_interface("IEnumWbemClassObject"),
                auth_level=self.auth_level,
            )

            if result_next.puReturned == 0:
                break
            else:
                acc += 1
        return acc

    def get_query_result_object(self, obj_ppEnum: ObjectInstance) -> list[WMI_Class]:
        op = IENUMWBEMCLASSOBJECT_OPNUMS[4]  # opnum 4 -> Next
        req_cls = op.request

        nextrq = req_cls(lTimeout=-1, uCount=1)

        objects: list[WMI_Class] = []
        # Loop next
        while True:
            # Next request
            result_next = obj_ppEnum.sr1_req(
                pkt=nextrq,
                iface=find_com_interface("IEnumWbemClassObject"),
                auth_level=self.auth_level,
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
                            encodingUnit: ENCODING_UNIT = ENCODING_UNIT(
                                obj_.pObjectData.load
                            )
                            objBlk: OBJECT_BLOCK = encodingUnit.ObjectBlock
                            objBlk.parseObject()
                            record = objBlk.ctCurrent["properties"]
                            objects.append(WMI_Class(record))
        return objects


@conf.commands.register
class wmiclient(CLIUtil):
    r"""
    A simple WMI client CLI powered by Scapy

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
    namespace_cache: dict[str, list[str]]
    classes_cache: dict[str, dict[str, OBJECT_BLOCK]]

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

        auth_level = DCE_C_AUTHN_LEVEL.PKT_INTEGRITY
        if REQUIRE_ENCRYPTION:
            auth_level = DCE_C_AUTHN_LEVEL.PKT_PRIVACY

        self.namespace_cache = dict()
        self.classes_cache = dict()
        # Create connection
        self.client = WMI_Client(ssp=ssp, auth_level=auth_level, verb=bool(debug))
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

    @CLIUtil.addcomplete(query)
    def query_complete(self, raw_query: str) -> list:
        if "FROM " in raw_query:
            cache = self.classes_cache.get(self.current_namescape)
            if cache is not None:
                split_query = raw_query.split("FROM ")
                return [
                    split_query[0] + "FROM " + elt
                    for elt in cache.keys()
                    if elt.startswith(split_query[-1])
                ]
            else:
                return []
        else:
            return []

    @CLIUtil.addoutput(query)
    def query_output(self, interfaces):
        for interface in interfaces:
            obj_ = OBJREF(interface.abData)
            # Do thing to get properties
            encodingUnit: ENCODING_UNIT = ENCODING_UNIT(obj_.pObjectData.load)
            objBlk: OBJECT_BLOCK = encodingUnit.ObjectBlock
            objBlk.parseObject()
            record = objBlk.ctCurrent["properties"]
            # Get padding, get the longer title
            pad_len = 0
            for col in record:
                if len(col) > pad_len:
                    pad_len = len(col)
            # Display
            for key in record:
                print(f"{key}{" " * (pad_len - len(key))}: ", end="")
                if type(record[key]["value"]) is list:
                    for item in record[key]["value"]:
                        print(item, end=", ")
                    print()
                else:
                    print("%s" % record[key]["value"])
            print()

    @CLIUtil.addcommand()
    def getclass(self, classname: str):
        ppEnum = self.client.query(
            self._parsequery(f"SELECT * FROM {classname}"), self.objref_wmi
        )
        interfaces = self.client.get_query_result(ppEnum)
        ppEnum.release()
        return interfaces

    @CLIUtil.addoutput(getclass)
    def class_output(self, interfaces):
        for interface in interfaces:
            obj_ = OBJREF(interface.abData)
            # Do thing to get properties
            encodingUnit: ENCODING_UNIT = ENCODING_UNIT(obj_.pObjectData.load)
            objBlk: OBJECT_BLOCK = encodingUnit.ObjectBlock
            objBlk.parseObject()
            record = objBlk.ctCurrent["properties"]
            # Get padding, get the longer title
            pad_len = 0
            for col in record:
                if len(col) > pad_len:
                    pad_len = len(col)
            # Display
            for key in record:
                print(f"{key}{" " * (pad_len - len(key))}: ", end="")
                if type(record[key]["value"]) is list:
                    for item in record[key]["value"]:
                        print(item, end=", ")
                    print()
                else:
                    print("%s" % record[key]["value"])
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
        return stripped + "\0"

    def _list_namespaces(self, parent_namespace: str) -> list:
        stripped_namespace = parent_namespace.strip("/")
        from_cache = self.namespace_cache.get(stripped_namespace)
        if from_cache is not None:
            return from_cache

        objref_wmi: ObjectInstance
        if stripped_namespace == self.current_namescape:
            objref_wmi = self.objref_wmi
        else:
            objref_wmi = self.client.get_namespace(stripped_namespace)
        ppEnum = self.client.query("SELECT * FROM __Namespace", objref_wmi)
        ns_interfaces = self.client.get_query_result_object(ppEnum)
        ppEnum.release()
        if stripped_namespace != self.current_namescape:
            objref_wmi.release()
        names = []
        for elt in ns_interfaces:
            names.append(parent_namespace + elt.Name["value"])
        self.namespace_cache[stripped_namespace] = names
        return names

    @CLIUtil.addcommand()
    def namespace(self, namespace: str):
        new_namespace = self.client.get_namespace(namespace)
        self.objref_wmi.release()
        self.objref_wmi = new_namespace
        self.current_namescape = namespace
        print("Switched to " + namespace)

    @CLIUtil.addcomplete(namespace)
    def namespace_complete(self, namespace: str) -> list:
        if namespace.endswith("/") and namespace.startswith("root/"):
            return self._list_namespaces(namespace)
        elif not namespace.startswith("root"):
            return ["root/"]
        else:
            return self._list_namespaces("/".join(namespace.split("/")[:-1]) + "/")

    def _list_class(self, namespace: str):
        objref_wmi: ObjectInstance
        if namespace.strip("/") == self.current_namescape:
            objref_wmi = self.objref_wmi
        else:
            objref_wmi = self.client.get_namespace(namespace.strip("/"))
        ppEnum = self.client.query("SELECT * FROM meta_class", objref_wmi)
        class_interfaces = self.client.get_query_result(ppEnum)
        ppEnum.release()
        return class_interfaces

    @CLIUtil.addcommand()
    def list(self):
        return self._list_class(self.current_namescape)

    def _update_class_cache(self, classname: str, objBlk: OBJECT_BLOCK):
        if not self.classes_cache.__contains__(self.current_namescape):
            self.classes_cache[self.current_namescape] = dict(classname=objBlk)
        else:
            self.classes_cache[self.current_namescape][classname] = objBlk

    @CLIUtil.addoutput(list)
    def list_output(self, interfaces):
        import textwrap

        print(f"{"Name":<34}{"Methods":<34}{"Properties":<34}")
        print(f"{"----":<34}{"-------":<34}{"----------":<34}")
        for interface in interfaces:
            obj_ = OBJREF(interface.abData)
            # Do thing to get properties
            encodingUnit: ENCODING_UNIT = ENCODING_UNIT(obj_.pObjectData.load)
            objBlk: OBJECT_BLOCK = encodingUnit.ObjectBlock
            objBlk.parseObject()
            name = objBlk.ctCurrent["name"].split(" : ")[0]
            self._update_class_cache(name, objBlk)
            methods = objBlk.ctCurrent["methods"].keys()
            properties = objBlk.ctCurrent["properties"].keys()
            print(
                f"{name[:31] + "..." if len(name) > 34 else name:<34}",
                f"{"{"+textwrap.shorten(", ".join(methods), 34, placeholder="...", break_long_words=True)+"}":<34}",
                f"{"{"+textwrap.shorten(", ".join(properties), 34, placeholder="...", break_long_words=True)+"}":<34}",
            )
