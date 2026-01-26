# Implementation de [ms-wmio]

# [ms-wmio]
# All signed and unsigned integer types that consist of more than one octet MUST be encoded as little-endian

from enum import Enum
import struct
from typing import Optional, OrderedDict, Self
from scapy.packet import Packet
from scapy.fields import (
    StrLenField,
    LEIntField,
    ByteField,
    ConditionalField,
    PacketField,
    StrNullField,
    StrNullFieldUtf16,
    MultipleTypeField,
    SignedByteField,
    LESignedShortField,
    LEShortField,
    LESignedIntField,
    LESignedLongField,
    LELongField,
    ThreeBytesField
)


class ENCODED_STRING8(Packet):
    name = "EncodedString8"
    value: bytes
    fields_desc = [
        StrNullField("value", b""),
    ]

    def extract_padding(self, s):
        return b"", s


class ENCODED_STRING16(Packet):
    name = "EncodedString16"
    value: bytes
    fields_desc = [
        StrNullFieldUtf16("value", b""),
    ]

    def extract_padding(self, s):
        return b"", s


class ENCODED_STRING(Packet):
    name = "EncodedString"
    encodedStringFlag: int
    fields_desc = [
        ByteField("encodedStringFlag", 0),
    ]

    def guess_payload_class(self, payload):
        if self.encodedStringFlag == 0x00:
            return ENCODED_STRING8
        elif self.encodedStringFlag == 0x01:
            return ENCODED_STRING16
        return Packet.guess_payload_class(self, payload)

    def str_value(self) -> str:
        p: ENCODED_STRING8 | ENCODED_STRING16 = self.payload
        if isinstance(p, ENCODED_STRING8):
            return p.value.decode()
        else:
            return p.value.decode("utf-16le")

    def bytes_len(self) -> int:
        p: ENCODED_STRING8 | ENCODED_STRING16 = self.payload
        if isinstance(p, ENCODED_STRING8):
            return len(p.value) + 1 + 1  # Flag len + Null byte
        else:
            return len(p.value) + 1 + 1  # Flag len + Null byte


WBEM_FLAVOR_FLAG_PROPAGATE_O_INSTANCE      = 0x01
WBEM_FLAVOR_FLAG_PROPAGATE_O_DERIVED_CLASS = 0x02
WBEM_FLAVOR_NOT_OVERRIDABLE                = 0x10
WBEM_FLAVOR_ORIGIN_PROPAGATED              = 0x20
WBEM_FLAVOR_ORIGIN_SYSTEM                  = 0x40
WBEM_FLAVOR_AMENDED                        = 0x80

# 2.2.32 Inherited
Inherited = 0x4000

# 2.2.82 CimType
CIM_ARRAY_FLAG = 0x2000


class CIM_TYPE_ENUM(Enum):
    CIM_TYPE_SINT8 = 16
    CIM_TYPE_UINT8 = 17
    CIM_TYPE_SINT16 = 2
    CIM_TYPE_UINT16 = 18
    CIM_TYPE_SINT32 = 3
    CIM_TYPE_UINT32 = 19
    CIM_TYPE_SINT64 = 20
    CIM_TYPE_UINT64 = 21
    CIM_TYPE_REAL32 = 4
    CIM_TYPE_REAL64 = 5
    CIM_TYPE_BOOLEAN = 11
    CIM_TYPE_STRING = 8
    CIM_TYPE_DATETIME = 101
    CIM_TYPE_REFERENCE = 102
    CIM_TYPE_CHAR16 = 103
    CIM_TYPE_OBJECT = 13
    CIM_ARRAY_SINT8 = 8208
    CIM_ARRAY_UINT8 = 8209
    CIM_ARRAY_SINT16 = 8194
    CIM_ARRAY_UINT16 = 8210
    CIM_ARRAY_SINT32 = 8195
    CIM_ARRAY_UINT32 = 8201
    CIM_ARRAY_SINT64 = 8202
    CIM_ARRAY_UINT64 = 8203
    CIM_ARRAY_REAL32 = 8196
    CIM_ARRAY_REAL64 = 8197
    CIM_ARRAY_BOOLEAN = 8203
    CIM_ARRAY_STRING = 8200
    CIM_ARRAY_DATETIME = 8293
    CIM_ARRAY_REFERENCE = 8294
    CIM_ARRAY_CHAR16 = 8295
    CIM_ARRAY_OBJECT = 8205


CIM_TYPES_REF = {
    CIM_TYPE_ENUM.CIM_TYPE_SINT8.value: lambda name: SignedByteField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_UINT8.value: lambda name: ByteField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_SINT16.value: lambda name: LESignedShortField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_UINT16.value: lambda name: LEShortField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_SINT32.value: lambda name: LESignedIntField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_UINT32.value: lambda name: LEIntField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_SINT64.value: lambda name: LESignedLongField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_UINT64.value: lambda name: LELongField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_REAL32.value: lambda name: LEIntField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_REAL64.value: lambda name: LELongField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value: lambda name: LEShortField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_STRING.value: lambda name: LEIntField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value: lambda name: LEIntField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value: lambda name: LEIntField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_CHAR16.value: lambda name: LEShortField(name, 0),
    CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value: lambda name: LEIntField(name, 0),
}

CIM_TYPE_TO_NAME = {
    CIM_TYPE_ENUM.CIM_TYPE_SINT8.value: "sint8",
    CIM_TYPE_ENUM.CIM_TYPE_UINT8.value: "uint8",
    CIM_TYPE_ENUM.CIM_TYPE_SINT16.value: "sint16",
    CIM_TYPE_ENUM.CIM_TYPE_UINT16.value: "uint16",
    CIM_TYPE_ENUM.CIM_TYPE_SINT32.value: "sint32",
    CIM_TYPE_ENUM.CIM_TYPE_UINT32.value: "uint32",
    CIM_TYPE_ENUM.CIM_TYPE_SINT64.value: "sint64",
    CIM_TYPE_ENUM.CIM_TYPE_UINT64.value: "uint64",
    CIM_TYPE_ENUM.CIM_TYPE_REAL32.value: "real32",
    CIM_TYPE_ENUM.CIM_TYPE_REAL64.value: "real64",
    CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value: "bool",
    CIM_TYPE_ENUM.CIM_TYPE_STRING.value: "string",
    CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value: "datetime",
    CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value: "reference",
    CIM_TYPE_ENUM.CIM_TYPE_CHAR16.value: "char16",
    CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value: "object",
}

CIM_NUMBER_TYPES = (
    CIM_TYPE_ENUM.CIM_TYPE_CHAR16.value,
    CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value,
    CIM_TYPE_ENUM.CIM_TYPE_SINT8.value,
    CIM_TYPE_ENUM.CIM_TYPE_UINT8.value,
    CIM_TYPE_ENUM.CIM_TYPE_SINT16.value,
    CIM_TYPE_ENUM.CIM_TYPE_UINT16.value,
    CIM_TYPE_ENUM.CIM_TYPE_SINT32.value,
    CIM_TYPE_ENUM.CIM_TYPE_UINT32.value,
    CIM_TYPE_ENUM.CIM_TYPE_SINT64.value,
    CIM_TYPE_ENUM.CIM_TYPE_UINT64.value,
    CIM_TYPE_ENUM.CIM_TYPE_REAL32.value,
    CIM_TYPE_ENUM.CIM_TYPE_REAL64.value,
)


# 2.2.71 EncodedValue
class ENCODED_VALUE(Packet):
    QualifierName: int
    fields_desc = [LEIntField("QualifierName", None)]

    @classmethod
    def getValue(cls, cimType: int, entry: int, heap: bytes):
        # Let's get the default Values
        pType = cimType & (~(CIM_ARRAY_FLAG | Inherited))
        cimType = cimType & (~Inherited)
        if entry != 0xFFFFFFFF:
            heapData = heap[entry:]
            if cimType & CIM_ARRAY_FLAG:
                # Print first 4 bytes
                # We have an array, let's set the right unpackStr and dataSize for the array contents
                dataSize = 4
                numItems = struct.unpack("<L", heapData[:dataSize])[0]
                heapData = heapData[dataSize:]
                array = list()
                unpackStrArray = CIM_TYPES_REF[pType]("").fmt
                dataSizeArray = struct.calcsize(unpackStrArray)
                if cimType == CIM_TYPE_ENUM.CIM_ARRAY_STRING.value:
                    # We have an array of strings
                    # First items are DWORDs with the string pointers
                    # inside the heap. We don't need those ones
                    heapData = heapData[4 * numItems :]
                    # Let's now grab the strings
                    for _ in range(numItems):
                        item = ENCODED_STRING(heapData)
                        array.append(item.str_value())
                        heapData = heapData[item.bytes_len() :]
                elif cimType == CIM_TYPE_ENUM.CIM_ARRAY_OBJECT.value:
                    # Discard the pointers
                    heapData = heapData[dataSize * numItems :]
                    for item in range(numItems):
                        msb = METHOD_SIGNATURE_BLOCK(heapData)
                        unit = ENCODING_UNIT()
                        unit.ObjectEncodingLength = msb.EncodingLength
                        unit.ObjectBlock = msb.ObjectBlock
                        array.append(unit)
                        heapData = heapData[msb.EncodingLength + 4 :]
                else:
                    for item in range(numItems):
                        # ToDo: Learn to unpack the rest of the array of things
                        array.append(
                            struct.unpack(unpackStrArray, heapData[:dataSizeArray])[0]
                        )
                        heapData = heapData[dataSizeArray:]
                value = array
            elif pType == CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value:
                if entry == 0xFFFF:
                    value = "True"
                else:
                    value = "False"
            elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value:
                # If the value type is CIM-TYPE-OBJECT, the EncodedValue is a HeapRef to the object encoded as an
                # ObjectEncodingLength (section 2.2.4) followed by an ObjectBlock (section 2.2.5).

                # ToDo: This is a hack.. We should parse this better. We need to have an ENCODING_UNIT.
                # I'm going through a METHOD_SIGNATURE_BLOCK first just to parse the ObjectBlock
                msb = METHOD_SIGNATURE_BLOCK(heapData)
                unit = ENCODING_UNIT()
                unit.ObjectEncodingLength = msb.EncodingLength
                unit.ObjectBlock = msb.ObjectBlock
                value = unit
            elif pType not in (
                CIM_TYPE_ENUM.CIM_TYPE_STRING.value,
                CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value,
                CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value,
            ):
                value = entry
            else:
                try:
                    value = ENCODED_STRING(heapData).str_value()
                except UnicodeDecodeError:
                    print("Unicode Error: dumping heapData")
                    raise

            return value


# 2.2.7 Decoration
class DECORATION(Packet):
    name = "Decoration"
    DecServerName: int
    DecNamespaceName: int
    fields_desc = [
        PacketField("DecServerName", None, ENCODED_STRING),
        PacketField("DecNamespaceName", None, ENCODED_STRING),
    ]

    def extract_padding(self, s):
        # Return the remaining bytes to the parent
        return b"", s


# 2.2.16 ClassHeader
class CLASS_HEADER(Packet):
    EncodingLength: int
    ReservedOctet: int
    ClassNameRef: int
    NdTableValueTableLength: int
    fields_desc = [
        LEIntField("EncodingLength", None),  # 2.2.73 EncodingLength
        ByteField("ReservedOctet", None),  # 2.2.76 ReservedOctet
        LEIntField("ClassNameRef", None),  # 2.2.19 ClassNameRef
        LEIntField("NdTableValueTableLength", None),  # 2.2.28 NdTableValueTableLength
    ]

    def extract_padding(self, s):
        return b"", s


# 2.2.17 DerivationList
class DERIVATION_LIST(Packet):
    EncodingLength: int
    ClassNameEncoding: str
    fields_desc = [
        LEIntField("EncodingLength", None),
        StrLenField(
            "ClassNameEncoding", b"", length_from=lambda pkt: pkt.EncodingLength - 4
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# 2.2.60 Qualifier
class QUALIFIER(Packet):
    name = "Qualifier"
    QualifierName: int
    QualifierFlavor: int
    QualifierType: int
    QualifierValue: int
    fields_desc = [
        LEIntField("QualifierName", None),
        ByteField("QualifierFlavor", None),
        LEIntField("QualifierType", None),
        MultipleTypeField(
            [
                (
                    factory("QualifierValue"),
                    lambda pkt, t=t: pkt.QualifierType & (~CIM_ARRAY_FLAG) == t,
                )
                for t, factory in CIM_TYPES_REF.items()
            ],
            ByteField("QualifierValue", None),
        ),
    ]

    def extract_padding(self, s):
        self._parsed_len = len(self.original) - len(s)
        return b"", s

    @property
    def header_len(self):
        return getattr(self, "_parsed_len", None)


# 2.2.80 DictionaryReference
DICTIONARY_REFERENCE = {
    0: '"',
    1: "key",
    2: "NADA",
    3: "read",
    4: "write",
    5: "volatile",
    6: "provider",
    7: "dynamic",
    8: "cimwin32",
    9: "DWORD",
    10: "CIMTYPE",
}


# 2.2.59 QualifierSet
class QUALIFIER_SET(Packet):
    name = "QualifierSet"
    EncodingLength: int
    Qualifier: str
    fields_desc = [
        LEIntField("EncodingLength", None),  # 2.2.73 EncodingLength
        StrLenField("Qualifier", b"", length_from=lambda pkt: pkt.EncodingLength - 4),
    ]

    def getQualifiers(self, heap: str):
        data: str = self.Qualifier
        qualifiers = dict()
        while len(data) > 0:
            itemn: QUALIFIER = QUALIFIER(data)
            if itemn.QualifierName == 0xFFFFFFFF:
                qName = b""
            elif itemn.QualifierName & 0x80000000:
                qName = DICTIONARY_REFERENCE[itemn.QualifierName & 0x7FFFFFFF]
            else:
                qName = ENCODED_STRING(heap[itemn.QualifierName :]).str_value()

            value = ENCODED_VALUE.getValue(
                itemn.QualifierType, itemn.QualifierValue, heap
            )
            qualifiers[qName] = value
            data = data[itemn.header_len :]

        return qualifiers

    def extract_padding(self, s):
        return b"", s


# 2.2.23 PropertyLookup
class PROPERTY_LOOKUP(Packet):
    name = "PropertyLookup"
    PropertyNameRef: int
    PropertyInfoRef: int
    fields_desc = [
        LEIntField("PropertyNameRef", None),  # 2.2.24 PropertyNameRef
        LEIntField("PropertyInfoRef", None),  # 2.2.25 PropertyInfoRef
    ]


# 2.2.30 PropertyInfo
class PROPERTY_INFO(Packet):
    name = "PropertyInfo"
    PropertyType: int
    DeclarationOrder: int
    ValueTableOffset: int
    ClassOfOrigin: int
    PropertyQualifierSet: QUALIFIER_SET
    fields_desc = [
        LEIntField("PropertyType", None),
        LEShortField("DeclarationOrder", None),
        LEIntField("ValueTableOffset", None),
        LEIntField("ClassOfOrigin", None),
        PacketField("PropertyQualifierSet", None, QUALIFIER_SET),
    ]

    def extract_padding(self, s):
        return b"", s


# 2.2.21 PropertyLookupTable
class PROPERTY_LOOKUP_TABLE(Packet):
    PropertyCount: int
    PropertyLookup: str
    fields_desc = [
        LEIntField("PropertyCount", None),  # 2.2.22 PropertyCount
        StrLenField(
            "PropertyLookup", None, length_from=lambda pkt: pkt.PropertyCount * 8
        ),
    ]

    def getProperties(self, heap):
        propTable = self.PropertyLookup
        properties = dict()
        for property in range(self.PropertyCount):
            propItemDict = dict()
            propItem: PROPERTY_LOOKUP = PROPERTY_LOOKUP(propTable)
            if propItem.PropertyNameRef & 0x80000000:
                propName = DICTIONARY_REFERENCE[propItem.PropertyNameRef & 0x7FFFFFFF]
            else:
                propName = ENCODED_STRING(heap[propItem.PropertyNameRef :]).str_value()
            propInfo: PROPERTY_INFO = PROPERTY_INFO(heap[propItem.PropertyInfoRef :])
            pType = propInfo.PropertyType
            pType &= ~CIM_ARRAY_FLAG
            pType &= ~Inherited
            sType = CIM_TYPE_TO_NAME[pType]

            propItemDict["stype"] = sType
            propItemDict["name"] = propName
            propItemDict["type"] = propInfo.PropertyType
            propItemDict["order"] = propInfo.DeclarationOrder
            propItemDict["inherited"] = propInfo.PropertyType & Inherited
            propItemDict["value"] = None

            qualifiers = dict()
            qualifiersBuf = propInfo.PropertyQualifierSet.Qualifier
            while len(qualifiersBuf) > 0:
                record: QUALIFIER = QUALIFIER(qualifiersBuf)
                if record.QualifierName & 0x80000000:
                    qualifierName = DICTIONARY_REFERENCE[
                        record.QualifierName & 0x7FFFFFFF
                    ]
                else:
                    qualifierName = ENCODED_STRING(
                        heap[record.QualifierName :]
                    ).str_value()
                qualifierValue = ENCODED_VALUE.getValue(
                    record.QualifierType, record.QualifierValue, heap
                )
                qualifiersBuf = qualifiersBuf[record.header_len :]
                qualifiers[qualifierName] = qualifierValue

            propItemDict["qualifiers"] = qualifiers
            properties[propName] = propItemDict

            propTable = propTable[8:]

        return OrderedDict(
            sorted(list(properties.items()), key=lambda x: x[1]["order"])
        )

    def extract_padding(self, s):
        return b"", s


# 2.2.66 Heap
class CLASS_HEAP(Packet):
    name = "ClassHeap"
    HeapLength: int
    HeapItem: str
    fields_desc = [
        LEIntField("HeapLength", None),
        StrLenField(
            "HeapItem", b"", length_from=lambda pkt: pkt.HeapLength & 0x7FFFFFFF
        ),
    ]

    def extract_padding(self, s):
        return b"", s


# 2.2.15 ClassPart
class CLASS_PART(Packet):
    name = "ClassPart"
    ClassHeader: CLASS_HEADER
    DerivationList: DERIVATION_LIST
    ClassQualifierSet: QUALIFIER_SET
    PropertyLookupTable: PROPERTY_LOOKUP_TABLE
    NdTable_ValueTable: str
    ClassHeap: CLASS_HEAP
    fields_desc = [
        PacketField("ClassHeader", None, CLASS_HEADER),
        PacketField("DerivationList", None, DERIVATION_LIST),
        PacketField("ClassQualifierSet", None, QUALIFIER_SET),
        PacketField("PropertyLookupTable", None, PROPERTY_LOOKUP_TABLE),
        StrLenField(
            "NdTable_ValueTable",
            b"",
            lambda pkt: pkt.ClassHeader.NdTableValueTableLength,
        ),
        PacketField("ClassHeap", None, CLASS_HEAP),
    ]

    def getQualifiers(self):
        return self.ClassQualifierSet.getQualifiers(self.ClassHeap.HeapItem)

    def getProperties(self):
        heap = self.ClassHeap.HeapItem
        properties = self.PropertyLookupTable.getProperties(self.ClassHeap.HeapItem)
        sorted_props = sorted(
            list(properties.keys()), key=lambda k: properties[k]["order"]
        )
        valueTableOff = (len(properties) - 1) // 4 + 1
        valueTable = self.NdTable_ValueTable[valueTableOff:]
        for key in sorted_props:
            # Let's get the default Values
            pType = properties[key]["type"] & (~(CIM_ARRAY_FLAG | Inherited))
            if properties[key]["type"] & CIM_ARRAY_FLAG:
                unpackStr = (lambda: LEIntField("value", 0))().fmt
            else:
                unpackStr = CIM_TYPES_REF[pType]("").fmt
            dataSize = struct.calcsize(unpackStr)
            try:
                itemValue = struct.unpack(unpackStr, valueTable[:dataSize])[0]
            except:
                print("getProperties: Error unpacking!!")
                exit()
                itemValue = 0xFFFFFFFF

            if itemValue != 0xFFFFFFFF and itemValue > 0:
                value = ENCODED_VALUE.getValue(properties[key]["type"], itemValue, heap)
                properties[key]["value"] = "%s" % value
            valueTable = valueTable[dataSize:]
        return properties

    def extract_padding(self, s):
        """
        s = remaining bytes after fields_desc were dissected
        We only want bytes up to EncodingLength
        """
        enc_len = self.ClassHeader.EncodingLength

        if enc_len is None or self.original is None:
            return b"", s

        used = len(self.original) - len(s)
        remaining = enc_len - used

        if remaining < 0:
            remaining = 0

        garbage = s[:remaining]
        rest = s[remaining:]
        return garbage, rest

# 2.2.41 MethodDescription
class METHOD_DESCRIPTION(Packet):
    MethodName: int
    MethodFlags: int
    MethodPadding0: int
    MethodOrigin: int
    MethodQualifiers: int
    InputSignature: int
    OutputSignature: int
    
    fields_desc = [
        LEIntField("MethodName", None),
        ByteField("MethodFlags", None),
        ByteField("MethodPadding0", None),
        ByteField("MethodPadding1", None),
        ByteField("MethodPadding2", None),
        LEIntField("MethodOrigin", None),
        LEIntField("MethodQualifiers", None),
        LEIntField("InputSignature", None),
        LEIntField("OutputSignature", None),
    ]

    def extract_padding(self, s):
        return b"", s
# 2.2.38 MethodsPart
class METHODS_PART(Packet):
    name = "MethodsPart"
    EncodingLength: int
    MethodCount: int
    MethodCountPadding: int
    MethodDescription: str
    MethodHeap: CLASS_HEAP
    fields_desc = [
        LEIntField("EncodingLength", None),
        LEShortField("MethodCount", None),
        LEShortField("MethodCountPadding", None),
        StrLenField("MethodDescription", b"", length_from=lambda pkt: pkt.MethodCount*24),
        PacketField("MethodHeap", None, CLASS_HEAP),
    ]

    def extract_padding(self, s):
        return b"", s
    
    def getMethods(self):
        methods = OrderedDict()
        data = self.MethodDescription
        heap = self.MethodHeap.HeapItem

        for method in range(self.MethodCount):
            methodDict = OrderedDict()
            itemn: METHOD_DESCRIPTION = METHOD_DESCRIPTION(data)
            if itemn.MethodFlags & WBEM_FLAVOR_ORIGIN_PROPAGATED:
                # TODO
                # raise ValueError("WBEM_FLAVOR_ORIGIN_PROPAGATED not yet supported!")
                continue
            methodDict['name'] = ENCODED_STRING(heap[itemn.MethodName:]).str_value()
            methodDict['origin'] = itemn.MethodOrigin
            if itemn.MethodQualifiers != 0xffffffff:
                # There are qualifiers
                qualifiersSet: QUALIFIER_SET = QUALIFIER_SET(heap[itemn.MethodQualifiers:])
                qualifiers = qualifiersSet.getQualifiers(heap)
                methodDict['qualifiers'] = qualifiers
            if itemn.InputSignature != 0xffffffff:
                inputSignature: METHOD_SIGNATURE_BLOCK = METHOD_SIGNATURE_BLOCK(heap[itemn.InputSignature:])
                if inputSignature.EncodingLength > 0:
                    methodDict['InParams'] = inputSignature.ObjectBlock.ClassType.CurrentClass.getProperties()
                    methodDict['InParamsRaw'] = inputSignature.ObjectBlock
                    #print methodDict['InParams'] 
                else:
                    methodDict['InParams'] = None
            if itemn.OutputSignature != 0xffffffff:
                outputSignature: METHOD_SIGNATURE_BLOCK = METHOD_SIGNATURE_BLOCK(heap[itemn.OutputSignature:])
                if outputSignature.EncodingLength > 0:
                    methodDict['OutParams'] = outputSignature.ObjectBlock.ClassType.CurrentClass.getProperties()
                    methodDict['OutParamsRaw'] = outputSignature.ObjectBlock
                else:
                    methodDict['OutParams'] = None
            data = data[24:]
            methods[methodDict['name']] = methodDict

        return methods


# 2.2.14 ClassAndMethodsPart
class CLASS_AND_METHODS_PART(Packet):
    name = "ClassAndMethodsPart"
    ClassPart: CLASS_PART
    MethodsPart: METHODS_PART
    fields_desc = [
        PacketField("ClassPart", None, CLASS_PART),
        PacketField("MethodsPart", None, METHODS_PART),
    ]

    def extract_padding(self, s):
        return b"", s

    def getClassName(self) -> str:
        pClassName = self.ClassPart.ClassHeader.ClassNameRef
        cHeap = self.ClassPart.ClassHeap.HeapItem
        if pClassName == 0xFFFFFFFF:
            return "None"
        else:
            className: str = ENCODED_STRING(cHeap[pClassName:]).str_value()
            derivationList = self.ClassPart.DerivationList.ClassNameEncoding
            while len(derivationList) > 0:
                superClass: ENCODED_STRING = ENCODED_STRING(derivationList)
                className += " : %s " % superClass.str_value()
                derivationList = derivationList[superClass.bytes_len() + 4 :]
            return className

    def getQualifiers(self):
        return self.ClassPart.getQualifiers()

    def getProperties(self):
        return self.ClassPart.getProperties()
    
    def getMethods(self):
        return self.MethodsPart.getMethods()


class CURRENT_CLASS_NO_METHODS(CLASS_AND_METHODS_PART):
    name = "CurrentClassNoMethods"
    ClassPart: CLASS_PART
    fields_desc = [PacketField("ClassPart", None, CLASS_PART)]

    def getMethods(self):
        return ()

    def extract_padding(self, s):
        return b"", s


# 2.2.65 InstancePropQualifierSet
class INSTANCE_PROP_QUALIFIER_SET(Packet):
    name = "InstancePropQualifierSet"
    InstPropQualSetFlag: int
    fields_desc = [ByteField("InstPropQualSetFlag", None)]

    def extract_padding(self, s):
        return b"", s


# 2.2.57 InstanceQualifierSet
class INSTANCE_QUALIFIER_SET(Packet):
    name = "InstanceQualifierSet"
    QualifierSet: QUALIFIER_SET
    InstancePropQualifierSet: INSTANCE_PROP_QUALIFIER_SET
    fields_desc = [
        PacketField("QualifierSet", None, QUALIFIER_SET),
        PacketField("InstancePropQualifierSet", None, INSTANCE_PROP_QUALIFIER_SET),
    ]

    def extract_padding(self, s):
        return b"", s


# 2.2.53 InstanceType
class INSTANCE_TYPE(Packet):
    name = "InstanceType"
    CurrentClass: CURRENT_CLASS_NO_METHODS
    EncodingLength: int
    InstanceFlags: int
    InstanceClassName: int
    NdTable_ValueTable: str
    InstanceQualifierSet: INSTANCE_QUALIFIER_SET
    InstanceHeap: CLASS_HEAP
    fields_desc = [
        PacketField("CurrentClass", None, CURRENT_CLASS_NO_METHODS),
        LEIntField("EncodingLength", None),  # 2.2.73 EncodingLength
        ByteField("InstanceFlags", None),  # 2.2.54 InstanceFlags
        LEIntField("InstanceClassName", None),  # 2.2.69 HeapRef
        StrLenField(
            "NdTable_ValueTable",
            b"",
            length_from=lambda pkt: pkt.CurrentClass.ClassPart.ClassHeader.NdTableValueTableLength,
        ),
        PacketField("InstanceQualifierSet", None, INSTANCE_QUALIFIER_SET),
        PacketField("InstanceHeap", None, CLASS_HEAP),
    ]

    def __processNdTable(self, properties):
        octetCount = (len(properties) - 1) // 4 + 1  # see [MS-WMIO]: 2.2.26 NdTable
        packedNdTable = self.NdTable_ValueTable[:octetCount]
        unpackedNdTable = [
            (byte >> shift) & 0b11 for byte in packedNdTable for shift in (0, 2, 4, 6)
        ]
        for key in properties:
            ndEntry = unpackedNdTable[properties[key]["order"]]
            properties[key]["null_default"] = bool(ndEntry & 0b01)
            properties[key]["inherited_default"] = bool(ndEntry & 0b10)

        return octetCount

    @staticmethod
    def __isNonNullNumber(prop):
        return (
            prop["type"] & ~Inherited in CIM_NUMBER_TYPES and not prop["null_default"]
        )

    def getValues(self, properties: dict):
        heap = self.InstanceHeap.HeapItem
        valueTableOff = self.__processNdTable(properties)
        valueTable = self.NdTable_ValueTable[valueTableOff:]
        sorted_props = sorted(
            list(properties.keys()), key=lambda k: properties[k]["order"]
        )
        for key in sorted_props:
            pType = properties[key]["type"] & (~(CIM_ARRAY_FLAG | Inherited))
            if properties[key]["type"] & CIM_ARRAY_FLAG:
                unpackStr = (lambda: LEIntField("value", 0))().fmt
            else:
                unpackStr = CIM_TYPES_REF[pType]("").fmt
            dataSize = struct.calcsize(unpackStr)
            try:
                itemValue = struct.unpack(unpackStr, valueTable[:dataSize])[0]
            except:
                print("getValues: Error Unpacking!")
                exit()
                itemValue = 0xFFFFFFFF

            # if itemValue == 0, default value remains
            if itemValue != 0 or self.__isNonNullNumber(properties[key]):
                value = ENCODED_VALUE.getValue(properties[key]["type"], itemValue, heap)
                properties[key]["value"] = value
            # is the value set valid or should we clear it? ( if not inherited )
            elif properties[key]["inherited"] == 0:
                properties[key]["value"] = None
            valueTable = valueTable[dataSize:]
        return properties

    def extract_padding(self, s):
        return b"", s

class CLASS_TYPE(Packet):
    ParentClass: CLASS_AND_METHODS_PART
    CurrentClass: CLASS_AND_METHODS_PART
    fields_desc = [
        PacketField("ParentClass", None, CLASS_AND_METHODS_PART),
        PacketField("CurrentClass", None, CLASS_AND_METHODS_PART)
    ]


# 2.2.5 ObjectBlock
class OBJECT_BLOCK(Packet):
    name = "ObjectBlock"
    ObjectFlags: int
    Decoration: Optional[DECORATION]
    InstanceType: INSTANCE_TYPE
    ClassType: CLASS_TYPE
    fields_desc = [
        ByteField("ObjectFlags", None),
        ConditionalField(  # This block MUST be present if the ObjectFlags (section 2.2.6) octet has 0x04 bit flag set; otherwise, it MUST be omitted.
            PacketField("Decoration", None, DECORATION), lambda p: p.ObjectFlags & 0x04
        ),
        ConditionalField(
            PacketField("InstanceType", None, INSTANCE_TYPE), lambda p: p.ObjectFlags & 0x02
        ),
        ConditionalField(
            PacketField("ClassType", None, CLASS_TYPE), lambda p: p.ObjectFlags & 0x01
        ),
    ]

    def extract_padding(self, s):
        return b"", s

    def parseObject(self):
        if self.ObjectFlags & 0x02:
            # The object is a CIM instance
            ctCurrent: CLASS_AND_METHODS_PART = self.InstanceType.CurrentClass
            currentName = ctCurrent.getClassName()
            if currentName is not None:
                self.ctCurrent = self.parseClass(ctCurrent, self.InstanceType)
            return
        else:
            # The object is a CIM class
            ctParent: CLASS_AND_METHODS_PART = self.ClassType.ParentClass
            ctCurrent: CLASS_AND_METHODS_PART = self.ClassType.CurrentClass

            parentName = ctParent.getClassName()
            if parentName is not None:
                self.ctParent = self.parseClass(ctParent)

            currentName = ctCurrent.getClassName()
            if currentName is not None:
                self.ctCurrent = self.parseClass(ctCurrent)

    def parseClass(
        self, pClass: CLASS_AND_METHODS_PART, cInstance: INSTANCE_TYPE = None
    ):
        classDict = OrderedDict()
        classDict["name"] = pClass.getClassName()
        classDict["qualifiers"] = pClass.getQualifiers()
        classDict["properties"] = pClass.getProperties()
        classDict["methods"] = pClass.getMethods()

        if cInstance is not None:
            classDict["values"] = cInstance.getValues(classDict["properties"])
        else:
            classDict["values"] = None

        return classDict

    def isInstance(self):
        if self.ObjectFlags & 0x01:
            return False
        return True

    def printClass(
        self, pClass: CLASS_AND_METHODS_PART, cInstance: INSTANCE_TYPE = None
    ):
        qualifiers = pClass.getQualifiers()

        for qualifier in qualifiers:
            print("[%s]" % qualifier)

        className = pClass.getClassName()

        print("class %s \n{" % className)

        properties = pClass.getProperties()
        if cInstance is not None:
            properties = cInstance.getValues(properties)

        for pName in properties:
            # if property['inherited'] == 0:
            qualifiers = properties[pName]["qualifiers"]
            for qName in qualifiers:
                if qName != "CIMTYPE":
                    print("\t[%s(%s)]" % (qName, qualifiers[qName]))
            print(
                "\t%s %s" % (properties[pName]["stype"], properties[pName]["name"]),
                end=" ",
            )
            if properties[pName]["value"] is not None:
                cimType = properties[pName]["type"] & (~Inherited)
                if cimType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value:
                    print("= IWbemClassObject\n")
                elif cimType == CIM_TYPE_ENUM.CIM_ARRAY_OBJECT.value:
                    if properties[pName]["value"] == 0:
                        print("= %s\n" % properties[pName]["value"])
                    else:
                        print(
                            "= %s\n"
                            % list(
                                "IWbemClassObject"
                                for _ in range(len(properties[pName]["value"]))
                            )
                        )
                else:
                    print("= %s\n" % properties[pName]["value"])
            else:
                print("\n")

        print()
        methods = pClass.getMethods()
        for methodName in methods:
            for qualifier in methods[methodName]["qualifiers"]:
                print("\t[%s]" % qualifier)

            if (
                methods[methodName]["InParams"] is None
                and methods[methodName]["OutParams"] is None
            ):
                print("\t%s %s();\n" % ("void", methodName))
            if (
                methods[methodName]["InParams"] is None
                and len(methods[methodName]["OutParams"]) == 1
            ):
                print(
                    "\t%s %s();\n"
                    % (
                        methods[methodName]["OutParams"]["ReturnValue"]["stype"],
                        methodName,
                    )
                )
            else:
                returnValue = b""
                if methods[methodName]["OutParams"] is not None:
                    # Search the Return Value
                    # returnValue = (item for item in method['OutParams'] if item["name"] == "ReturnValue").next()
                    if "ReturnValue" in methods[methodName]["OutParams"]:
                        returnValue = methods[methodName]["OutParams"]["ReturnValue"][
                            "stype"
                        ]

                print("\t%s %s(\n" % (returnValue, methodName), end=" ")
                if methods[methodName]["InParams"] is not None:
                    for pName in methods[methodName]["InParams"]:
                        print(
                            "\t\t[in]    %s %s,"
                            % (methods[methodName]["InParams"][pName]["stype"], pName)
                        )

                if methods[methodName]["OutParams"] is not None:
                    for pName in methods[methodName]["OutParams"]:
                        if pName != "ReturnValue":
                            print(
                                "\t\t[out]    %s %s,"
                                % (
                                    methods[methodName]["OutParams"][pName]["stype"],
                                    pName,
                                )
                            )

                print("\t);\n")

        print("}")

    def printInformation(self):
        if self.ObjectFlags & 0x02:
            # The object is a CIM instance
            ctCurrent: CLASS_AND_METHODS_PART = self.InstanceType.CurrentClass
            currentName = ctCurrent.getClassName()
            if currentName is not None:
                self.printClass(ctCurrent, self.InstanceType)
            return
        else:
            # The object is a CIM class
            ctParent: CLASS_AND_METHODS_PART = self.ClassType.ParentClass
            ctCurrent: CLASS_AND_METHODS_PART = self.ClassType.CurrentClass

            parentName = ctParent.getClassName()
            if parentName is not None:
                self.printClass(ctParent)

            currentName = ctCurrent.getClassName()
            if currentName is not None:
                self.printClass(ctCurrent)


# 2.2.70 MethodSignatureBlock
class METHOD_SIGNATURE_BLOCK(Packet):
    name = "MethodSignatureBlock"
    EncodingLength: int
    ObjectBlock: OBJECT_BLOCK
    fields_desc = [
        LEIntField("EncodingLength", None),  # 2.2.73 EncodingLength
        ConditionalField(
            PacketField("ObjectBlock", None, OBJECT_BLOCK),
            lambda pkt: pkt.EncodingLength > 0,
        ),
    ]


# 2.2.1 EncodingUnit
class ENCODING_UNIT(Packet):
    Signature: int
    ObjectEncodingLength: int
    ObjectBlock: OBJECT_BLOCK
    name = "EncodingUnit"
    fields_desc = [
        LEIntField("Signature", 0x12345678),  # 2.2.77 Signature
        LEIntField("ObjectEncodingLength", None),  # 2.2.4 ObjectEncodingLength
        PacketField("ObjectBlock", None, OBJECT_BLOCK),
    ]


if __name__ == "__main__":
    data = b'xV4\x12\x07#\x00\x00\x06\x00WIN-8K15VKV24SG\x00\x00root\\cimv2\x00~ \x00\x00\x00\x00\x00\x00\x00\xee\x00\x00\x00K\x00\x00\x00\x00CIM_Process\x00\r\x00\x00\x00\x00CIM_LogicalElement\x00\x14\x00\x00\x00\x00CIM_ManagedSystemElement\x00\x1a\x00\x00\x00f\x00\x00\x00\x07\x00\x00\x80\x01\x0b\x00\x00\x00\xff\xff\x06\x00\x00\x80\x01\x08\x00\x00\x00\x0f\x00\x00\x00\x19\x00\x00\x00\x00\x0b\x00\x00\x00\xff\xff)\x00\x00\x00\x00\x08\x00\x00\x003\x00\x00\x00;\x00\x00\x00\x00\x0b\x00\x00\x00\xff\xffK\x00\x00\x00\x00\x08\x00\x00\x00U\x00\x00\x00e\x00\x00\x00\x01\x03\x00\x00\x00\t\x04\x00\x00m\x00\x00\x00\x01\x08\x00\x00\x00s\x00\x00\x00-\x00\x00\x00\x9b\x00\x00\x00\xa4\x00\x00\x00\xeb\x00\x00\x00\xf8\x00\x00\x00*\x01\x00\x00=\x01\x00\x00\x98\x01\x00\x00\xa6\x01\x00\x00\xec\x01\x00\x00\x01\x02\x00\x00\x9e\x02\x00\x00\xa6\x02\x00\x006\x03\x00\x00C\x03\x00\x00u\x03\x00\x00\x85\x03\x00\x00F\x04\x00\x00V\x04\x00\x00\x88\x04\x00\x00\x90\x04\x00\x00\xe2\x04\x00\x00\xef\x04\x00\x00\x86\x05\x00\x00\x93\x05\x00\x00\x08\x06\x00\x00\x18\x06\x00\x00q\x06\x00\x00\x88\x06\x00\x00D\x07\x00\x00[\x07\x00\x00\x17\x08\x00\x00\x1d\x08\x00\x00O\x08\x00\x00d\x08\x00\x00\xff\x08\x00\x00\x07\t\x00\x00\x95\t\x00\x00\xaa\t\x00\x00X\n\x00\x00l\n\x00\x00\x19\x0b\x00\x00%\x0b\x00\x00\xbf\x0b\x00\x00\xce\x0b\x00\x00g\x0c\x00\x00x\x0c\x00\x00 \r\x00\x003\r\x00\x00\xd0\r\x00\x00\xe1\r\x00\x00|\x0e\x00\x00\x90\x0e\x00\x00.\x0f\x00\x008\x0f\x00\x00\xf1\x0f\x00\x00\x03\x10\x00\x00\x9f\x10\x00\x00\xaa\x10\x00\x00J\x11\x00\x00b\x11\x00\x00\x04\x12\x00\x00\x19\x12\x00\x00\xb8\x12\x00\x00\xd4\x12\x00\x00z\x13\x00\x00\x93\x13\x00\x006\x14\x00\x00J\x14\x00\x00\xf7\x14\x00\x00\n\x15\x00\x00\xb6\x15\x00\x00\xc1\x15\x00\x00V\x16\x00\x00^\x16\x00\x00c\x17\x00\x00t\x17\x00\x00\xa8\x17\x00\x00\xb5\x17\x00\x00P\x18\x00\x00^\x18\x00\x00\xb5\x18\x00\x00\xc2\x18\x00\x00Y\x19\x00\x00i\x19\x00\x00\xf9\x19\x00\x00\t\x1a\x00\x00;\x1a\x00\x00P\x1a\x00\x00\xfe\x1a\x00\x00\x12\x1b\x00\x00\xff\xff\xdf\xf7]UUUUUU\xfd\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffb\x1d\x00\x80\x00Win32_Process\x00\x00CIMWin32\x00\x00SupportsCreate\x00\x00CreateBy\x00\x00Create\x00\x00SupportsDelete\x00\x00DeleteBy\x00\x00DeleteInstance\x00\x00Locale\x00\x00UUID\x00\x00{8502C4DC-5FBB-11D2-AAC1-006008C78BC7}\x00\x00Caption\x00\x08@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\xdb\x00\x00\x00\xe3\x00\x00\x00"\x03\x00\x00\x00@\x00\x00\x00\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x00string\x00\x00MaxLen\x00\x00CommandLine\x00\x08\x00\x00\x00,\x00\xde\x00\x00\x00\x03\x00\x00\x00\x1c\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00"\x01\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\x00string\x00\x00CreationClassName\x00\x08@\x00\x00\x07\x00\x1c\x00\x00\x00\x02\x00\x00\x004\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\x7f\x01\x00\x00\x87\x01\x00\x00"\x0b\x00\x00\x00\xff\xff\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x90\x01\x00\x00"\x03\x00\x00\x00\x00\x01\x00\x00\x00string\x00\x00CIM_Key\x00\x00MaxLen\x00\x00CreationDate\x00e@\x00\x00\x08\x00 \x00\x00\x00\x02\x00\x00\x00\'\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\xdb\x01\x00\x00\xe5\x01\x00\x00"\x0b\x00\x00\x00\xff\xff\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x00datetime\x00\x00Fixed\x00\x00CSCreationClassName\x00\x08@\x00\x00\x05\x00\x14\x00\x00\x00\x02\x00\x00\x00A\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00P\x02\x00\x00X\x02\x00\x00"\x08\x00\x00\x00d\x02\x00\x00\x8d\x02\x00\x00"\x0b\x00\x00\x00\xff\xff\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x96\x02\x00\x00"\x03\x00\x00\x00\x00\x01\x00\x00\x00string\x00\x00Propagated\x00\x00CIM_OperatingSystem.CSCreationClassName\x00\x00CIM_Key\x00\x00MaxLen\x00\x00CSName\x00\x08@\x00\x00\x06\x00\x18\x00\x00\x00\x02\x00\x00\x00A\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\xf5\x02\x00\x00\xfd\x02\x00\x00"\x08\x00\x00\x00\t\x03\x00\x00%\x03\x00\x00"\x0b\x00\x00\x00\xff\xff\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff.\x03\x00\x00"\x03\x00\x00\x00\x00\x01\x00\x00\x00string\x00\x00Propagated\x00\x00CIM_OperatingSystem.CSName\x00\x00CIM_Key\x00\x00MaxLen\x00\x00Description\x00\x08@\x00\x00\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00m\x03\x00\x00\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x00string\x00\x00ExecutablePath\x00\x08\x00\x00\x00\x12\x00R\x00\x00\x00\x03\x00\x00\x006\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xc9\x03\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xd1\x03\x00\x00\x02\x08 \x00\x00\xdd\x03\x00\x00\xf7\x03\x00\x00\x02\x08 \x00\x00\x07\x04\x00\x00\x00string\x00\x00Privileges\x00\x01\x00\x00\x00\xe5\x03\x00\x00\x00SeDebugPrivilege\x00\x00MappingStrings\x00\x01\x00\x00\x00\x0f\x04\x00\x00\x00Win32API|Tool Help Structures|MODULEENTRY32|szExePath\x00\x00ExecutionState\x00\x12@\x00\x00\x0e\x00<\x00\x00\x00\x02\x00\x00\x00\x1c\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\x80\x04\x00\x00\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x00uint16\x00\x00Handle\x00\x08@\x00\x00\t\x00$\x00\x00\x00\x02\x00\x00\x004\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\xd2\x04\x00\x00\x01\x00\x00\x803\x0b\x00\x00\x00\xff\xff\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\xda\x04\x00\x00"\x03\x00\x00\x00\x00\x01\x00\x00\x00string\x00\x00MaxLen\x00\x00HandleCount\x00\x13\x00\x00\x00 \x00\x8a\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00&\x05\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff.\x05\x00\x00\x02\x08 \x00\x00>\x05\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00F\x05\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|HandleCount\x00\x00InstallDate\x00e@\x00\x00\x02\x00\x08\x00\x00\x00\x00\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\xca\x05\x00\x00\xd4\x05\x00\x00"\x08 \x00\x00\xe4\x05\x00\x00\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x00datetime\x00\x00MappingStrings\x00\x01\x00\x00\x00\xec\x05\x00\x00\x00MIF.DMTF|ComponentID|001.5\x00\x00KernelModeTime\x00\x15@\x00\x00\n\x00(\x00\x00\x00\x02\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00O\x06\x00\x00W\x06\x00\x00\x00\x08\x00\x00\x00a\x06\x00\x00\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x00uint64\x00\x00Override\x00\x00KernelModeTime\x00\x00MaximumWorkingSetSize\x00\x13\x00\x00\x00\x13\x00V\x00\x00\x00\x03\x00\x00\x006\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xcc\x06\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xd4\x06\x00\x00\x02\x08 \x00\x00\xe0\x06\x00\x00\xfa\x06\x00\x00\x02\x08 \x00\x00\n\x07\x00\x00\x00uint32\x00\x00Privileges\x00\x01\x00\x00\x00\xe8\x06\x00\x00\x00SeDebugPrivilege\x00\x00MappingStrings\x00\x01\x00\x00\x00\x12\x07\x00\x00\x00Win32|WINNT.H|QUOTA_LIMITS|MaximumWorkingSetSize\x00\x00MinimumWorkingSetSize\x00\x13\x00\x00\x00\x14\x00Z\x00\x00\x00\x03\x00\x00\x006\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\x9f\x07\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xa7\x07\x00\x00\x02\x08 \x00\x00\xb3\x07\x00\x00\xcd\x07\x00\x00\x02\x08 \x00\x00\xdd\x07\x00\x00\x00uint32\x00\x00Privileges\x00\x01\x00\x00\x00\xbb\x07\x00\x00\x00SeDebugPrivilege\x00\x00MappingStrings\x00\x01\x00\x00\x00\xe5\x07\x00\x00\x00Win32|WINNT.H|QUOTA_LIMITS|MinimumWorkingSetSize\x00\x00Name\x00\x08@\x00\x00\x03\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00G\x08\x00\x00\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x00string\x00\x00OSCreationClassName\x00\x08@\x00\x00\x0b\x000\x00\x00\x00\x02\x00\x00\x00A\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\xb3\x08\x00\x00\xbb\x08\x00\x00"\x08\x00\x00\x00\xc7\x08\x00\x00\xee\x08\x00\x00"\x0b\x00\x00\x00\xff\xff\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\xf7\x08\x00\x00"\x03\x00\x00\x00\x00\x01\x00\x00\x00string\x00\x00Propagated\x00\x00CIM_OperatingSystem.CreationClassName\x00\x00CIM_Key\x00\x00MaxLen\x00\x00OSName\x00\x08@\x00\x00\x0c\x004\x00\x00\x00\x02\x00\x00\x00A\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00V\t\x00\x00^\t\x00\x00"\x08\x00\x00\x00j\t\x00\x00\x84\t\x00\x00"\x0b\x00\x00\x00\xff\xff\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x8d\t\x00\x00"\x03\x00\x00\x00\x00\x01\x00\x00\x00string\x00\x00Propagated\x00\x00CIM_OperatingSystem.Name\x00\x00CIM_Key\x00\x00MaxLen\x00\x00OtherOperationCount\x00\x15\x00\x00\x00(\x00\xbe\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xe1\t\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xe9\t\x00\x00\x02\x08 \x00\x00\xf9\t\x00\x00\x00uint64\x00\x00MappingStrings\x00\x01\x00\x00\x00\x01\n\x00\x00\x00Win32API|Process and Thread Structures|SYSTEM_PROCESS_INFORMATION|OtherOperationCount\x00\x00OtherTransferCount\x00\x15\x00\x00\x00+\x00\xd6\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xa3\n\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xab\n\x00\x00\x02\x08 \x00\x00\xbb\n\x00\x00\x00uint64\x00\x00MappingStrings\x00\x01\x00\x00\x00\xc3\n\x00\x00\x00Win32API|Process and Thread Structures|SYSTEM_PROCESS_INFORMATION|OtherTransferCount\x00\x00PageFaults\x00\x13\x00\x00\x00\x15\x00^\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\\\x0b\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xffd\x0b\x00\x00\x02\x08 \x00\x00t\x0b\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00|\x0b\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|PageFaultCount\x00\x00PageFileUsage\x00\x13\x00\x00\x00\x16\x00b\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\x05\x0c\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\r\x0c\x00\x00\x02\x08 \x00\x00\x1d\x0c\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00%\x0c\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|PagefileUsage\x00\x00ParentProcessId\x00\x13\x00\x00\x00!\x00\x8e\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xaf\x0c\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xb7\x0c\x00\x00\x02\x08 \x00\x00\xc7\x0c\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00\xcf\x0c\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|InheritedFromUniqueProcessId\x00\x00PeakPageFileUsage\x00\x13\x00\x00\x00\x17\x00f\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00j\r\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xffr\r\x00\x00\x02\x08 \x00\x00\x82\r\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00\x8a\r\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|PeakPagefileUsage\x00\x00PeakVirtualSize\x00\x15\x00\x00\x00$\x00\x9e\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\x18\x0e\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff \x0e\x00\x00\x02\x08 \x00\x000\x0e\x00\x00\x00uint64\x00\x00MappingStrings\x00\x01\x00\x00\x008\x0e\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|PeakVirtualSize\x00\x00PeakWorkingSetSize\x00\x13\x00\x00\x00\x18\x00j\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xc7\x0e\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xcf\x0e\x00\x00\x02\x08 \x00\x00\xdf\x0e\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00\xe7\x0e\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|PeakWorkingSetSize\x00\x00Priority\x00\x13@\x00\x00\r\x008\x00\x00\x00\x02\x00\x00\x006\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00|\x0f\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\x84\x0f\x00\x00\x02\x08\x00\x00\x00\x8e\x0f\x00\x00\x98\x0f\x00\x00\x02\x08 \x00\x00\xa8\x0f\x00\x00\x00uint32\x00\x00Override\x00\x00Priority\x00\x00MappingStrings\x00\x01\x00\x00\x00\xb0\x0f\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|BasePriority\x00\x00PrivatePageCount\x00\x15\x00\x00\x00#\x00\x96\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00:\x10\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xffB\x10\x00\x00\x02\x08 \x00\x00R\x10\x00\x00\x00uint64\x00\x00MappingStrings\x00\x01\x00\x00\x00Z\x10\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|PrivatePageCount\x00\x00ProcessId\x00\x13\x00\x00\x00\x19\x00n\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xe1\x10\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xe9\x10\x00\x00\x02\x08 \x00\x00\xf9\x10\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00\x01\x11\x00\x00\x00Win32API|Process and Thread Structures|PROCESS_INFORMATION|dwProcessId \x00\x00QuotaNonPagedPoolUsage\x00\x13\x00\x00\x00\x1a\x00r\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\x99\x11\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xa1\x11\x00\x00\x02\x08 \x00\x00\xb1\x11\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00\xb9\x11\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|QuotaNonPagedPoolUsage\x00\x00QuotaPagedPoolUsage\x00\x13\x00\x00\x00\x1b\x00v\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00P\x12\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xffX\x12\x00\x00\x02\x08 \x00\x00h\x12\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00p\x12\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|QuotaPagedPoolUsage\x00\x00QuotaPeakNonPagedPoolUsage\x00\x13\x00\x00\x00\x1c\x00z\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\x0b\x13\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\x13\x13\x00\x00\x02\x08 \x00\x00#\x13\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00+\x13\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|QuotaPeakNonPagedPoolUsage\x00\x00QuotaPeakPagedPoolUsage\x00\x13\x00\x00\x00\x1d\x00~\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xca\x13\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xd2\x13\x00\x00\x02\x08 \x00\x00\xe2\x13\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00\xea\x13\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|QuotaPeakPagedPoolUsage\x00\x00ReadOperationCount\x00\x15\x00\x00\x00&\x00\xae\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\x81\x14\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\x89\x14\x00\x00\x02\x08 \x00\x00\x99\x14\x00\x00\x00uint64\x00\x00MappingStrings\x00\x01\x00\x00\x00\xa1\x14\x00\x00\x00Win32API|Process and Thread Structures|SYSTEM_PROCESS_INFORMATION|ReadOperationCount\x00\x00ReadTransferCount\x00\x15\x00\x00\x00)\x00\xc6\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00A\x15\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xffI\x15\x00\x00\x02\x08 \x00\x00Y\x15\x00\x00\x00uint64\x00\x00MappingStrings\x00\x01\x00\x00\x00a\x15\x00\x00\x00Win32API|Process and Thread Structures|SYSTEM_PROCESS_INFORMATION|ReadTransferCount\x00\x00SessionId\x00\x13\x00\x00\x00"\x00\x92\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xf8\x15\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\x00\x16\x00\x00\x02\x08 \x00\x00\x10\x16\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00\x18\x16\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|SessionId\x00\x00Status\x00\x08@\x00\x00\x04\x00\x10\x00\x00\x00\x00\x00\x00\x006\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\xa2\x16\x00\x00\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\xaa\x16\x00\x00"\x03\x00\x00\x00\n\x00\x00\x00\xb2\x16\x00\x00"\x08 \x00\x00\xbc\x16\x00\x00\x00string\x00\x00MaxLen\x00\x00ValueMap\x00\x0c\x00\x00\x00\xf0\x16\x00\x00\xf4\x16\x00\x00\xfb\x16\x00\x00\x05\x17\x00\x00\x0e\x17\x00\x00\x19\x17\x00\x00#\x17\x00\x00-\x17\x00\x006\x17\x00\x00@\x17\x00\x00L\x17\x00\x00X\x17\x00\x00\x00OK\x00\x00Error\x00\x00Degraded\x00\x00Unknown\x00\x00Pred Fail\x00\x00Starting\x00\x00Stopping\x00\x00Service\x00\x00Stressed\x00\x00NonRecover\x00\x00No Contact\x00\x00Lost Comm\x00\x00TerminationDate\x00e@\x00\x00\x0f\x00>\x00\x00\x00\x02\x00\x00\x00\x1c\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x00\x9e\x17\x00\x00\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x00datetime\x00\x00ThreadCount\x00\x13\x00\x00\x00\x1f\x00\x86\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xec\x17\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xf4\x17\x00\x00\x02\x08 \x00\x00\x04\x18\x00\x00\x00uint32\x00\x00MappingStrings\x00\x01\x00\x00\x00\x0c\x18\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|NumberOfThreads\x00\x00UserModeTime\x00\x15@\x00\x00\x10\x00B\x00\x00\x00\x02\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\x95\x18\x00\x00\x9d\x18\x00\x00\x00\x08\x00\x00\x00\xa7\x18\x00\x00\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x00uint64\x00\x00Override\x00\x00UserModeTime\x00\x00VirtualSize\x00\x15\x00\x00\x00%\x00\xa6\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xf9\x18\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\x01\x19\x00\x00\x02\x08 \x00\x00\x11\x19\x00\x00\x00uint64\x00\x00MappingStrings\x00\x01\x00\x00\x00\x19\x19\x00\x00\x00Win32API|Process Status|SYSTEM_PROCESS_INFORMATION|VirtualSize\x00\x00WindowsVersion\x00\x08\x00\x00\x00\x1e\x00\x82\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\xa0\x19\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\xa8\x19\x00\x00\x02\x08 \x00\x00\xb8\x19\x00\x00\x00string\x00\x00MappingStrings\x00\x01\x00\x00\x00\xc0\x19\x00\x00\x00Win32API|Process and Thread Functions|GetProcessVersion\x00\x00WorkingSetSize\x00\x15@\x00\x00\x11\x00J\x00\x00\x00\x02\x00\x00\x00\x1c\x00\x00\x00\n\x00\x00\x80#\x08\x00\x00\x003\x1a\x00\x00\x03\x00\x00\x80"\x0b\x00\x00\x00\xff\xff\x00uint64\x00\x00WriteOperationCount\x00\x15\x00\x00\x00\'\x00\xb6\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00\x87\x1a\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xff\x8f\x1a\x00\x00\x02\x08 \x00\x00\x9f\x1a\x00\x00\x00uint64\x00\x00MappingStrings\x00\x01\x00\x00\x00\xa7\x1a\x00\x00\x00Win32API|Process and Thread Structures|SYSTEM_PROCESS_INFORMATION|WriteOperationCount\x00\x00WriteTransferCount\x00\x15\x00\x00\x00*\x00\xce\x00\x00\x00\x03\x00\x00\x00)\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x00I\x1b\x00\x00\x03\x00\x00\x80\x02\x0b\x00\x00\x00\xff\xffQ\x1b\x00\x00\x02\x08 \x00\x00a\x1b\x00\x00\x00uint64\x00\x00MappingStrings\x00\x01\x00\x00\x00i\x1b\x00\x00\x00Win32API|Process and Thread Structures|SYSTEM_PROCESS_INFORMATION|WriteTransferCount\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00k\x02\x00\x00\x00\x00\x00\x00\x000\x03\x00\xf0\xf0\x03\x00\x00\x00\x00\x00\x036\x00\x00\x00K\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00`\x00\x00\x00v\x00\x00\x00\x12\x00\x00\x00\x07\x01\x00\x00\x0f\x00\x00\x00|\xd3\xd44\xbd\x02\x00\x00\x87\x00\x00\x00\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x008\x00\x00\x008\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x9e\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01"\x01\x00\x80\x00Win32_Process\x00\x000\x00\x00Win32_Process\x00\x00System Idle Process\x00\x00System Idle Process\x00\x00System Idle Process\x00\x00Win32_ComputerSystem\x00\x00WIN-8K15VKV24SG\x00\x00Win32_OperatingSystem\x00\x0010.0.17763\x00\x00Microsoft Windows Server 2019 Datacenter Evaluation|C:\\Windows|\\Device\\Harddisk0\\Partition2\x00\x0020260105174910.413931-480\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    encodingUnit: ENCODING_UNIT = ENCODING_UNIT(data)

    # encodingUnit.show()

    objBlk: OBJECT_BLOCK = encodingUnit.ObjectBlock
    objBlk.parseObject()

    # print(objBlk.isInstance())

    print(encodingUnit.ObjectBlock.ctCurrent.get("values"))
    values = encodingUnit.ObjectBlock.ctCurrent.get("values")
    properties = objBlk.ctCurrent.properties

    for name, info in properties.items():
        print(name, info.get("value"))  # class default or stringified default
        if values:
            print("instance value:", values.get(name))

    # print(encodingUnit.ObjectBlock.ctCurrent.properties)
    # encodingUnit.ObjectBlock.printInformation()
