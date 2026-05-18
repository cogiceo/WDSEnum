from impacket.dcerpc.v5.ndr import *
from impacket.dcerpc.v5.dtypes import *
from impacket.dcerpc.v5.rpcrt import *
from enum import IntEnum, IntFlag

MSRPC_UUID_WDSC = uuidtup_to_bin(("1a927394-352e-4553-ae3f-7cf4aafca620", "1.0"))

################################################################################
# CONSTANTS
################################################################################


## MS-WDSC ##
# 2.2.1.2.1 Packet Type
class WdscplPacketType(IntEnum):
    REQUEST = 0x01
    REPLY = 0x02


# 2.2.1.3.2.1 Base Types
class WdscplVarType(IntEnum):
    BYTE = 0x01
    USHORT = 0x02
    ULONG = 0x04
    ULONG64 = 0x08
    STRING = 0x10
    WSTRING = 0x20
    BLOB = 0x40
    ARRAY = 0x1000


## MS-WDSOSD ##
# 2.2 Message Syntax - OS Deployment
class WdsOpCode(IntEnum):
    IMG_ENUMERATE = 0x02
    LOG_INIT = 0x03
    LOG_MSG = 0x04
    GET_CLIENT_UNATTEND = 0x05
    GET_UNATTEND_VARIABLES = 0x06
    GET_DOMAIN_JOIN_INFORMATION = 0x07
    RESET_BOOT_PROGRAM = 0x08


# 2.2 Message Syntax - Dynamic Driver Provisioning
class DdpOpCode(IntEnum):
    GET_MACHINE_DRIVER_PACKAGES = 0xC8


# 2.2 Message Syntax - Deployment Agent Metadata
class WdsdcmgrOpCode(IntEnum):
    QUERY_METADATA = 0x02


# 2.2.8 Architecture
class ProcessorArchitecture(IntEnum):
    AMD64 = 0x09
    INTEL = 0x00
    IA64 = 0x06
    ARM64 = 0x0B
    ARM = 0x05


# 2.2.2 WDS_OP_LOG_MSG - MESSAGE_TYPE
class WdsLogTypeClient(IntEnum):
    STARTED = 0x02
    FINISHED = 0x03
    IMAGE_SELECTED = 0x04
    APPLY_STARTED = 0x05
    APPLY_FINISHED = 0x06
    GENERIC_MESSAGE = 0x07
    UNATTEND_MODE = 0x08
    TRANSFER_START = 0x09
    TRANSFER_END = 0x0A
    TRANSFER_DOWNGRADE = 0x0B
    DOMAINJOINERROR = 0x0C
    POST_ACTIONS_START = 0x0D
    POST_ACTIONS_END = 0x0E
    APPLY_STARTED_2 = 0x0F
    APPLY_FINISHED_2 = 0x10
    DOMAINJOINERROR_2 = 0x11
    DRIVER_PACKAGE_NOT_ACCESSIBLE = 0x12
    OFFLINE_DRIVER_INJECTION_START = 0x13
    OFFLINE_DRIVER_INJECTION_END = 0x14
    OFFLINE_DRIVER_INJECTION_FAILURE = 0x15
    IMAGE_SELECTED2 = 0x16


# 2.2.3 WDS_OP_GET_CLIENT_UNATTEND - Unattend - FLAGS
class WdsCliUnattendFlags(IntFlag):
    NONE = 0x00
    PRESENT = 0x01
    OVERRIDE = 0x02


# 2.2.3 WDS_OP_GET_CLIENT_UNATTEND - Firmware - FLAGS
class WdsCliFirmwareType(IntEnum):
    PCAT = 0x00
    UEFI = 0x01


# 2.2.6 WDS_OP_IMG_ENUMERATE - Client Capability
class ClientCapFlags(IntFlag):
    NONE = 0x00
    SUPPORT_V2 = 0x01
    SUPPORT_VHDX = 0x02


# 1.9 Standards Assignments
OS_DEPLOYMENT_GUID = "5AEBDED8FDEFB24399FC1A8A5921C227"
DYNAMIC_DRIVER_PROVISIONING_GUID = "AC241D013ACB3947A3395D2E1B5306CE"  # Observed GUID differs from docs
DEPLOYMENT_AGENT_METADATA_GUID = "B7DF44106BA3C34092BBAC4152187CB3"
MULTICAST_SESSION_INITIALISATION = "17A3136F8736544B81A5504DAA9062FA"

## Observed architecture mapping
ARCH_MAP = {
    "x86": (WdsCliFirmwareType.PCAT.value, ProcessorArchitecture.INTEL.value),
    "x64": (WdsCliFirmwareType.PCAT.value, 0x09),
    "arm": (WdsCliFirmwareType.PCAT.value, 0x05),
    "arm64": (WdsCliFirmwareType.PCAT.value, 0x0C),
    "x86_uefi": (WdsCliFirmwareType.UEFI.value, ProcessorArchitecture.INTEL.value),
    "x64_uefi": (WdsCliFirmwareType.UEFI.value, ProcessorArchitecture.AMD64.value),
}

################################################################################
# STRUCTURES
################################################################################


class WDSEndpointHeader(NDRSTRUCT):
    structure = (
        ("SizeOfHeader", "<H=0x28"),
        ("Version", "<H=0x0100"),
        ("PacketSize", "<L"),
        ("EndpointGUID", "16s"),
        ("Reserved", "16s=b''"),
    )


class WDSOperationHeader(NDRSTRUCT):
    structure = (
        ("PacketSize", "<L"),
        ("Version", "<H=0x0100"),
        ("PacketType", "<B=0x01"),
        ("Padding1", "<B=0"),
        ("OpCodeErrorCode", "<L"),
        ("VariableCount", "<L"),
    )


class WDSVariableBlock(NDRSTRUCT):
    structure = (
        ("VariableName", "66s"),
        ("Padding1", "<H=0"),
        ("VariableType", "<L"),
        ("ValueLength", "<L"),
        ("ArraySize", "<L=0"),
        ("VariableValue", ":"),
        ("PaddingEnd", ":"),
    )

    def fromString(self, data, offset=0):
        NDRSTRUCT.fromString(self, data[offset : offset + 80])
        offset += 80

        clean_name = self["VariableName"].split(b"\x00\x00", 1)[0]
        self["VariableName"] = clean_name.ljust(66, b"\x00")

        value_size = self.get_value_size()
        self["VariableValue"] = data[offset : offset + value_size]
        offset += value_size

        pad_len = self.padding()
        self["PaddingEnd"] = data[offset : offset + pad_len]
        offset += pad_len

        return offset

    def get_value_size(self):
        is_array = bool(self["VariableType"] & WdscplVarType.ARRAY)

        if is_array:
            return self["ValueLength"] * self["ArraySize"]

        return self["ValueLength"]

    def padding(self):
        block_size = 80 + self.get_value_size()
        padding = 16 - (block_size % 16)
        if bool(self["VariableType"] & (WdscplVarType.STRING | WdscplVarType.WSTRING | WdscplVarType.BLOB)):
            # Observed padding rule
            if padding < 4:
                return padding + 16
        return padding

    def set(self, var_type, name, value):
        # Array construction does not work currently
        if isinstance(value, list):
            array_size = len(value)
            encoded_items = []

            if array_size == 0:
                raise ValueError("ArraySize MUST NOT be zero")

            # Fixed-size integers
            if all(isinstance(v, int) for v in value):
                raw_items = [v.to_bytes(var_type, "little") for v in value]

            # Strings
            elif all(isinstance(v, str) for v in value):
                for v in value:
                    if var_type == WdscplVarType.WSTRING:
                        raw_items = [v.encode("utf-16le") + b"\x00\x00" for v in value]
                    else:
                        raw_items = [v.encode("ascii") + b"\x00" for v in value]

            elif all(isinstance(v, (bytes, bytearray)) for v in value):
                raw_items = [bytes(v) for v in value]

            max_len = max(len(v) for v in raw_items)

            for item in raw_items:
                encoded_items.append(item.ljust(max_len, b"\x00"))

            encoded = b"".join(encoded_items)
            self["ValueLength"] = max_len
            self["ArraySize"] = array_size

        else:
            if isinstance(value, int):
                encoded = value.to_bytes(var_type, "little")

            elif isinstance(value, str):
                if var_type == WdscplVarType.WSTRING:
                    encoded = value.encode("utf-16le") + b"\x00\x00"
                else:
                    encoded = value.encode("ascii") + b"\x00"

            elif isinstance(value, bytes):
                encoded = value

            self["ValueLength"] = len(encoded)
            self["ArraySize"] = 0

        self["VariableName"] = name.encode("utf-16le") + b"\x00\x00"
        self["VariableType"] = var_type + WdscplVarType.ARRAY if self["ArraySize"] else var_type
        self["VariableValue"] = encoded

        self["PaddingEnd"] = b"\x00" * self.padding()
        return self


class WDSVariableBlockArray(NDRUniConformantArray):
    item = WDSVariableBlock

    def fromString(self, data, offset=0):

        for _ in range(self["MaximumCount"]):
            block = self.item()
            offset = block.fromString(data, offset)
            self["Data"].append(block)

        return offset

    def getData(self, soFar=0):
        return b"".join([block.getData() for block in self["Data"]])

    def to_dict(self):
        output = {}
        for block in self["Data"]:
            key = block["VariableName"].decode("utf-16le").strip("\x00")
            type = block["VariableType"]
            value = block["VariableValue"]

            try:
                if not type & (WdscplVarType.ARRAY | WdscplVarType.BLOB):
                    if type & (WdscplVarType.BYTE | WdscplVarType.USHORT | WdscplVarType.ULONG | WdscplVarType.ULONG64):
                        value = hex(int.from_bytes(value, "little"))
                    elif type & WdscplVarType.STRING:
                        value = value.decode("ascii").strip("\x00")
                    elif type & WdscplVarType.WSTRING:
                        value = value.decode("utf-16le").strip("\x00")
            except Exception as e:
                logging.debug(f"Failed to decode value of {key} : {e}")

            output.update({key: value})
        return output


class WDSRequestPacket(NDRSTRUCT):
    structure = (
        ("Endpoint", WDSEndpointHeader),
        ("Operation", WDSOperationHeader),
        ("Variables", WDSVariableBlockArray),
    )

    def getData(self):
        return b"".join([self.fields[attr].getData() for attr in self.fields.keys()])

    def fromString(self, data, offset=0):
        # Parse endpoint
        self["Endpoint"] = WDSEndpointHeader(data[offset:])
        offset += len(self["Endpoint"].getData())

        # Parse operation
        self["Operation"] = WDSOperationHeader(data[offset:])
        offset += len(self["Operation"].getData())

        # Parse variables from remaining payload
        var_blocks = WDSVariableBlockArray()
        var_blocks["MaximumCount"] = self["Operation"]["VariableCount"]
        var_blocks.fromString(data[offset:])
        self["Variables"] = var_blocks

        return offset


################################################################################
# HELPER FUNCTIONS
################################################################################


class WdsRpcMessage(NDRCALL):
    opnum = 0
    structure = (
        ("uRequestPacketSize", ULONG),
        ("uRequestPacketSize2", ULONG),
        ("bRequestPacket", WDSRequestPacket),
        ("ErrorCode", ULONG),
    )

    def getData(self):
        return b"".join([self.fields[attr].getData() for attr in self.fields.keys()])


class WdsRpcMessageResponse(NDRCALL):
    structure = (
        ("puReplyPacketSize", ULONG),
        ("Unknown", ULONG),
        ("puReplyPacketSize2", ULONG),
        ("pbReplyPacket", WDSRequestPacket),
    )

    def getData(self):
        return b"".join([self.fields[attr].getData() for attr in self.fields.keys()])


################################################################################
# RPC Connection
################################################################################


def hWdsRpcMessage(dce, endpoint_guid, opcode, variables):
    req = WdsRpcMessage()

    # Variable block
    for variable in variables:
        var_type, name, value = variable
        block = WDSVariableBlock().set(var_type, name, value)
        req["bRequestPacket"].fields["Variables"]["Data"].append(block)

    # Operation block
    req["bRequestPacket"]["Operation"]["OpCodeErrorCode"] = opcode
    req["bRequestPacket"]["Operation"]["VariableCount"] = len(variables)
    req["bRequestPacket"]["Operation"]["PacketSize"] = 16 + len(req["bRequestPacket"].fields["Variables"])

    # Endpoint block
    req["bRequestPacket"]["Endpoint"]["PacketSize"] = req["bRequestPacket"]["Operation"]["PacketSize"]
    req["bRequestPacket"]["Endpoint"]["EndpointGUID"] = bytes.fromhex(endpoint_guid)

    req["uRequestPacketSize"] = len(req["bRequestPacket"])
    req["uRequestPacketSize2"] = len(req["bRequestPacket"])

    return dce.request(req)
