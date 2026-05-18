import logging
import traceback

from wdsenum.dcerpc.wdsc import *
from impacket.dcerpc.v5 import transport


class RPCUtils:
    def __init__(
        self, dc="", logon_domain="", username="", password="", lmhash="", nthash="", aeskey="", do_kerberos=False
    ):
        self.__dc = dc
        self.__logon_domain = logon_domain
        self.__username = username
        self.__password = password
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__aeskey = aeskey
        self.__do_kerberos = do_kerberos

    def connect(self, target):
        """
        Establishes a DCE/RPC connection to the WDS server.
        """
        stringbinding = f"ncacn_ip_tcp:{target}[5040]"
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_connect_timeout(10)
        rpctransport.set_kerberos(True, self.__dc)

        if self.__logon_domain:
            rpctransport.set_credentials(
                self.__username,
                self.__password,
                self.__logon_domain,
                self.__lmhash,
                self.__nthash,
                self.__aeskey,
            )

        dce = rpctransport.get_dce_rpc()

        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        if self.__do_kerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        try:
            dce.connect()
        except (DCERPCException, socket.gaierror) as e:
            logging.debug(traceback.format_exc())
            logging.info(e)
            return

        dce.bind(MSRPC_UUID_WDSC)
        return dce

    def img_enumerate(self, cap_flag=ClientCapFlags.SUPPORT_V2):
        """
        [MS-WDSOSD] - 2.2.6 WDS_OP_IMG_ENUMERATE
        """

        variables = [
            (WdscplVarType.ULONG, "VERSION", 1),
            (WdscplVarType.ULONG, "CC", cap_flag),
        ]
        return OS_DEPLOYMENT_GUID, WdsOpCode.IMG_ENUMERATE, variables

    def log_init(self):
        """
        [MS-WDSOSD] - 2.2.1 WDS_OP_LOG_INIT
        """

        variables = [
            (WdscplVarType.ULONG, "VERSION", 1),
        ]
        return OS_DEPLOYMENT_GUID, WdsOpCode.LOG_INIT, variables

    def log_msg(self, transaction_id, client_uuid, client_ip, client_mac):
        """
        [MS-WDSOSD] - 2.2.2 WDS_OP_LOG_MSG
        """

        variables = [
            (WdscplVarType.ULONG, "VERSION", 1),
            (WdscplVarType.ULONG, "MESSAGE_TYPE", 2),
            (WdscplVarType.WSTRING, "CLIENT_ADDRESS", client_ip),
            (WdscplVarType.WSTRING, "CLIENT_UUID", client_uuid),
            (WdscplVarType.WSTRING, "TRANSACTION_ID", transaction_id),
            (WdscplVarType.ULONG, "ARCHITECTURE", ProcessorArchitecture.AMD64),
        ]
        return OS_DEPLOYMENT_GUID, WdsOpCode.LOG_MSG, variables

    def get_client_unattend(
        self,
        client_guid="0" * 32,
        client_mac="0" * 12,
        firmware=WdsCliFirmwareType.PCAT,
        architecture=ProcessorArchitecture.AMD64,
    ):
        """
        [MS-WDSOSD] - 2.2.3 WDS_OP_GET_CLIENT_UNATTEND
        """

        variables = [
            (WdscplVarType.ULONG, "VERSION", 1),
            (WdscplVarType.ULONG, "ARCHITECTURE", architecture),
            (WdscplVarType.BYTE, "FIRMWARE", firmware),
            (WdscplVarType.WSTRING, "CLIENT_GUID", client_guid),
            (WdscplVarType.WSTRING, "CLIENT_MAC", client_mac),
        ]
        return OS_DEPLOYMENT_GUID, WdsOpCode.GET_CLIENT_UNATTEND, variables

    def get_unattend_variables(self, client_guid="0" * 32, client_mac="0" * 12):
        """
        [MS-WDSOSD] - 2.2.4 WDS_OP_GET_UNATTEND_VARIABLES
        """

        variables = [
            (WdscplVarType.ULONG, "VERSION", 1),
            (WdscplVarType.WSTRING, "CLIENT_GUID", client_guid),
            (WdscplVarType.WSTRING, "CLIENT_MAC", client_mac),
        ]
        return OS_DEPLOYMENT_GUID, WdsOpCode.GET_UNATTEND_VARIABLES, variables

    def get_domain_join_information(self, device_id="0" * 32):
        """
        [MS-WDSOSD] - 2.2.5 WDS_OP_GET_DOMAIN_JOIN_INFORMATION
        """
        variables = [
            (WdscplVarType.ULONG, "VERSION", 1),
            (WdscplVarType.WSTRING, "CLIENT_GUID", device_id),
            (WdscplVarType.WSTRING, "CLIENT_MAC", device_id),
        ]
        return OS_DEPLOYMENT_GUID, WdsOpCode.GET_DOMAIN_JOIN_INFORMATION, variables

    def reset_boot_program(self, device_id="0" * 32):
        """
        [MS-WDSOSD] - 2.2.10 WDS_OP_RESET_BOOT_PROGRAM
        """
        variables = [
            (WdscplVarType.ULONG, "VERSION", 1),
            (WdscplVarType.WSTRING, "CLIENT_GUID", device_id),
            (WdscplVarType.WSTRING, "CLIENT_MAC", device_id),
        ]
        return OS_DEPLOYMENT_GUID, WdsOpCode.RESET_BOOT_PROGRAM, variables

    def get_machine_driver_packages(self):
        """
        [MS-WDSOSD] - 2.2.7 DDP_OP_GET_MACHINE_DRIVER_PACKAGES
        """
        variables = [
            (WdscplVarType.ULONG, "VERSION", 1),
        ]
        return DYNAMIC_DRIVER_PROVISIONING_GUID, DdpOpCode.GET_MACHINE_DRIVER_PACKAGES, variables

    def query_metadata(self, device_id):
        """
        [MS-WDSOSD] - 2.2.9 WDSDCMGR_OP_QUERY_METADATA
        """
        if not "-" in device_id:
            device_id = "-".join(device_id[i : i + 2] for i in range(0, len(device_id), 2))

        variables = [
            (WdscplVarType.WSTRING, "Metadata.Entry[0]", "WDS.Request.Type='Deployment'"),
            # (WdscplVarType.WSTRING, "Metadata.Entry[0]", "WDS.Request.Type='PXE'"),
            (WdscplVarType.WSTRING, "Metadata.Entry[1]", f"WDS.Device.ID=[{device_id}]"),
        ]

        meta_count = 0
        metars_count = 0
        for variable in variables:
            if variable[1].startswith("Metadata.Entry"):
                meta_count += 1
            if variable[1].startswith("MetadataRS.Entry"):
                metars_count += 1

        variables.append((WdscplVarType.ULONG, "Metadata.Count", meta_count))
        variables.append((WdscplVarType.ULONG, "MetadataRS.Count", metars_count))

        return DEPLOYMENT_AGENT_METADATA_GUID, WdsdcmgrOpCode.QUERY_METADATA, variables

    def mutlticast_initiate(self, namespace="", content="", client=""):
        """
        [MS-WDSOSD] - 2.2.7 WDSMC_OP_INITIATE OpCode
        """
        # variables = [
        #    (WdscplVarType.WSTRING, "Namespace", "WDS:ImageGroup1/install-(10).wim/1"),
        #    (WdscplVarType.WSTRING, "Content", "Res.RWM"),
        #    (WdscplVarType.WSTRING, "Client", "myclient"),
        #    (WdscplVarType.ULONG, "Cap", 2),
        # ]
        variables = [
            (WdscplVarType.WSTRING, "Namespace", namespace),
            (WdscplVarType.WSTRING, "Content", content),
            (WdscplVarType.WSTRING, "Client", client),
            (WdscplVarType.ULONG, "Cap", 0),
        ]
        return MULTICAST_SESSION_INITIALISATION, 6, variables
