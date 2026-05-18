import logging
import traceback

from wdsenum.utils.smb import SMBUtils
from wdsenum.utils.ldap import LDAPUtils
from wdsenum.utils.rpc import RPCUtils
from wdsenum.utils.misc import transform_guid, save_file
from wdsenum.dcerpc.wdsc import hWdsRpcMessage, ARCH_MAP

from rich.panel import Panel
from rich.console import Console
from rich.pretty import Pretty

from impacket.dcerpc.v5.rpcrt import DCERPCException

console = Console()


class WDSEnum:
    def __init__(
        self,
        cmd,
        output_folder,
        yes=False,
        dc="",
        domain="",
        logon_domain="",
        username="",
        password="",
        hashes="",
        do_kerberos=False,
        aeskey="",
        use_ldaps=False,
        use_gc=False,
        timeout=60,
    ):
        self.__output_folder = output_folder
        self.__yes = yes
        self.__dc = dc
        self.__domain = domain
        self.__logon_domain = logon_domain
        self.__username = username
        self.__password = password if password else ""
        self.__lmhash = ""
        self.__nthash = ""
        self.__do_kerberos = do_kerberos
        self.__aeskey = aeskey

        if hashes:
            self.__lmhash, self.__nthash = hashes.split(":")

        self.rpc = RPCUtils(
            dc=self.__dc,
            logon_domain=self.__logon_domain,
            username=self.__username,
            password=self.__password,
            lmhash=self.__lmhash,
            nthash=self.__nthash,
            aeskey=self.__aeskey,
            do_kerberos=self.__do_kerberos,
        )

        if cmd == "unattend":
            self.ldap = LDAPUtils(
                dc=self.__dc,
                domain=self.__domain,
                logon_domain=self.__logon_domain,
                username=self.__username,
                password=self.__password,
                lmhash=self.__lmhash,
                nthash=self.__nthash,
                do_kerberos=self.__do_kerberos,
                aeskey=self.__aeskey,
                use_ldaps=use_ldaps,
                use_gc=use_gc,
                timeout=timeout,
            )
            self.smb = SMBUtils(
                kdc_host=self.__dc,
                logon_domain=self.__logon_domain,
                username=self.__username,
                password=self.__password,
                lmhash=self.__lmhash,
                nthash=self.__nthash,
                do_kerberos=self.__do_kerberos,
                aeskey=self.__aeskey,
            )

    def arch_unattend(self, target):
        """
        Iterates over all known architecture/firmware combinations and requests an unattend file for each from the WDS server
        """
        console.print(f"  [underline]Retrieving architecture-specific unattend files", highlight=False)

        dce = self.rpc.connect(target)

        if dce:
            found = False
            saved_file = []

            try:

                # Iterates over architecture/firmware combinations
                for arch, (firmware, architecture) in ARCH_MAP.items():

                    # RPC request variables
                    endpoint_guid, opcode, variables = self.rpc.get_client_unattend(
                        firmware=firmware,
                        architecture=architecture,
                    )
                    try:
                        # RPC request and response
                        resp = hWdsRpcMessage(dce, endpoint_guid, opcode, variables)
                        if resp:
                            resp_var = resp["pbReplyPacket"].fields["Variables"].to_dict()

                            # Retrieve unattend file if it exists
                            if "CLIENT_UNATTEND" in resp_var:
                                if not found:
                                    found = True
                                    console.print(
                                        "   [green bold][+][/green bold] Found unattend file(s) for architecture(s) :",
                                        highlight=False,
                                    )
                                msg = f"      [bold]- {arch}[/]"
                                if self.__yes:
                                    console.print(msg, highlight=False)

                                file = save_file(
                                    msg, self.__output_folder, target, arch, resp_var["CLIENT_UNATTEND"], self.__yes
                                )
                                if file:
                                    saved_file.append(file)
                    except DCERPCException as e:
                        logging.debug(traceback.format_exc())
                        logging.info(e)

            finally:
                dce.disconnect()

            if not found:
                console.print("   [red bold][-][/red bold] No architecture-specific unattend files found")
            elif saved_file:
                console.print(
                    f"   [green bold][+][/green bold] Saved unattend file(s) : [bold]{', '.join(saved_file)}",
                    highlight=False,
                )
        else:
            console.print("   [red bold][-][/red bold] Failed to connect to the RPC server", highlight=False)

        console.print()

    def device_id_unattended(self, server, id):
        """
        Retrieve a custom unattend file using a device ID from the WDS server
        """

        console.print(f"  [underline]Retrieving a custom unattend file using a device ID", highlight=False)

        dce = self.rpc.connect(server)

        if dce:
            try:
                # Format device ID for RPC request
                device_id = id.strip("{").strip("}")
                if "-" in id == 36:
                    device_id = transform_guid(device_id)
                elif "-" in id:
                    device_id = id.replace("-", "")
                else:
                    device_id = id

                # RPC request variables without a device ID do get the default response
                endpoint_guid, opcode, variables = self.rpc.get_client_unattend()
                default_resp = hWdsRpcMessage(dce, endpoint_guid, opcode, variables)
                default_unattend = None
                if default_resp:
                    default_resp_var = default_resp["pbReplyPacket"].fields["Variables"].to_dict()
                    if "CLIENT_UNATTEND" in default_resp_var:
                        default_unattend = default_resp_var["CLIENT_UNATTEND"]

                # RPC request variables with a device ID
                endpoint_guid, opcode, variables = self.rpc.get_client_unattend(
                    client_guid=device_id,
                    client_mac=device_id,
                )

                resp = hWdsRpcMessage(dce, endpoint_guid, opcode, variables)
                if resp:
                    resp_var = resp["pbReplyPacket"].fields["Variables"].to_dict()

                    # Verify that the unattend file is not the default one
                    if "CLIENT_UNATTEND" in resp_var and resp_var["CLIENT_UNATTEND"] != default_unattend:
                        msg = f"   [green bold][+][/green bold] Found custom unattend file for [bold]{id}[/bold] :"
                        if self.__yes:
                            console.print(msg, highlight=False)

                        file_saved = save_file(
                            msg, self.__output_folder, server, device_id, resp_var["CLIENT_UNATTEND"], self.__yes
                        )
                        if file_saved:
                            console.print(
                                f"   [green bold][+][/green bold] Saved unattend file(s) : [bold]{file_saved}",
                                highlight=False,
                            )
                        return
                console.print(
                    f"   [red bold][-][/red bold] No custom unattend file found for device ID : [bold]{id}",
                    highlight=False,
                )

            except DCERPCException as e:
                logging.debug(traceback.format_exc())
                logging.error(e)
            finally:
                dce.disconnect()
        else:
            console.print("   [red bold][-][/red bold] Failed to connect to the RPC server", highlight=False)

    def all_device_id_unattended(self, server, computers):
        """
        For each prestaged computer, requests its specific unattend file from the WDS server using its netbootGUID or netbootDUID.
        """

        console.print(f"  [underline]Retrieving custom unattend file for prestage computer(s)", highlight=False)

        dce = self.rpc.connect(server)

        if dce:
            found = False
            saved_file = []

            try:
                # Iterates over prestage computers
                for computer in computers:
                    device_id = computer.get("netbootGUID") or computer.get("netbootDUID")
                    if not device_id:
                        continue

                    # RPC request variables with the computer device ID
                    endpoint_guid, opcode, variables = self.rpc.get_client_unattend(
                        client_guid=device_id,
                        client_mac=device_id,
                    )
                    resp = hWdsRpcMessage(dce, endpoint_guid, opcode, variables)

                    # RPC request and response parsing
                    if resp:
                        resp_var = resp["pbReplyPacket"].fields["Variables"].to_dict()
                        if "CLIENT_UNATTEND" in resp_var:
                            if not found:
                                found = True
                                console.print(
                                    "   [green bold][+][/green bold] Found unattend file for prestage computer(s) :",
                                    highlight=False,
                                )
                            msg = f"      [bold]- '{computer['sAMAccountName']}'[/]"
                            if self.__yes:
                                console.print(msg, highlight=False)

                            file = save_file(
                                msg,
                                self.__output_folder,
                                server,
                                computer["sAMAccountName"].strip("$"),
                                resp_var["CLIENT_UNATTEND"],
                                self.__yes,
                            )
                            if file:
                                saved_file.append(file)

            except DCERPCException as e:
                logging.debug(traceback.format_exc())
                logging.info(e)
            finally:
                dce.disconnect()

            if not found:
                console.print(
                    "   [red bold][-][/red bold] No unattend files found for prestaged computers", highlight=False
                )
            elif saved_file:
                console.print(
                    f"   [green bold][+][/green bold] Saved unattend file(s) : [bold]{', '.join(saved_file)}",
                    highlight=False,
                )
        else:
            console.print("   [red bold][-][/red bold] Failed to connect to the RPC server")

        console.print()

    def images_unattend(self, server):
        """
        Enumerates images and their unattend files on a WDS server over SMB.
        """

        console.print(f"  [underline]Retrieving unattend files for install image(s)", highlight=False)

        found = False
        saved_file = []
        try:
            self.smb.connect(server)
        except Exception as e:
            logging.debug(traceback.format_exc())
            logging.info(e)
            console.print(f"   [red bold][-][/red bold] Failed to connect to the SMB server\n")
            return

        try:
            # List images contained in image groups
            for image in self.smb.list_images():
                # Try to get unattend file associated to the image if it exist
                content = self.smb.read_unattend_file(image["path"])
                if content:
                    if not found:
                        found = True
                        console.print(
                            "   [green bold][+][/green bold] Found unattend file for install image(s) :",
                            highlight=False,
                        )
                    msg = f"      [bold]- '{image['group']}/{image['name']}'[/]"
                    if self.__yes:
                        console.print(msg, highlight=False)

                    file = save_file(
                        msg, self.__output_folder, server, f"{image['group']}_{image['name']}", content, self.__yes
                    )
                    if file:
                        saved_file.append(file)
                else:
                    logging.debug(f"No unattend file for {image['group']}/{image['name']}")
        except Exception as e:
            logging.debug(traceback.format_exc())
            logging.info(e)
        finally:
            self.smb.close()

        if not found:
            console.print("   [red bold][-][/red bold] No prestage computer unattend file found")
        elif saved_file:
            console.print(
                f"   [green bold][+][/green bold] Saved unattend file(s) : [bold]{', '.join(saved_file)}",
                highlight=False,
            )

        console.print()

    def all_unattend(self):
        """
        Full authenticated enumeration across all discovered WDS servers
        """

        console.print(Panel(f"[bold]WDS LDAP enumeration[/bold]", expand=False))

        if not self.ldap.ldap_conn:
            console.print(" [red bold][-][/red bold] Failed to connect to the LDAP server")
            return

        # Recover all WDS servers in LDAP
        try:
            servers = self.ldap.get_wds_servers()
            if not servers:
                console.print(" [red bold][-][/red bold] No WDS server found in LDAP")
                return
            servers.sort(key=str.lower)
        except Exception as e:
            logging.debug(traceback.format_exc())
            logging.info(e)
            console.print(" [red bold][-][/red bold] Error retrieving WDS server from LDAP")
            return
        console.print(f" [green bold][+][/green bold] Found {len(servers)} WDS server(s)", highlight=False)

        if logging.getLogger().getEffectiveLevel() <= logging.INFO:
            console.print(Pretty(servers, expand_all=True), highlight=False)

        # Recover all prestage computer in LDAP
        try:
            computers = self.ldap.get_prestaged_computers()
            if computers:
                console.print(
                    f" [green bold][+][/green bold] Found {len(computers)} prestage computer(s) with a custom unattend file\n",
                    highlight=False,
                )
                if logging.getLogger().getEffectiveLevel() <= logging.INFO:
                    console.print(Pretty(computers, expand_all=True), highlight=False)
            else:
                console.print(" [red bold][-][/red bold] No prestaged computers with custom unattend files found\n")

        except Exception as e:
            logging.debug(traceback.format_exc())
            logging.info(e)
            console.print(" [red bold][-][/red bold] Error finding prestage computers in LDAP\n")
            return

        # Use all methods to recover unattend files for each server
        for server in servers:
            console.print(Panel(f"[bold]WDS Server : {server}[/bold]", expand=False))

            self.arch_unattend(server)
            if computers:
                self.all_device_id_unattended(server, computers)
            self.images_unattend(server)
