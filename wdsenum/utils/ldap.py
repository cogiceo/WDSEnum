import logging
import socket
import traceback

from impacket.ldap.ldap import LDAPConnection, LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry, SDFlagsControl, SimplePagedResultsControl


class LDAPUtils:
    def __init__(
        self,
        dc,
        domain,
        logon_domain,
        username,
        password,
        lmhash,
        nthash,
        do_kerberos,
        aeskey,
        use_ldaps,
        use_gc,
        timeout,
    ):
        self.__kdc = dc
        self.__username = username
        self.__domain = domain
        self.__logon_domain = logon_domain if logon_domain else self.__domain
        self.__password = password
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__do_kerberos = do_kerberos
        self.__aeskey = aeskey
        self.__ldaps_flag = use_ldaps
        self.__gc_flag = use_gc
        self.__timeout = timeout
        self.base_dn = ",".join(f"DC={part}" for part in domain.split("."))

        if self.__ldaps_flag:
            prefix = "ldaps://"
        elif self.__gc_flag:
            prefix = "gc://"
        else:
            prefix = "ldap://"

        self.ldap_conn = None
        try:
            socket.setdefaulttimeout(self.__timeout)
            self.ldap_conn = LDAPConnection(f"{prefix}{self.__kdc}", self.__kdc)
            self.ldap_conn.searchBase = self.base_dn

            if self.__do_kerberos:
                self.ldap_conn.kerberosLogin(
                    self.__username,
                    self.__password,
                    self.__logon_domain,
                    self.__lmhash,
                    self.__nthash,
                    self.__aeskey,
                    self.__kdc,
                )
            else:
                self.ldap_conn.login(
                    self.__username, self.__password, self.__logon_domain, self.__lmhash, self.__nthash
                )
        except TimeoutError as e:
            logging.debug(traceback.format_exc())
            logging.info(e)

    def search(self, ldap_filter="(ObjectClass=*)", attributes=["distinguishedName"]):
        """
        LDAP search request
        """
        entries = []
        ldap_connection = self.ldap_conn

        try:
            result = ldap_connection.search(
                searchFilter=ldap_filter,
                searchBase=self.base_dn,
                attributes=attributes,
                searchControls=[SDFlagsControl(), SimplePagedResultsControl(size=500)],
            )

            for raw_entry in result:
                if isinstance(raw_entry, SearchResultEntry):
                    entry = {}
                    for attr in raw_entry["attributes"]:
                        attr_type = str(attr["type"])
                        values = []
                        for value in attr["vals"]:
                            if attr_type in ("netbootGUID", "netbootDUID"):
                                values.append(bytes(value).hex())
                            else:
                                values.append(bytes(value).decode(errors="ignore"))
                        entry[attr_type] = values if len(values) > 1 else values[0]
                    entries.append(entry)

        except LDAPSearchError as e:
            logging.debug(traceback.format_exc())
            logging.info(f"Search failed on {self.base_dn}: {e}")

        return entries

    def get_wds_servers(self):
        """
        Get a list of WDS server hostnames
        """
        # Get WDS servers DN
        wds_servers_dn = self.search(
            ldap_filter="(netbootServer=*)",
            attributes=["distinguishedName", "netbootServer"],
        )

        hostnames = []
        for entry in wds_servers_dn:
            server_dn = entry.get("netbootServer")
            if not server_dn:
                continue

            try:
                # Get sAMAccountName and dNSHostName of the WDS server
                results = self.search(
                    ldap_filter=f"(distinguishedName={server_dn})",
                    attributes=["sAMAccountName", "dNSHostName"],
                )
            except LDAPSearchError as e:
                logging.debug(traceback.format_exc())
                logging.info(f"Could not resolve WDS server DN {server_dn}: {e}")
                continue

            if not results:
                continue

            # WDS server in hostname format
            server = results[0]
            if "dNSHostName" in server:
                hostnames.append(server["dNSHostName"])
            elif "sAMAccountName" in server:
                name = server["sAMAccountName"].rstrip("$")
                hostnames.append(f"{name}.{self.__domain}")
            else:
                logging.debug(f"Could not resolve hostname for DN {server_dn}")

        return hostnames

    def get_prestaged_computers(self):
        """
        Get prestage computer accounts that have a WDS unattend file path set
        """
        return self.search(
            ldap_filter="(netbootMirrorDataFile=*WdsUnattendFilePath=*)",
            attributes=[
                "distinguishedName",
                "sAMAccountName",
                "netbootGUID",
                "netbootDUID",
                "netbootMachineFilePath",
                "netbootMirrorDataFile",
            ],
        )
