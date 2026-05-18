import logging
import traceback

from impacket.smbconnection import SMBConnection, SessionError


class SMBUtils:
    def __init__(self, kdc_host, logon_domain, username, password, lmhash, nthash, do_kerberos, aeskey):
        self.__kdc_host = kdc_host
        self.__username = username
        self.__logon_domain = logon_domain
        self.__password = password
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__do_kerberos = do_kerberos
        self.__aeskey = aeskey
        self.smbClient = None

    def connect(self, target):
        """
        Establishes a SMB connection to a WDS server
        """

        self.smbClient = SMBConnection(target, target)

        if self.__do_kerberos is True:
            self.smbClient.kerberosLogin(
                self.__username,
                self.__password,
                self.__logon_domain,
                self.__lmhash,
                self.__nthash,
                self.__aeskey,
                self.__kdc_host,
            )
        else:
            self.smbClient.login(self.__username, self.__password, self.__logon_domain, self.__lmhash, self.__nthash)

    def close(self):
        if self.smbClient:
            try:
                self.smbClient.close()
            except Exception:
                pass
            finally:
                self.smbClient = None

    def _list_dir(self, share, path):
        return [e for e in self.smbClient.listPath(share, path) if e.get_longname() not in (".", "..")]

    def list_images(self):
        """
        Get all images path accessible by a user
        """

        images = []

        try:
            groups = self._list_dir("REMINST", "/Images/*")
        except SessionError as e:
            logging.debug(traceback.format_exc())
            logging.info(e)
            return images

        for group in groups:
            group_name = group.get_longname()
            try:
                entries = self._list_dir("REMINST", f"/Images/{group_name}/*")
            except SessionError as e:
                logging.debug(traceback.format_exc())
                logging.info(f"Could not list group {group_name}: {e}")
                continue

            for entry in entries:
                if entry.is_directory():
                    image_name = entry.get_longname()
                    images.append(
                        {
                            "group": group_name,
                            "name": image_name,
                            "path": f"/Images/{group_name}/{image_name}",
                        }
                    )

        return images

    def read_unattend_file(self, image_path):
        """
        Get the unattend file associated to an image if it exist
        """

        unattend_path = f"{image_path}/Unattend/ImageUnattend.xml"
        content = []

        def collect(data):
            content.append(data)

        try:
            self.smbClient.getFile("REMINST", unattend_path, collect)
        except SessionError as e:
            if not "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                logging.debug(traceback.format_exc())
                logging.info(e)
            return None

        raw = b"".join(content)
        try:
            return raw.decode("utf-16le")
        except UnicodeDecodeError:
            return raw.decode("utf-8", errors="replace")
