#! /usr/bin/env python3
import sys
import logging
import argparse

from wdsenum.wdsenum import WDSEnum
from wdsenum.utils.misc import is_ip

from rich.logging import RichHandler
from rich.panel import Panel
from rich.console import Console

console = Console()


def main():

    # Authentication arguments
    auth_parent = argparse.ArgumentParser(add_help=False)
    auth_parser = auth_parent.add_argument_group(title="Connection")
    auth_parser.add_argument("-i", "--dc", type=str, help="Domain Controller IP address or hostname", required=True)
    auth_parser.add_argument("-d", "--domain", type=str, help="Target domain name", required=True)
    auth_parser.add_argument("-u", "--username", type=str, help="[Domain/]Username for authentication", required=True)
    auth_parser.add_argument("-p", "--password", type=str, help="Password for authentication")
    auth_parser.add_argument("-H", "--hashes", type=str, help="NTLM hashes (LMHASH:NTHASH)")
    auth_parser.add_argument(
        "-k", "--kerberos", action="store_true", help="Use Kerberos authentication (Requires hostnames)"
    )
    auth_parser.add_argument("--aeskey", type=str, help="AES key for Kerberos authentication")

    # WDSEnum parser
    parser = argparse.ArgumentParser(description="WDSEnum")
    subparsers = parser.add_subparsers(title="Commands", dest="command", required=True)

    # Unattend files without authentication
    notauth = subparsers.add_parser(
        "unattend-noauth", help="Enumerate unattend files on a WDS server without authentication"
    )
    notauth.add_argument("--debug", action="store_true", help="Enable debug output")
    notauth.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    notauth.add_argument("-y", "--yes", action="store_true", help="Say yes to all prompts")
    notauth.add_argument("-o", "--output", type=str, help="Output folder to save the unattend files", required=True)

    notauth_parser = notauth.add_argument_group(title="Connection")
    notauth_parser.add_argument(
        "-t", "--target", type=str, help="Target WDS server IP address or hostname", required=True
    )
    notauth_parser.add_argument(
        "-a", "--arch", action="store_true", help="Get unattend files based on architecture and firmware"
    )
    notauth_parser.add_argument(
        "-i", "--id", type=str, help="Get custom unattend file for a device ID (GUID, DUID, MAC)"
    )

    # Unattend files on all WDS servers
    unattend_parser = subparsers.add_parser(
        "unattend", parents=[auth_parent], help="Enumerate all accessible unattend files on all WDS servers"
    )
    unattend_parser.add_argument("--debug", action="store_true", help="Enable debug output")
    unattend_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    unattend_parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Say yes to all prompts",
    )
    unattend_parser.add_argument("-o", "--output", type=str, help="Output folder to save unattend files", required=True)

    ldap_parser = unattend_parser.add_argument_group(title="LDAP flags")
    connection_type = ldap_parser.add_mutually_exclusive_group()
    connection_type.add_argument("--timeout", type=int, default=60, help="LDAP timeout in seconds (default: 60)")
    connection_type.add_argument("--ldaps", action="store_true", help="Use LDAPS (port 636)")
    connection_type.add_argument("--gc", action="store_true", help="Use the Global Catalog (port 3268)")
    args = parser.parse_args()

    # Logging options
    if getattr(args, "debug", False):
        level = logging.DEBUG
    elif getattr(args, "verbose", False):
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[
            RichHandler(
                rich_tracebacks=True,
                show_path=getattr(args, "debug", False),
            )
        ],
    )

    if level != logging.DEBUG:
        logging.getLogger("impacket").disabled = True

    # Commands
    if args.command == "unattend":
        if args.kerberos and is_ip(args.dc):
            console.print("Kerberos authentication requires hostname of the DC instead of an IP")
            sys.exit()

        if "/" in args.username:
            logon_domain, username = args.username.rsplit("/", 1)
        else:
            username = args.username
            logon_domain = args.domain

        wdsenum = WDSEnum(
            args.command,
            args.output,
            args.yes,
            args.dc,
            args.domain,
            logon_domain,
            username,
            args.password,
            args.hashes,
            args.kerberos,
            args.aeskey,
            args.ldaps,
            args.gc,
            args.timeout,
        )
        wdsenum.all_unattend()

    elif args.command == "unattend-noauth":
        wdsenum = WDSEnum(args.command, args.output, args.yes)
        if args.arch or args.id:
            console.print(Panel(f"[bold]Anonymous enumeration of unattend files on {args.target}", expand=False))
            if args.arch:
                wdsenum.arch_unattend(args.target)
            if args.id:
                wdsenum.device_id_unattended(args.target, args.id)
        else:
            console.print("You must specify either --arch or/and --id <Device ID>")


if __name__ == "__main__":
    main()
