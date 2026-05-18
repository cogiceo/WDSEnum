import ipaddress
from pathlib import Path

from rich.console import Console

console = Console()


def is_ip(s):
    """
    Test if a string is an IP address
    """

    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def transform_guid(guid):
    """
    Tranform the GUID with dashes to the format required by WDSC
    """

    guid = guid.strip("{").strip("}")
    parts = guid.split("-")

    def reverse_bytes(hex_str):
        return "".join([hex_str[i : i + 2] for i in range(0, len(hex_str), 2)][::-1])

    p1 = reverse_bytes(parts[0])
    p2 = reverse_bytes(parts[1])
    p3 = reverse_bytes(parts[2])

    result = p1 + p2 + p3 + parts[3] + parts[4]

    return result.lower()


def save_file(msg, folder, server, file_name, content, yes=False):
    """
    Save a file to an output folder
    """

    file_name = file_name.replace(".", "_") + ".xml"
    folder_path = Path(folder) / server
    file_path = folder_path / file_name
    relative_path = Path(server) / file_name

    if not yes:
        if file_path.exists():
            # Prompt if the user wants to overwrite an unattend file
            console.print(f"{msg} : Overwrite '{relative_path}' ? \[y/N] ", end="", highlight=False)
            resp = console.input()
            if resp.lower() in ["", "n"]:
                return
        else:
            # Prompt if the user wants to save the unattend file
            console.print(f"{msg} : Download '{relative_path}' ? \[Y/n] ", end="", highlight=False)
            resp = console.input()
            if resp.lower() == "n":
                return

    # Write the unattend file
    folder_path.mkdir(parents=True, exist_ok=True)
    with open(file_path, "wb") as f:
        if isinstance(content, str):
            content = content.encode()
        f.write(content)
    return file_name
