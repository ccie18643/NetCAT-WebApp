#!/usr/bin/env python3

"""

NetCAT config backup, deployment and monitoring system version 5.5 - 2020, Sebastian Majewski

netcat.py (App version) - module containing global variables, exceptions and shared functions

"""

import re
import sys
import time

from typing import List, Dict, Tuple, Any, Callable, Optional, Union

import loguru  # type: ignore

from os import getpid
MAIN_PROCESS_PID = getpid()

from multiprocessing import cpu_count
MAX_WORKERS = 4  # cpu_count()

POLL_FREQUENCY:int = 12

DEBUG: bool = False
SINGLE_PROCESS_MODE: bool = False
LOGGER: Any = None

VERSION: str = "5.5"
YEAR: str = "2020"

DB_TYPE: str = "MongoDB"
#DB_TYPE: str = "DynamoDB"

DBT_INFO = "netcat_info"
DBT_BACKUP = "netcat_backup"
DBT_STATUS = "netcat_status"


class CustomException(Exception):
    """ Custom exception class used to raise NetCAT specific exception whenever unrecoverable error occurs """


def split_list(input_list: list, chunk_number: int) -> List[list]:
    """ Split input list into list containing number of sublists """

    if chunk_len := int(len(input_list) / chunk_number) + bool(len(input_list) % chunk_number):
        return [input_list[_:_ + chunk_len] for _ in range(0, len(input_list), chunk_len)]

    else:
        return []


def encode_command(command: str) -> str:
    """ Encode command name to ensure it doesnt contain any weird characters """

    from binascii import hexlify

    return hexlify(command.encode("utf-8")).decode("utf-8").translate(str.maketrans("1234567890", "ghijklmnop"))


def decode_command(command: str) -> str:
    """ Decode command name previously encoded by 'encode_command_name' function """

    from binascii import unhexlify

    return str(unhexlify(command.translate(str.maketrans("ghijklmnop", "1234567890"))), "utf-8")


def decompress_command_output(command_output: str) -> str:
    """ Decompress command output """

    from bz2 import decompress
    from base64 import b85decode

    return str(decompress(b85decode(command_output)), "utf-8")


def compress_device_data(device_data: Dict[str, Any]) -> Dict[str, Any]:
    """ Compress command outputs in device data structure """

    from bz2 import compress
    from base64 import b85encode

    if not device_data:
        return {}

    compressed_device_data: Dict[str, Any] = {
        "snapshot_timestamp": device_data.get("snapshot_timestamp"),
        "device_name": device_data.get("device_name"),
        "device_type": device_data.get("device_type"),
        "output_formats": {},
    }

    for format_name, format_data in device_data.get("output_formats", {}).items():
        compressed_device_data["output_formats"][format_name] = {}
        for command_name, command_data in format_data.items():
            compressed_device_data["output_formats"][format_name][encode_command(command_name)]  = str(b85encode(compress(bytes(command_data, "utf-8"))), "utf-8")

    return compressed_device_data


def decompress_device_data(compressed_device_data: Dict[str, Any]) -> Dict[str, Any]:
    """ Decompress command outputs in device data structure """

    from bz2 import decompress
    from base64 import b85decode

    if not compressed_device_data:
        return {}

    device_data: Dict[str, Any] = {
        "snapshot_timestamp": compressed_device_data.get("snapshot_timestamp"),
        "device_name":  compressed_device_data.get("device_name"),
        "device_type": compressed_device_data.get("device_type"),
        "output_formats": {},
    }

    for format_name, format_data in compressed_device_data.get("output_formats",{}).items():
        device_data["output_formats"][format_name] = {}
        for command_name, command_data in format_data.items():
            device_data["output_formats"][format_name][decode_command(command_name)]  = str(decompress(b85decode(command_data)), "utf-8")

    return device_data


def http_error(message: str = "", code=400) -> Tuple[str, int]:
    """ Returns html formated errror message """

    if code == 400:
        return f"<html>\n<title>400 Bad request</title>\n<h2>400 Bad request</h2>\n<p>{message}</p>\n</html>\n", 400

    if code == 500:
        return f"<html>\n<title>500 Server error</title>\n<h2>5.1 Server error</h2>\n<p>{message}</p>\n</html>\n", 500

    return f"<html>\n<title>{code} Unknown error</title>\n<h2>{code} Unknown error</h2>\n<p>{message}</p>\n</html>\n", code


def fn() -> str:
    """ Returns name of current function. Goes deeper if current fuction name is _, __ or ___ """

    for depth in range(1, 4):
        name = sys._getframe(depth).f_code.co_name
        if name not in {"_", "__", "___"}:
            return name + "()"

    return "unknown()"


def standardize_mac_address(mac_address: str) -> str:
    """ Converting couple different mac address formats to standard one """

    # Cisco's DHCP ID thing
    if re.search(r"^(01[0-9A-Fa-f]{2}\.)([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{2}$", mac_address):
        mac_address = mac_address[2:]
        mac_address = re.sub(r"\.", r"", mac_address.upper().strip())
        mac_address = ":".join(mac_address[_ : _ + 2] for _ in range(0, len(mac_address), 2))

    # Couple various formats
    elif re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac_address.strip()) or re.search(
        r"^([0-9A-Fa-f]{4}[.]){2}([0-9A-Fa-f]{4})$", mac_address.strip()
    ):

        mac_address = re.sub(r":|-|\.", "", mac_address.upper().strip())
        mac_address = ":".join(mac_address[_ : _ + 2] for _ in range(0, len(mac_address), 2))

    else:
        mac_address = "UNKNOWN"

    return mac_address


def setup_logger(debug: bool = False, process_name_length: int = 9, stdout: bool = True) -> None:
    """ Setting up logger """

    log_level = "DEBUG" if debug else "INFO"

    loguru.logger.remove(0)

    if stdout:
        loguru.logger.add(sys.stdout, colorize=True, level=log_level, format=f"<green>{{time:YYYY-MM-DD HH:mm:ss}}</green> <level>| {{level:7}} "
                + f"|</level> <level>{{extra[process_name]:{process_name_length}}} | {{message}}</level>")

    bind_logger("MAIN_PROG")


def bind_logger(process_name: str) -> None:
    """ Bind specific process name to logger """

    global LOGGER

    LOGGER = loguru.logger.bind(process_name=process_name)


def print_device_data(device_data: Dict[str, Any], no_indent: bool = False) -> str:
    """ Print device data json format in human readable form """

    from datetime import datetime

    output = []

    if no_indent:
        indent = ""
    else:
        indent = "  "

    output.append("SECTION: INFO")
    output.append("")
    output.append(f"{indent}NAME: {device_data.get('device_name')}")
    output.append(f"{indent}TYPE: {device_data.get('device_type', '').replace('_', ' ') or None}")
    output.append(f"{indent}TIMESTAMP: {device_data.get('snapshot_timestamp')} [{datetime.utcfromtimestamp(int(device_data.get('snapshot_timestamp')))} UTC]")  # type: ignore
    output.append("")
    output.append("")
    output.append("SECTION: FORMATS")
    output.append("")

    for format in device_data.get("output_formats", {}):
        output.append(f"{indent}FORMAT: {format.upper().replace('_', ' ')}")
        output.append("")

        for command in device_data.get("output_formats", {}).get(format):
            output.append(f"{indent}{indent}COMMAND: '{command}'")
            output.append("")

            for command_line in device_data.get("output_formats", {}).get(format, {}).get(command, "").split("\n"):
                output.append(f"{indent}{indent}{indent}{command_line}")

            output.append("")

        output.append("")

    return "\n".join(output)


def get_command_output(device_data: Dict[str, Any], command: str) -> str:
    """ Function returns command output for given device_data / command """

    if command_output := device_data.get("output_formats", {}).get("info", {}).get(command):
        return command_output

    return ""


def find_regex_sl(*args: Any, **kwargs: Any) -> str:
    """ Wrapper for find_regex_ml() function to easily handle cases when we only expect to pull the value(s) from single line of text """

    return (find_regex_ml(*args, **kwargs) or [""])[0]


def find_regex_ml(text: str, regex: str, /, *, hint: Optional[str] = None, optional: bool = True) -> List[str]:
    """ Find single or multiple values per each of the lines of text. Uses regex grouping mechanism to mark interesting values. """

    if hint:
        if optional and hint not in text:
            return []

        if not (text_lines := [_ for _ in text.split("\n") if hint in _]):
            return []

    else:
        text_lines = text.split("\n")

    cregex = re.compile(regex)

    return [_.groups() if len(_.groups()) > 1 else _.group(1) for __ in text_lines if (_ := cregex.search(__.rstrip("\r")))]


def validate_ip_address(ip_address: str) -> bool:
    """ Validate IP address """

    from socket import inet_aton

    if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
        try:
            inet_aton(ip_address)
        except OSError:
            return False
        return True
    return False


def validate_mac_address(mac_address: str) -> bool:
    """ Validate if provided MAC address has valid format """

    if not (
        re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac_address.strip())
        or re.search(r"^([0-9A-Fa-f]{4}[.]){2}([0-9A-Fa-f]{4})$", mac_address.strip())
        or re.search(r"^([0-9A-Fa-f]{12})$", mac_address.strip())
    ):
        return False

    return True


def validate_search_depth(input_string: str) -> bool:
    """ Validate search depth string to prevent any malicious regex action """

    if not re.match(r"^[0-9]{1,3}$", input_string):
        return False

    return True


def validate_http_input(input_string: str) -> bool:
    """ Validate input string to prevent any malicious regex action """

    if not re.match(r"^[a-zA-Z0-9_\-]{1,25}$", input_string):
        return False

    return True


def validate_timestamp(input_string: str) -> bool:
    """ Validate timestamp string to prevent any malicious regex action """

    if not re.match(r"^\d{10}$", input_string):
        return False

    return True


def convert_mac_to_cisco_format(mac_address: str) -> str:
    """ Convert couple different MAC address formats into Cisco's 'aabb.ccdd.eeff' format """

    mac_address = re.sub(r":|-|\.| ", "", mac_address.lower().strip())
    mac_address = ".".join(mac_address[_ : _ + 4] for _ in range(0, len(mac_address), 4))

    return mac_address


def exception_handler(function: Callable[..., Any]) -> Any:
    """ Decorator to log exceptions and exit process or forward them for further processing """

    from functools import wraps

    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)

        except CustomException as exception:
            LOGGER.error(f"{exception}")
            sys.exit()

        except SystemExit:
            raise

        except:
            LOGGER.error(f"Unknown exception '{sys.exc_info()}'")
            raise

    return wrapper


def execute_data_processing_function(data_list: List[Any], data_processing_function: Callable[..., List[Any]],
        *args: Any, max_workers: int = MAX_WORKERS, **kwargs: Any) -> List[Any]:
    """ Execute generic data processing function in single or multiprocess manner and return merged list of results """

    from concurrent.futures import ProcessPoolExecutor

    if not data_list:
        return []

    if SINGLE_PROCESS_MODE:
        results = [data_processing_function(_, *args, **kwargs) for _ in data_list]

    else:
        with ProcessPoolExecutor(max_workers=min(max_workers, len(data_list))) as executor:
            process_pool = [executor.submit(data_processing_function, _, *args, **kwargs) for _ in data_list]

        results = [_.result() for _ in process_pool if not _.exception() and _.result()]

    return [_ for __ in results for _ in __]
