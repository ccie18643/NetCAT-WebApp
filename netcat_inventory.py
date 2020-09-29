#!/usr/bin/env python3

"""

NetCAT config backup, deployment and monitoring system version 5.5 - 2020, Sebastian Majewski

netcat_inventory.py - device inventory web front end

"""

import os
import sys
import time
import socket
import datetime

from typing import List, Dict, Any, Optional

import flask

import netcat

if netcat.DB_TYPE == "MongoDB":
    import netcat_mongodb as db

if netcat.DB_TYPE == "DynamoDB":
    import netcat_dynamodb as db


MAX_WORKERS = netcat.MAX_WORKERS


if __name__ == "__main__":
    app = application = flask.Flask(__name__)


def get_device_data_list(device_name_list: List[str]) -> List[Dict[str, Any]]:
    """ Prepare list of device data documents to be used to create inventory """

    device_data_list = db.get_device_data_list__b(device_name_list, ["show version", "show system info", "show sys version", "show sys hardware"])

    # Create mock entries for devices that exist in snapshot status but were never pooled successfuly
    for device_name in set(device_name_list) - set(_.get("device_name") for _ in device_data_list):
        device_data_list.append({"device_name": device_name})

    return device_data_list


@netcat.exception_handler
@db.exception_handler
def create_inventory_list(device_name_list: List[str]) -> List[Dict[str, Any]]:
    """ Create inventory list """

    # Time process execution
    start_time = time.monotonic()

    # Setup logger to show process name
    if os.getpid() != netcat.MAIN_PROCESS_PID:
        netcat.bind_logger("SUB_PROC")

    inventory_list = []

    for device_data in get_device_data_list(device_name_list):

        if device_data.get("device_type") == "cisco_switch":
            command_output = netcat.get_command_output(device_data, "show version")
            model_numbers = netcat.find_regex_ml(command_output, r"^Model number\s+: (\S+)$", hint="el n", optional=False)
            serial_numbers = netcat.find_regex_ml(command_output, r"^System serial number\s+: (\S+)$", hint="m s", optional=False)
            software_versions = netcat.find_regex_ml(command_output, r"^\*?\s+\d+\s+\d+\s+\S+\s+(\S+) .*$", hint="  W", optional=False)

        elif device_data.get("device_type") == "cisco_router":
            command_output = netcat.get_command_output(device_data, "show version")
            model_numbers = netcat.find_regex_ml(command_output, r"^[Cc]isco (\S+) .+ bytes of memory.$", hint="s of m", optional=False)
            serial_numbers = netcat.find_regex_ml(command_output, r"^Processor board ID (\S+)$", hint="d I", optional=False)
            software_versions = netcat.find_regex_ml(command_output, r"^Cisco IOS Software,? .+ Version ([^\s,]+), .+$", hint="o I", optional=False)

        elif device_data.get("device_type") == "cisco_nexus":
            command_output = netcat.get_command_output(device_data, "show version")
            model_numbers = netcat.find_regex_ml(command_output, r"^\s+cisco Nexus[^ ]* (\S+) .+$", hint="has", optional=False)
            serial_numbers = netcat.find_regex_ml(command_output, r"^\s+Processor Board ID (\S+)$", hint=" Pr", optional=False)
            software_versions = netcat.find_regex_ml(command_output, r"^\s+(?:system|NXOS):\s+version (\S+)$", hint="ver", optional=False)

        elif device_data.get("device_type") == "cisco_asa":
            command_output = netcat.get_command_output(device_data, "show version")
            model_numbers = netcat.find_regex_ml(command_output, r"^Hardware:\s+([^ ^,]+),.+$", hint="Har", optional=False)
            serial_numbers = netcat.find_regex_ml(command_output, r"^Serial Number: (\S+)$", hint="Ser", optional=False)
            software_versions = netcat.find_regex_ml(command_output, r"^Cisco .+ Software Version (\S+) .*$", hint="e S", optional=False)

        elif device_data.get("device_type") == "cisco_asa_mc":
            command_output = netcat.get_command_output(device_data, "show version")
            model_numbers = netcat.find_regex_ml(command_output, r"^Hardware:\s+([^ ^,]+),.+$", hint="Har", optional=False)
            serial_numbers = netcat.find_regex_ml(command_output, r"^Serial Number: (\S+)$", hint="Ser", optional=False)
            software_versions = netcat.find_regex_ml(command_output, r"^Cisco .+ Software Version (\S+) .*$", hint="e S", optional=False)

        elif device_data.get("device_type") == "paloalto":
            command_output = netcat.get_command_output(device_data, "show system info")
            model_numbers = netcat.find_regex_ml(command_output, r"^model: (\S+)$", hint="el:", optional=False)
            serial_numbers = netcat.find_regex_ml(command_output, r"^serial: (\S+)$", hint="ser", optional=False)
            software_versions = netcat.find_regex_ml(command_output, r"^sw-version: (\S+)$", hint="sw-", optional=False)

        elif device_data.get("device_type") == "f5":
            command_output = netcat.get_command_output(device_data, "show sys hardware")
            model_numbers = netcat.find_regex_ml(command_output, r"^  Name\s+(BIG-IP \S+).*$", hint="BIG", optional=False)
            serial_numbers = netcat.find_regex_ml(command_output, r"^\s+Host Board Serial\s+(\S+)$", hint=" Ho", optional=False)

            # Fix for vf2lb[12]mgmt that dont show serial numbers, can be removed after VF2 decom
            if serial_numbers == []:
                serial_numbers = ["UNKNOWN"]

            command_output = netcat.get_command_output(device_data, "show sys version")
            software_versions = netcat.find_regex_ml(command_output, r"^\s+Version\s+(\S+)$", hint="  V", optional=False)

        else:
            inventory_list.append({"device_name": device_data.get("device_name")})
            continue

        from uuid import uuid1
        inventory_list.append(
            {
                "uuid" : uuid1(),
                "snapshot_timestamp": device_data.get("snapshot_timestamp"),
                "device_name": device_data.get("device_name"),
                "device_type": device_data.get("device_type"),
                "chasis": [{"model": _, "serial": __, "software": ___} for _, __, ___ in zip(model_numbers, serial_numbers, software_versions)],
            }
        )

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.debug(f"Inventory data created for {len(device_name_list)} devices in {end_time - start_time:.2f}s")

    return inventory_list


@app.before_first_request
def _before_first_request() -> None:
    """ Initialize logger """

    netcat.LOGGER or netcat.setup_logger()  # type: ignore


@app.route("/inventory")
@netcat.exception_handler
@db.exception_handler_http
def _display_device_inventory_web_page() -> str:
    """ Display device inventory on the web page """

    # Time process execution
    start_time = time.monotonic()

    netcat.LOGGER.debug("Creating device inventory list")

    # Create list of all devices for latest command snapshot
    device_name_list = list(next(iter(db.get_command_status_list(search_depth=1, field_list=["device_info_dict"])), {}).get("device_info_dict", {}))  # type: ignore

    # Randomize list so we have even spread of device types per batch
    from random import shuffle
    shuffle(device_name_list)

    # Start child processes to perform search operation for each batch
    inventory_list = sorted(netcat.execute_data_processing_function(
            netcat.split_list(device_name_list, MAX_WORKERS), create_inventory_list), key=lambda _: _.get("device_name"))

    # Time process execution
    end_time = time.monotonic()

    if netcat.SINGLE_PROCESS_MODE:
        generated_info = (
                f"Witchcraft performed by {socket.gethostname()} on {datetime.datetime.now().strftime('%Y-%m-%d at %H:%M:%S EDT')} "
                + f"in {end_time - start_time:.2f}s by casting single spell for {len(device_name_list)} "
                + f"devices. NetCAT {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski"
        )
    else:
        generated_info = (
                f"Witchcraft performed by {socket.gethostname()} on {datetime.datetime.now().strftime('%Y-%m-%d at %H:%M:%S EDT')} "
                + f"in {end_time - start_time:.2f}s by casting {MAX_WORKERS} concurrent spells for {len(device_name_list)} "
                + f"devices. NetCAT {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski"
        )

    netcat.LOGGER.info(f"Created device inventory list for {len(inventory_list)} devices in {end_time - start_time :.2f}s")

    return flask.render_template("inventory_results.html", inventory_list=inventory_list, generated_info=generated_info)


def parse_arguments(args: Optional[List[Any]] = None) -> Any:
    """ Parse comand line arguments """

    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("-D", "--debug", action="store_true", help="enable debug logs")
    parser.add_argument("-S", "--single-process", action="store_true", help="enable single procss operation for debuging purposes")
    parser.add_argument("-p", "--http-port", default=8000, type=int, action="store", help="TCP port for Flask web service to run on")

    return parser.parse_args(args)


def main() -> int:
    """ Run app in FLask HTTP server if executed directly from command line """

    arguments = parse_arguments()
    netcat.SINGLE_PROCESS_MODE = arguments.single_process

    netcat.setup_logger(debug=arguments.debug)

    arguments.debug and netcat.LOGGER.opt(ansi=True).info("<magenta>Debug mode enabled</magenta>")
    arguments.single_process and netcat.LOGGER.opt(ansi=True).info("<magenta>Single process mode enabled</magenta>")

    print(f"\nNetCAT Network Inventory, ver {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski\n")

    try:
        app.run(host="0.0.0.0", port=arguments.http_port)

    except PermissionError:
        print(f"\nERROR: Unable to start Flask Web Server on port {arguments.http_port}/TCP, port not permited...\n")
        return 1

    except OSError:
        print(f"\nERROR: Unable to start Flask Web Server on port {arguments.http_port}/TCP, port already in use...\n")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
