#!/usr/bin/env python3

"""

NetCAT config backup, deployment and monitoring system version 5.5 - 2020, Sebastian Majewski

netcat_maclookup.py - mac address to switch port lookup web frontend

"""

import re
import sys
import time
import socket
import random
import string
import datetime
import argparse

from typing import List, Dict, Any, Optional, Tuple, Union

import flask
import wtforms  # type: ignore
import flask_wtf  # type: ignore

import netcat

if netcat.DB_TYPE == "MongoDB":
    import netcat_mongodb as db

if netcat.DB_TYPE == "DynamoDB":
    import netcat_dynamodb as db


MAX_WORKERS = netcat.MAX_WORKERS


if __name__ == "__main__":
    app = application = flask.Flask(__name__)

app.config["SECRET_KEY"] = ''.join(random.choice(string.printable) for _ in range(32))


def find_mac_address_in_device_data(device_data: Dict[str, Any], mac_address: str, physical_ports_only: bool) -> List[Dict[str, Any]]:
    """ Find vlans and ports in switch mac table for spcified mac address """

    findings = netcat.find_regex_ml(netcat.get_command_output(device_data, "show mac address-table"),
            rf"^\*?\s+(\d+)\s+{mac_address}\s+\S+\s+(?:\d+\s+\S+\s+\S+\s+)?(\S+) ?$", hint=mac_address)

    return [
        {
            "mac_address": mac_address,
            "device_name": device_data.get("device_name"),
            "vlan": _,
            "port": __,
            "snapshot_timestamp": device_data.get("snapshot_timestamp"),
        }
        for _, __ in findings if re.search("Gi|Eth", __) or not physical_ports_only
    ]


@netcat.exception_handler
@db.exception_handler
def find_mac_address_in_snapshot(timestamp: int, mac_address: str, physical_ports_only: bool) -> List[Dict[str, str]]:
    """ Execute 'find_ip_address_in_device_data()' function on all devices info files with given timestamp """

    # Time process execution
    start_time = time.monotonic()

    netcat.bind_logger("SUB_PROC")

    device_data_list = db.get_device_data_list__a(timestamp, ["cisco_switch", "cisco_nexus"], command_list=["show mac address-table"])

    findings = [_ for __ in device_data_list for _ in find_mac_address_in_device_data(__, mac_address, physical_ports_only)]

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.debug(f"Search for '{mac_address}' performed on {len(device_data_list)} devices in '{timestamp}' snapshot in {end_time - start_time:.2f}s")

    return findings


@app.before_first_request
def _before_first_request() -> None:
    """ Initialize logger """

    netcat.LOGGER or netcat.setup_logger(process_name_length=17)  # type: ignore


@app.route("/maclookup", methods=["GET", "POST"])
@netcat.exception_handler
@db.exception_handler_http
def _display_maclookup_findings_by_input_form() -> str:
    """ Get search paramters from user and execute search """

    class _(flask_wtf.FlaskForm):
        mac_address = wtforms.StringField()
        search_depth = wtforms.RadioField("Label", choices=[(netcat.POLL_FREQUENCY * 1, "1 hour"), (netcat.POLL_FREQUENCY * 8, "8 hours"),
                (netcat.POLL_FREQUENCY * 24, "24 hours"), (netcat.POLL_FREQUENCY * 24 * 7, "7 days")], default=netcat.POLL_FREQUENCY * 1, coerce=int)
        physical_ports_only = wtforms.BooleanField("Physical ports only")
        submit = wtforms.SubmitField("Start search")

    form = _()

    if not (form.validate_on_submit() and netcat.validate_mac_address(form.mac_address.data.strip())):
        return flask.render_template("maclookup_input.html", form=form)

    return lookup_mac_address(netcat.convert_mac_to_cisco_format(form.mac_address.data), form.search_depth.data, form.physical_ports_only.data)


@app.route("/maclookup/<mac_address>")
@app.route("/maclookup/<mac_address>/<search_depth>")
@netcat.exception_handler
@db.exception_handler_http
def _display_maclookup_findings_by_url(mac_address: str, search_depth: str = str(netcat.POLL_FREQUENCY)) -> Union[str, Tuple[str, int]]:
    """ Get mac address by url and execute search """

    if not netcat.validate_mac_address(mac_address):
        return netcat.http_error(f"Incorrect MAC address format: {mac_address}")

    if not netcat.validate_search_depth(search_depth):
        return netcat.http_error(f"Incorrect search depth format: {search_depth}")

    return lookup_mac_address(netcat.convert_mac_to_cisco_format(mac_address), int(search_depth), True)


def lookup_mac_address(mac_address: str, search_depth: int, physical_ports_only: bool) -> str:
    """ Main search function """

    # Time process execution
    start_time = time.monotonic()

    timestamp_list = [_.get("snapshot_timestamp") for _ in db.get_command_status_list(search_depth) if type(_) is dict]

    netcat.LOGGER.debug(f"Starting search for '{mac_address}' using {len(timestamp_list)} search processes")

    # Start child processes to perform search operation
    findings = sorted(netcat.execute_data_processing_function(timestamp_list, find_mac_address_in_snapshot, mac_address, physical_ports_only,
            max_workers=MAX_WORKERS), key=lambda _: _.get("snapshot_timestamp"), reverse=True)

    # Add UUIDs to be used as HTML IDs for JavaScript
    from uuid import uuid1
    for finding in findings:
        finding["uuid"] = uuid1()

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.info(f"Finished search for '{mac_address}' in {end_time - start_time:.2f}s, number of findings: {len(findings)}")

    if netcat.SINGLE_PROCESS_MODE:
        generated_info = (
            f"Witchcraft performed by {socket.gethostname()} on {datetime.datetime.now().strftime('%Y-%m-%d at %H:%M:%S EDT')} "
            + f"in {end_time - start_time:.2f}s by casting single spell. "
            + f"NetCAT {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski"
        )
    else:
        generated_info = (
            f"Witchcraft performed by {socket.gethostname()} on {datetime.datetime.now().strftime('%Y-%m-%d at %H:%M:%S EDT')} "
            + f"in {end_time - start_time:.2f}s by casting {MAX_WORKERS} concurrent spells. "
            + f"NetCAT {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski"
        )

    return flask.render_template(
        "maclookup_results.html",
        mac_address=netcat.standardize_mac_address(mac_address),
        findings=findings,
        snapshot_number=len(timestamp_list),
        generated_info=generated_info,
    )


def parse_arguments(args: Optional[List[Any]] = None) -> argparse.Namespace:
    """ Parse comand line arguments """

    parser = argparse.ArgumentParser()
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

    print("\nNetCAT Network MAC Address to Switch / Port Lookup, ver {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski\n")

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
