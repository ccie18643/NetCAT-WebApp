#!/usr/bin/env python3

"""

NetCAT config backup, deployment and monitoring system version 5.5 - 2020, Sebastian Majewski

netcat_iplookup.py - ip address to mac address lookup web front end

"""

import sys
import time
import random
import string
import socket
import datetime
import argparse

from typing import List, Dict, Any, Optional, Tuple, Union, Set

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


def find_ip_address_in_device_data(device_data: Dict[str, Any], ip_address: str, use_arp: bool, use_dhcp: bool, use_dsnp: bool) -> List[Dict[str, Any]]:
    """ Find data line containing ip address in device data structure """

    results: List[Tuple[Any, str, str]] = []

    if device_data.get("device_type") == "cisco_switch":
        if use_dsnp:
            results += [(_, "DSNP", f"[ l2_int: {___} ], [ vlan: {__} ]") for _, __, ___ in
                    netcat.find_regex_ml(netcat.get_command_output(device_data, "show ip dhcp snooping binding"),
                    rf"^(\S+)\s+{ip_address}\s+\d+\s+\S+\s+(\d+)\s+(\S+)\s*$", hint=ip_address)]

    elif device_data.get("device_type") == "cisco_router":

        if use_arp:
            results += [(_, "ARP", f"[ l3_int: {__} ]") for _, __ in
                    netcat.find_regex_ml(netcat.get_command_output(device_data, "show ip arp"),
                    rf"^Internet\s+{ip_address}\s+\S+\s+(\S+)\s+ARPA\s+(\S+)\s*$", hint=ip_address)]

        if use_dhcp:
            results += [(_, "DHCP", f"") for _ in
                    netcat.find_regex_ml(netcat.get_command_output(device_data, "show ip dhcp binding"),
                    rf"^{ip_address}\s+(\S+)\s.+$", hint=ip_address)]

    elif device_data.get("device_type") == "paloalto":

        if use_arp:
            results += [(__, "ARP", f"[ l3_int: {_} ]") for _, __ in
                    netcat.find_regex_ml(netcat.get_command_output(device_data, "show arp all"),
                    rf"^(\S+)\s+{ip_address}\s+(\S+)\s+\S+\s.*$", hint=ip_address)]

        if use_dhcp:
            results += [(_, "DHCP", f"[ name: {__} ]") for _, __ in
                    netcat.find_regex_ml(netcat.get_command_output(device_data, "show dhcp server lease interface all"),
                    rf"^{ip_address}\s+(\S+)\s+(\S+) .*$", hint=ip_address)]

    else:
        netcat.LOGGER.warning(f"{netcat.fn()}: Unknown device data type value '{device_data.get('device_type')}'")
        return []

    return [
        {
            "snapshot_timestamp": device_data.get("snapshot_timestamp"),
            "mac_address": netcat.standardize_mac_address(_),
            "device_name": device_data.get("device_name"),
            "source": __,
            "other_info": ___,
        }
        for _, __, ___ in results
    ]


@netcat.exception_handler
@db.exception_handler
def find_ip_address_in_snapshot(timestamp: int, ip_address: str, use_arp: bool, use_dhcp: bool, use_dsnp: bool) -> List[Dict[str, str]]:
    """ Execute 'find_ip_address_in_device_data()' function on all devices info files with given timestamp """

    # Time process execution
    start_time = time.monotonic()

    netcat.bind_logger("SUB_PROC")

    device_type_list: Set[str] = set()
    command_list: Set[str] = set()

    if use_arp:
        device_type_list |= {"cisco_router", "paloalto"}
        command_list |= {"show ip arp", "show arp all"}

    if use_dhcp:
        device_type_list |= {"cisco_router", "paloalto"}
        command_list |= {"show ip dhcp binding", "show dhcp server lease interface all"}

    if use_dsnp:
        device_type_list |= {"cisco_switch"}
        command_list |= {"show ip dhcp snooping binding"}

    device_data_list = db.get_device_data_list__a(timestamp, list(device_type_list), list(command_list))

    findings = [_ for __ in device_data_list for _ in find_ip_address_in_device_data(__, ip_address, use_arp, use_dhcp, use_dsnp)]

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.debug(f"Search for '{ip_address}' performed on {len(device_data_list)} devices in '{timestamp}' snapshot in {end_time - start_time:.2f}s")

    return findings


@app.before_first_request
def _before_first_request() -> None:
    """ Initialize logger """

    netcat.LOGGER or netcat.setup_logger()  # type: ignore


@app.route("/iplookup", methods=["GET", "POST"])
@netcat.exception_handler
@db.exception_handler_http
def _display_iplookup_findings_by_input_form() -> str:
    """ Get search paramters from user and execute search """

    class _(flask_wtf.FlaskForm):
        ip_address = wtforms.StringField()
        search_depth = wtforms.RadioField("Label", choices=[(netcat.POLL_FREQUENCY * 1, "1 hour"), (netcat.POLL_FREQUENCY * 8, "8 hours"),
                (netcat.POLL_FREQUENCY * 24, "24 hours"), (netcat.POLL_FREQUENCY * 24 * 7, "7 days")], default=netcat.POLL_FREQUENCY * 1, coerce=int)
        use_arp = wtforms.BooleanField("ARP")
        use_dhcp = wtforms.BooleanField("DHCP")
        use_dsnp = wtforms.BooleanField("DHCP Snooping")
        submit = wtforms.SubmitField("Start search")

    form = _()

    if not (form.validate_on_submit() and netcat.validate_ip_address(form.ip_address.data.strip())):
        return flask.render_template("iplookup_input.html", form=form)

    return lookup_ip_address(form.ip_address.data, form.search_depth.data, form.use_arp.data, form.use_dhcp.data, form.use_dsnp.data)


@app.route("/iplookup/<ip_address>")
@app.route("/iplookup/<ip_address>/<search_depth>")
@netcat.exception_handler
@db.exception_handler_http
def _display_iplookup_findings_by_url(ip_address: str, search_depth: str = str(netcat.POLL_FREQUENCY)) -> Union[str, Tuple[str, int]]:
    """ Get ip address by url and execute search """

    if not netcat.validate_ip_address(ip_address):
        return netcat.http_error(f"Incorect IP address format: {ip_address}")

    return lookup_ip_address(ip_address, int(search_depth))


def lookup_ip_address(ip_address: str, search_depth: int, use_arp: bool = True, use_dhcp: bool = True, use_dsnp: bool = True) -> str:
    """ Main search function """

    # Time process execution
    start_time = time.monotonic()

    # Create list of command snapshot timestamps up to given search depth
    timestamp_list = [_.get("snapshot_timestamp") for _ in db.get_command_status_list(search_depth) if type(_) is dict]

    netcat.LOGGER.debug(f"Starting search for '{ip_address}' using {len(timestamp_list)} search processes")

    # Start child processes to perform search operation
    findings = sorted(netcat.execute_data_processing_function(timestamp_list, find_ip_address_in_snapshot, ip_address, use_arp, use_dhcp, use_dsnp,
            max_workers=MAX_WORKERS), key=lambda _: _.get("snapshot_timestamp"), reverse=True)

    # Add UUIDs to be used as HTML IDs for JavaScript
    from uuid import uuid1
    for finding in findings:
        finding["uuid"] = uuid1()

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.info(f"Finished search for '{ip_address}' in {end_time - start_time:.2f}s, number of findings: {len(findings)}")

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
        "iplookup_results.html", ip_address=ip_address, findings=findings, snapshot_number=len(timestamp_list), search_depth=search_depth, generated_info=generated_info
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

    print(f"\nNetCAT IP to MAC Address Lookup, ver {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski\n")

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
