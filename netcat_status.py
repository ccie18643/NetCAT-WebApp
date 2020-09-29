#!/usr/bin/env python3

"""

NetCAT config backup, deployment and monitoring system version 5.5 - 2020, Sebastian Majewski

netcat_status.py - network status web front end

"""

import os
import re
import sys
import time
import uuid
import socket
import smtplib
import datetime
import argparse

from typing import List, Dict, Tuple, Any, Optional, Union

import flask
import jinja2

import netcat

if netcat.DB_TYPE == "MongoDB":
    import netcat_mongodb as db

if netcat.DB_TYPE == "DynamoDB":
    import netcat_dynamodb as db


MAX_WORKERS = netcat.MAX_WORKERS


if __name__ == "__main__":
    app = application = flask.Flask(__name__)


@netcat.exception_handler
def get_failed_device_data_list(device_list: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    """ Prepare list of device data documents to be used to create failed device data list """

    # Time process execution
    start_time = time.monotonic()

    # Setup logger to show process name
    if os.getpid() != netcat.MAIN_PROCESS_PID:
        netcat.bind_logger("SUB_PROC")

    # Pull list of latest device_data documents for devices in device_list
    device_data_list = db.get_device_data_list__b([_[0] for _ in device_list], command_list=None)

    # Create mock entries for devices that exist in command snapshot status but were never pooled successfuly
    for device_name in set([_[0] for _ in device_list]) - set(_.get("device_name") for _ in device_data_list):
        device_data_list.append({"device_name": device_name, "device_type": next(iter([_[1] for _ in device_list if _[0] == device_name]), None)})

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.debug(f"Created inaccessible device list for {len(device_list)} devices in {end_time - start_time:.2f}s")

    return device_data_list


def find_inaccessible_devices(latest_command_status: Dict[str, Any]) -> List[Dict[str, Any]]:
    """ Search for devices that have missing latest device_info structures """

    # Time process execution
    start_time = time.monotonic()

    # Create failed device name list from latest snapshot
    failed_device_list = [(_[0], _[1].get("device_type")) for _ in latest_command_status.get("device_info_dict", {}).items() if _[1].get("failed")]

    # Start child processes to perform search operation for each batch
    device_data_list = sorted(netcat.execute_data_processing_function(netcat.split_list(failed_device_list,
            MAX_WORKERS), get_failed_device_data_list), key=lambda _: _.get("device_name"))

    inaccessible_devices = sorted(device_data_list, key=lambda _: _.get("device_name"))

    # Add UUIDs to be used as HTML IDs for JavaScript
    for device in inaccessible_devices:
        device["uuid"] = uuid.uuid1()

    # Remove all the BS switches
    inaccessible_devices = [_ for _ in inaccessible_devices if not re.match(r"^\S+bs\d+$", _.get("device_name"))]

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.debug(f"Assembled inaccessible device list for {len(device_data_list)} devices in {end_time - start_time:.2f}s")

    return inaccessible_devices


def find_broken_bgp_sessions(latest_command_status: Dict[str, Any]) -> List[Dict[str, Any]]:
    """ Search for broken BGP sessions in list of device_data structures """

    # Time process execution
    start_time = time.monotonic()

    device_data_list = db.get_device_data_list__a(latest_command_status.get("snapshot_timestamp", ""), ["paloalto", "cisco_router"],
            command_list=["show ip bgp summary", "show routing protocol bgp summary", "show high-availability all"])

    # Filter out routers that dont run bgp
    device_data_list = [_ for _ in device_data_list if _.get("device_name")[-3:] not in {"ts1", "ts2"}]

    # Start child processes to perform search operation for each device
    broken_bgp_sessions = sorted(netcat.execute_data_processing_function(device_data_list,
            find_broken_bgp_sessions_per_device, max_workers=MAX_WORKERS), key=lambda _: _.get("device_name"))

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.debug(f"Assembled broken bgp session list for {len(broken_bgp_sessions)} sessions in {end_time - start_time:.2f}s")

    return broken_bgp_sessions


@netcat.exception_handler
def find_broken_bgp_sessions_per_device(device_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """ Search for broken BGP sessions on Cisco routers and Palo Alto firewalls """

    # Time process execution
    start_time = time.monotonic()

    # Setup logger to show process name
    if os.getpid() != netcat.MAIN_PROCESS_PID:
        netcat.bind_logger("SUB_PROC")

    broken_bgp_sessions = []

    if device_data.get("device_type") == "cisco_router":

        # Look for any broken BGP sessions
        for bgp_session_peer_ip, bgp_session_peer_asn in netcat.find_regex_ml(netcat.get_command_output(device_data, "show ip bgp summary"),
                r"^(\S+)\s+\d\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(?:Idle|Active)$"):

            broken_bgp_session = {
                "uuid": uuid.uuid1(),
                "device_name": device_data.get("device_name"),
                "device_type": device_data.get("device_type"),
                "peer_ip": bgp_session_peer_ip,
                "peer_asn": bgp_session_peer_asn,
            }

            # Search for latest device_data document that has broken BGP session in UP state and record its timestamp
            device_data_list = db.get_device_data_list__c(device_data.get("device_name", ""), command_list=["show ip bgp summary"])

            for device_data in device_data_list:
                if netcat.find_regex_ml(netcat.get_command_output(device_data, "show ip bgp summary"),
                            rf"(^{bgp_session_peer_ip}\s+\d\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+\d+$)", hint=bgp_session_peer_ip, optional=False):
                    broken_bgp_session["snapshot_timestamp"] = device_data.get("snapshot_timestamp")
                    break

            broken_bgp_sessions.append(broken_bgp_session)

    elif device_data.get("device_type") == "paloalto":

        # Skip device if its not in active ha state
        if netcat.find_regex_sl(netcat.get_command_output(device_data, "show high-availability all"),
                r"\s+State: (\S+) .*$") not in {"active", "active-primary", "active-secondary", ""}:
            return []

        # Look for any broken BGP sessions
        for bgp_session_peer_asn, bgp_session_peer_ip in netcat.find_regex_ml(
                netcat.get_command_output(device_data, "show routing protocol bgp summary"), r"^\s+peer \S+\s+ AS (\d+), (?:Connect|Active), IP (\S+)$"):

            broken_bgp_session = {
                "uuid": uuid.uuid1(),
                "device_name": device_data.get("device_name"),
                "device_type": device_data.get("device_type"),
                "peer_ip": bgp_session_peer_ip,
                "peer_asn": bgp_session_peer_asn,
            }

            # Search for latest device_data structure that has broken BGP session in UP state and record its timestamp
            device_data_list = db.get_device_data_list__c(device_data.get("device_name", ""),
                    command_list=["show routing protocol bgp summary", "show high-availability all"])

            for device_data in device_data_list:
                if netcat.find_regex_sl(netcat.get_command_output(device_data, "show routing protocol bgp summary"),
                        rf"(^\s+peer \S+\s+ AS \d+, Established, IP {bgp_session_peer_ip})$", hint=bgp_session_peer_ip, optional=False):
                    broken_bgp_session["snapshot_timestamp"] = device_data.get("snapshot_timestamp")
                    break

            broken_bgp_sessions.append(broken_bgp_session)

    else:
        netcat.LOGGER.warning(f"{netcat.fn()}: Unknown device data type value '{device_data.get('type')}'")

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.debug(f"Created broken bgp session list of {len(broken_bgp_sessions)} sessions in {end_time - start_time:.2f}s")

    return broken_bgp_sessions


def find_broken_links(latest_command_status: Dict[str, Any]) -> List[Dict[str, Any]]:
    """ Search for broken links in list of device_data structures """

    # Time process execution
    start_time = time.monotonic()

    device_data_list = db.get_device_data_list__a(latest_command_status.get("snapshot_timestamp", ""), ["paloalto", "cisco_router"],
            command_list=["show ip interface brief", "show interface all", "show high-availability all"])

    # Filter out routers that have single link
    device_data_list = [_ for _ in device_data_list if _.get("device_name")[-3:] not in {"ts1", "ts2"}]

    # Start child processes to perform search operation for each device
    broken_links = sorted(netcat.execute_data_processing_function(device_data_list,
            find_broken_links_per_device, max_workers=MAX_WORKERS), key=lambda _: _.get("device_name"))

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.debug(f"Assembled broken links list for {len(broken_links)} links in {end_time - start_time:.2f}s")

    return broken_links


@netcat.exception_handler
def find_broken_links_per_device(device_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """ Search for any link that is down (but not admin down) on Cisco routers and Palo Alto firewalls """

    # Time process execution
    start_time = time.monotonic()

    # Setup logger to show process name
    if os.getpid() != netcat.MAIN_PROCESS_PID:
        netcat.bind_logger("SUB_PROC")

    broken_links = []

    if device_data.get("device_type") == "cisco_router":

        # Look for any broken link
        for interface_name, interface_ip_address in netcat.find_regex_ml(netcat.get_command_output(device_data, "show ip interface brief"),
                rf"^([^\s]*(?:Ethernet|Tunnel)\S+)\s+(\S+)\s+\S+\s+\S+\s+(?:up|down)\s+down\s*$"):

            broken_link = {
                "uuid": uuid.uuid1(),
                "device_name": device_data.get("device_name"),
                "device_type": device_data.get("device_type"),
                "interface_name": interface_name,
                "interface_name_encoded": interface_name.replace("/", "_"),
                "interface_ip_address": interface_ip_address,
            }

            # Search for latest device_info structure that has broken link in UP state and record its timestamp
            device_data_list = db.get_device_data_list__c(device_data.get("device_name", ""), command_list=["show ip interface brief"])

            for device_data in device_data_list:
                regex_interface_name = interface_name.replace("/", "\\/").replace(".", "\.")
                if netcat.find_regex_sl(netcat.get_command_output(device_data, "show ip interface brief"),
                        rf"(^[^\s]*{regex_interface_name}\s+\S+\s+\S+\s+\S+\s+up\s+up\s*$)", hint=interface_name, optional=False):
                    broken_link["snapshot_timestamp"] = device_data.get("snapshot_timestamp")
                    break

            broken_links.append(broken_link)

    elif device_data.get("device_type") == "paloalto":

        # Skip device if its not in active ha state
        if netcat.find_regex_sl(netcat.get_command_output(device_data, "show high-availability all"),
                r"\s+State: (\S+) .*$") not in {"active", "active-primary", "active-secondary", ""}:
            return []

        # Look for any broken link
        for interface_name, interface_mac_address in netcat.find_regex_ml(netcat.get_command_output(device_data, "show interface all"),
                r"^((?:ethernet|ae)\S+)\s+\d+\s+ukn\/ukn\/down\S+\s+(\S+)\s*$"):

            broken_link = {
                "uuid": uuid.uuid1(),
                "device_name": device_data.get("device_name"),
                "device_type": device_data.get("device_type"),
                "interface_name": interface_name,
                "interface_name_encoded": interface_name.replace("/", "_"),
                "interface_ip_address": "N/A",
                "interface_mac_address": interface_mac_address,
            }

            # Search for latest device_info structure that has broken BGP session in UP state and record its timestamp
            device_data_list = db.get_device_data_list__c(device_data.get("device_name", ""), command_list=["show interface all"])

            for device_data in device_data_list:
                regex_interface_name = interface_name.replace("/", "\\/").replace(".", "\.")
                if netcat.find_regex_ml(netcat.get_command_output(device_data, "show interface all"),
                        rf"(^{regex_interface_name}\s+\S+\s+\S+\/up\s+\S+\s*$)", hint=interface_name, optional=False):
                    broken_link["snapshot_timestamp"] = device_data.get("snapshot_timestamp")
                    break

            broken_links.append(broken_link)

    else:
        netcat.LOGGER.warning(f"{netcat.fn()}: Unknown device data type value '{device_data.get('type')}'")

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.debug(f"Created broken links list of {len(broken_links)} links in {end_time - start_time:.2f}s")

    return broken_links


def get_dns_status() -> Dict[str, Any]:
    """ Gather latest status of DNS servers """

    # Time process execution
    start_time = time.monotonic()

    dns_status = db.get_dns_status()

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.debug(f"Assembled dns status for {len(dns_status.get('dns_data', []))} servers in {end_time - start_time:.2f}s")

    return dns_status


def create_network_status() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any], str]:
    """ Gather network status from various status checks """

    # Time process execution
    start_time = time.monotonic()

    netcat.LOGGER.debug("Creating network status")

    latest_command_status: Dict[str, Any] = next(iter(db.get_command_status_list(search_depth=1, field_list=["device_info_dict"])), {})
    
    if latest_command_status:
        inaccessible_devices = find_inaccessible_devices(latest_command_status)
        broken_bgp_sessions = find_broken_bgp_sessions(latest_command_status)
        broken_links = find_broken_links(latest_command_status)

    else:
        netcat.LOGGER.warning(f"{netcat.fn()}: Unable to pull latest command status document from database")
        latest_command_status = {}
        inaccessible_devices = broken_bgp_sessions = broken_links = []

    dns_status = get_dns_status()

    # Time process execution
    end_time = time.monotonic()

    if netcat.SINGLE_PROCESS_MODE:
        generated_info = (
            f"Witchcraft performed by {socket.gethostname()} on {datetime.datetime.now().strftime('%Y-%m-%d at %H:%M:%S EDT')} "
            + f"in {end_time - start_time:.2f}s by casting single spell for {len(latest_command_status.get('devices', {}))} "  # type: ignore
            + f"devices. NetCAT {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski"
        )
    else:
        generated_info = (
            f"Witchcraft performed by {socket.gethostname()} on {datetime.datetime.now().strftime('%Y-%m-%d at %H:%M:%S EDT')} "
            + f"in {end_time - start_time:.2f}s by casting {MAX_WORKERS} concurrent spells for "
            + f"{len(latest_command_status.get('devices', {}))} devices. NetCAT {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski"  # type: ignore
        )

        netcat.LOGGER.info(f"Created network status for {len(latest_command_status.get('devices', {}))} " +  # type: ignore
            f"devices in {end_time - start_time:.2f}s")

    return inaccessible_devices, broken_bgp_sessions, broken_links, dns_status, generated_info


@app.before_first_request
def _before_first_request() -> None:
    """ Initialize logger """

    netcat.LOGGER or netcat.setup_logger()  # type: ignore


def display_resource_availability_history(device_name: str, resource: str, resource_name: str,
        cisco_command: str, cisco_regex: str, pa_regex: str, pa_command: str) -> str:
    """ Display resource history for given device name and resource """

    # Time process execution
    start_time = time.monotonic()

    timestamp_list = [_.get("snapshot_timestamp") for _ in db.get_command_status_list() if type(_) is dict]

    device_data_list = db.get_device_data_list__c(device_name, [pa_command, cisco_command])

    availability_history = []

    for timestamp in timestamp_list:

        device_data: Optional[Dict[str, Any]] = next((_ for _ in device_data_list if _.get("snapshot_timestamp") == timestamp), None)

        if device_data is None:
            availability_history.append({"uuid": uuid.uuid1(), "snapshot_timestamp": timestamp})
            continue

        if device_data.get("device_type") == "cisco_router":
            if status := netcat.find_regex_sl(netcat.get_command_output(device_data, cisco_command), cisco_regex):
                availability_history.append({"uuid": uuid.uuid1(), "snapshot_timestamp": timestamp, "status": status})
                continue

        elif device_data.get("device_type") == "paloalto":
            if status := netcat.find_regex_sl(netcat.get_command_output(device_data, pa_command), pa_regex):
                availability_history.append({"uuid": uuid.uuid1(), "snapshot_timestamp": timestamp, "status": status})
                continue
    
        else:
            netcat.LOGGER.warning(f"{netcat.fn()}: Unknown device data type value '{device_data.get('type')}'")
            continue

        availability_history.append({"uuid": uuid.uuid1(), "snapshot_timestamp": timestamp, "status": "Not found"})

    # Time process execution
    end_time = time.monotonic()

    generated_info = (
        f"Witchcraft performed by {socket.gethostname()} on {datetime.datetime.now().strftime('%Y-%m-%d at %H:%M:%S EDT')} "
        + f"in {end_time - start_time:.2f}s by casting single spell for {len(timestamp_list)} "
        + f"snapshots. NetCAT {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski"
    )

    netcat.LOGGER.info(f"Created availability history for '{device_name} - {resource}' in {end_time - start_time:.2f}s")

    return flask.render_template("status_resource_availability_history.html", device_name=device_name, resource=resource, resource_name=resource_name,
            availability_history=availability_history, generated_info=generated_info)


@app.route("/status/bgp_availability_history/<device_name>/<peer_ip_address>")
@netcat.exception_handler
def _display_bgp_availability_history(device_name: str, peer_ip_address: str) -> Union[str, Tuple[str, int]]:
    """ Display bgp session history for given device name and peer ip address """

    if not netcat.validate_http_input(device_name):
        return netcat.http_error(f"Incorrect device name format: {device_name}")

    if not netcat.validate_ip_address(peer_ip_address):
        return netcat.http_error(f"Incorrect peer IP address format: {peer_ip_address}")

    return display_resource_availability_history(
        device_name=device_name,
        resource_name="BGP",
        resource=peer_ip_address,
        cisco_command="show ip bgp summary",
        cisco_regex=rf"^{peer_ip_address}\s+\d\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)$",
        pa_command="show routing protocol bgp summary",
        pa_regex=rf"^\s+peer \S+\s+ AS \d+, (\S+), IP {peer_ip_address}$",
    )


@app.route("/status/link_availability_history/<device_name>/<interface_name>")
@netcat.exception_handler
def _display_link_availability_history(device_name: str, interface_name: str) -> Union[str, Tuple[str, int]]:
    """ Display link history based on device name and interface name  """

    if not netcat.validate_http_input(device_name):
        return netcat.http_error(f"Incorrect device name format: {device_name}")

    if not netcat.validate_http_input(interface_name):
        return netcat.http_error(f"Incorrect interface name format: {interface_name}")

    # Decode interface name
    interface_name = interface_name.replace("_", "/")

    return display_resource_availability_history(
        device_name=device_name,
        resource_name="Link",
        resource=interface_name,
        cisco_command="show ip interface brief",
        cisco_regex=rf"^{interface_name}\s+\S+\s+\S+\s+\S+\s+(?:administratively )?(\S+\s+\S+) *$",
        pa_command="show interface all",
        pa_regex=rf"^{interface_name}\s+\d+\s+(\S+)\s+\S+ *$",
    )


@app.route("/status")
@netcat.exception_handler
def _display_network_status() -> Union[str, Tuple[str, int]]:
    """ Display network status on the web page """

    inaccessible_devices, broken_bgp_sessions, broken_links, dns_servers_status, generated_info = create_network_status()

    return flask.render_template(
        "status_results.html",
        inaccessible_devices=inaccessible_devices,
        broken_bgp_sessions=broken_bgp_sessions,
        broken_links=broken_links,
        dns_servers_status=dns_servers_status,
        generated_info=generated_info,
    )


@netcat.exception_handler
def email_network_status(email_receipients: str, smtp_server: str) -> None:
    """ Email network status """

    inaccessible_devices, broken_bgp_sessions, broken_links, dns_servers_status, generated_info = create_network_status()

    env = jinja2.Environment(loader=jinja2.FileSystemLoader("templates"))
    template = env.get_template("status_results_email.html")

    from datetime import datetime
    status_html = template.render(
        fromtimestamp=datetime.fromtimestamp,
        inaccessible_devices=inaccessible_devices,
        broken_bgp_sessions=broken_bgp_sessions,
        broken_links=broken_links,
        dns_servers_status=dns_servers_status,
        generated_info=generated_info,
    )

    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    message = MIMEMultipart("alternative")
    message["From"] = "netcat@verifone.com"
    message["To"] = email_receipients
    message["Subject"] = "NetCAT - VFI Network Status"
    message.attach(MIMEText(status_html, "html"))

    netcat.LOGGER.debug(f"Sending result email to '{email_receipients}' via '{smtp_server}' SMTP server")

    smtp = smtplib.SMTP(smtp_server)
    smtp.send_message(message)

    # Need to add some kind of handling SMTP related errors

    smtp.quit()


def parse_arguments(args: Optional[List[Any]] = None) -> argparse.Namespace:
    """ Parse comand line arguments """

    parser = argparse.ArgumentParser()
    parser.add_argument("-D", "--debug", action="store_true", help="enable debug logs")
    parser.add_argument("-S", "--single-process", action="store_true", help="enable single procss operation for debuging purposes")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--http-port", default=8000, type=int, action="store", help="TCP port for Flask web service to run on")
    group.add_argument("-m", "--email-address", nargs="+", action="store", help="email(s) to sent report to")

    return parser.parse_args(args)


def main() -> int:
    """ Run app in FLask HTTP server if executed directly from command line """

    arguments = parse_arguments()
    netcat.SINGLE_PROCESS_MODE = arguments.single_process

    netcat.setup_logger(debug=arguments.debug)

    arguments.debug and netcat.LOGGER.opt(ansi=True).info("<magenta>Debug mode enabled</magenta>")
    arguments.single_process and netcat.LOGGER.opt(ansi=True).info("<magenta>Single process mode enabled</magenta>")

    if arguments.email_address:
        email_network_status(", ".join(arguments.email_address), "intrelay.verifone.com")
        return 0

    print("\nNetCAT Network Status, ver {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski\n")

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
