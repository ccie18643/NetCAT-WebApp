#!/usr/bin/env python3

"""

NetCAT config backup, deployment and monitoring system version 5.5 - 2020, Sebastian Majewski

netcat_services.py - shared web services

"""

import sys
import time
import socket
import datetime

from typing import List, Any, Optional, Tuple, Union

import flask
import pymongo  # type: ignore

import netcat

if netcat.DB_TYPE == "MongoDB":
    import netcat_mongodb as db

if netcat.DB_TYPE == "DynamoDB":
    import netcat_dynamodb as db


if __name__ == "__main__":
    app = application = flask.Flask(__name__)


@app.before_first_request
def _before_first_request() -> None:
    """ Initialize logger """

    netcat.LOGGER or netcat.setup_logger()  # type: ignore


@app.route("/services/device_data/<device_name>/<timestamp>")
@netcat.exception_handler
@db.exception_handler_http
def _device_data__device_name__timestamp(device_name: str, timestamp: str) -> Union[str, Tuple[str, int]]:
    """ Display device info file if the device exists """

    if not netcat.validate_http_input(device_name):
        return netcat.http_error(f"Incorrect device name format: {device_name}")

    if not netcat.validate_timestamp(timestamp):
        return netcat.http_error(f"Incorrect timestamp format: {timestamp}")

    # Time process execution
    start_time = time.monotonic()

    if not (device_data := db.get_device_data(device_name, int(timestamp))):
        return netcat.http_error("Non existent record requested")

    # Time process execution
    end_time = time.monotonic()

    netcat.LOGGER.info(f"Displayed device data '{device_name} - {timestamp}' in {end_time - start_time:.2f}s")

    return (f"<html><head><title>NetCAT - Device Data [{device_name.upper()} / {timestamp}]" +
            f"</title></head><body><pre>{netcat.print_device_data(device_data)}</pre></body></html>")


@app.route("/services/device_data/<device_name>")
@netcat.exception_handler
@db.exception_handler_http
def _device_data__device_name(device_name: str) -> str:
    """ Display list of device records for given device"""

    from uuid import uuid1

    # Time process execution
    start_time = time.monotonic()

    device_data_history = [{"uuid": uuid1(), "snapshot_timestamp": __.get("snapshot_timestamp"), "status": device_name in
            [_[0] for _ in __.get("device_info_dict", {}).items() if _[1].get("successful")]} for __ in db.get_command_status_list(field_list=["device_info_dict"])]

    # Time process execution
    end_time = time.monotonic()

    generated_info = (
        f"Witchcraft performed by {socket.gethostname()} on {datetime.datetime.now().strftime('%Y-%m-%d at %H:%M:%S EDT')} "
        + f"in {end_time - start_time:.2f}s by casting single spell for {len(device_data_history)} "
        + f"snapshots. NetCAT {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski"
    )

    netcat.LOGGER.info(f"Created device data history for '{device_name}' in {end_time - start_time:.2f}s")

    return flask.render_template("services_device_data_history.html", device_name=device_name,
            device_data_history=device_data_history, generated_info=generated_info)


def parse_arguments(args: Optional[List[Any]] = None) -> Any:
    """ Parse comand line arguments """

    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("-D", "--debug", action="store_true", help="enable debug logs")
    parser.add_argument("-p", "--http-port", default=8000, type=int, action="store", help="TCP port for Flask web service to run on")

    return parser.parse_args(args)


def main() -> int:
    """ Run app in FLask HTTP server if executed directly from command line """

    arguments = parse_arguments()

    netcat.setup_logger(debug=arguments.debug)

    arguments.debug and netcat.LOGGER.opt(ansi=True).info("<magenta>Debug mode enabled</magenta>")

    print(f"\nNetCAT Network Web Services, ver {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski\n")

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
