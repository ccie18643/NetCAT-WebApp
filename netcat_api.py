#!/usr/bin/env python3

"""

NetCAT config backup, deployment and monitoring system version 5.5 - 2020, Sebastian Majewski

netcat_api.py - rest ip server

"""


import sys
import time
import socket
import datetime
import argparse

from typing import List, Dict, Any, Optional

import flask
import flask_restful  # type: ignore

import netcat

if netcat.DB_TYPE == "MongoDB":
    import netcat_mongodb as db

if netcat.DB_TYPE == "DynamoDB":
    import netcat_dynamodb as db


if __name__ == "__main__":
    app = application = flask.Flask(__name__)

api = flask_restful.Api(app)


class ApiDevices(flask_restful.Resource):
    """ API /api/devices """

    def get(self) -> List[str]:
        """ Get list of all the devices """

        return list(next(iter(db.get_command_status_list(search_depth=1, field_list=["device_info_dict"])), {}).get("device_info_dict", {}))  # type: ignore


api.add_resource(ApiDevices, "/api/devices")


class ApiDevicesDevice(flask_restful.Resource):
    """ API /api/devices/<device_name> """

    def get(self, device_name: str) -> Dict[str, Any]:
        """ Get device info document for given device """

        return next(iter(db.get_command_status_list(search_depth=1, field_list=["device_info_dict"])), {}).get("device_info_dict", {}).get(device_name, {})  # type: ignore


api.add_resource(ApiDevicesDevice, "/api/devices/<device_name>")


class ApiDevicesDeviceSnapshots(flask_restful.Resource):
    """ API /api/devices/<device_name>/snapshots """

    def get(self, device_name: str) -> List[str]:
        """ Get snapshot list for given device """

        return [__ for _ in db.get_device_data_list__c(device_name, command_list=None) if (__ := _.get("snapshot_timestamp"))]


api.add_resource(ApiDevicesDeviceSnapshots, "/api/devices/<device_name>/snapshots")


class ApiDevicesDeviceSnapshotsSnapshot(flask_restful.Resource):
    """ API /api/devices/<device_name>/snapshots/<timestamp> """

    def get(self, device_name: str, timestamp: str) -> Dict[str, Any]:
        """ Get device data record by given timestamp """

        return db.get_device_data(device_name, int(timestamp)) or {}


api.add_resource(ApiDevicesDeviceSnapshotsSnapshot, "/api/devices/<device_name>/snapshots/<timestamp>")


@app.before_first_request
def _before_first_request() -> None:
    """ Initialize logger """

    netcat.LOGGER or netcat.setup_logger()  # type: ignore


def parse_arguments(args: Optional[List[Any]] = None) -> argparse.Namespace:
    """ Parse comand line arguments """

    parser = argparse.ArgumentParser()
    parser.add_argument("-D", "--debug", action="store_true", help="enable debug logs")
    parser.add_argument("-p", "--http-port", default=8000, type=int, action="store", help="TCP port for Flask web service to run on")
    return parser.parse_args(args)


def main() -> int:
    """ Run app in FLask HTTP server if executed directly from command line """

    arguments = parse_arguments()

    netcat.setup_logger(debug=arguments.debug)

    arguments.debug and netcat.LOGGER.opt(ansi=True).info("<magenta>Debug mode enabled</magenta>")

    print(f"\nNetCAT Web API, ver NetCAT {netcat.VERSION} ({netcat.DB_TYPE}) - {netcat.YEAR}, Sebastian Majewski\n")

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
