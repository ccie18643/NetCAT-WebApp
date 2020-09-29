#!/usr/bin/env python3

"""

NetCAT config backup, deployment and monitoring system version 5.5 - 2020, Sebastian Majewski

netcat_webapp.py - netcat web front end

"""

import sys
import netcat
import flask
import argparse

from typing import List, Dict, Any, Optional

import builtins

builtins.app = app = application = flask.Flask(__name__)

import netcat_inventory
import netcat_status
import netcat_iplookup
import netcat_maclookup
import netcat_services
import netcat_api


@app.route("/")
def _root():
    return flask.render_template("root.html")


def parse_arguments(args: Optional[List[Any]] = None) -> argparse.Namespace:
    """ Parse comand line arguments """

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--http-port", default=8000, type=int, action="store", help="TCP port for Flask web service to run on")

    return parser.parse_args(args)


def main() -> int:
    """ Run app in FLask HTTP server if executed directly from command line """

    arguments = parse_arguments()

    netcat.setup_logger()

    print("\nNetCat Web App, ver 5.5 - 2020, Sebastian Majewski\n")

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
