#!/usr/bin/env python3

"""

NetCAT config backup, deployment and monitoring system version 5.5 - 2020, Sebastian Majewski

netcat_mongodb.py (App version) - module containing shared functions used to access MongoDB

"""

import sys

from typing import List, Dict, Tuple, Any, Callable, Optional

import pymongo  # type: ignore

import netcat


DB_URI: str = "mongodb://127.0.0.1/netcat"


def _projection(command_list: Optional[List[str]] = []) -> Dict[str, bool]:
    """ Create MongoDB projection from provided command list, '[]' for all commands to be included, 'None' for no commands to be included """

    projection = {"_id": False, "snapshot_timestamp": True, "device_name": True, "device_type": True}

    if command_list:
        projection.update({"output_formats.info." + _: True for _ in [netcat.encode_command(_) for _ in command_list]})

    elif command_list == []:
        projection.update({"output_formats.info": True})

    return projection


def get_device_data(device_name: str, timestamp: int, command_list: Optional[List[str]] = []) -> Dict[str, Any]:
    """ Get output of all or given command(s) from device_name / timestamp document """

    results: List[Dict[str, Any]] = []

    with pymongo.MongoClient(DB_URI) as client:
        table = client.get_default_database()[netcat.DBT_INFO]

        query_params = {
            "filter": {"device_name": device_name, "snapshot_timestamp": timestamp},
            "projection": _projection(command_list),
        }

        netcat.LOGGER.debug(f"{netcat.fn()}: table='{netcat.DBT_INFO}', {query_params=}")

    return netcat.decompress_device_data(table.find_one(**query_params))


def get_device_data_list__a(timestamp: int, device_type_list: List[str], command_list: Optional[List[str]] = []) -> List[Dict[str, Any]]:
    """ Get list of device_data items by given timestamp and device types """

    results: List[Dict[str, Any]] = []

    with pymongo.MongoClient(DB_URI) as client:
        table = client.get_default_database()[netcat.DBT_INFO]

        query_params = {
            "filter": {"snapshot_timestamp": timestamp, "device_type": {"$in": device_type_list}},
            "projection": _projection(command_list),
        }

        netcat.LOGGER.debug(f"{netcat.fn()}: table='{netcat.DBT_INFO}', {query_params=}")

    return [netcat.decompress_device_data(_) for _ in table.find(**query_params)]


def get_device_data_list__b(device_name_list: List[str], command_list: Optional[List[str]] = []) -> List[Dict[str, Any]]:
    """ Get list of device_data items by device name list and latest timestamp available for each device """

    results: List[Dict[str, Any]] = []

    with pymongo.MongoClient(DB_URI) as client:
        table = client.get_default_database()[netcat.DBT_INFO]

        for device_name in device_name_list:

            query_params = {
                "filter": {"device_name": device_name},
                "projection": _projection(command_list),
                "sort": [("snapshot_timestamp", pymongo.DESCENDING)],
            }

            netcat.LOGGER.debug(f"{netcat.fn()}: table='{netcat.DBT_INFO}', {query_params=}")

            if result := table.find_one(**query_params):
                results.append(result)

    return [netcat.decompress_device_data(_) for _ in results]


def get_device_data_list__c(device_name: str, command_list: Optional[List[str]] = [], search_depth: int = 0) -> List[Dict[str, Any]]:
    """ Get list of device_data items up to given search depth by device name  """

    results: List[Dict[str, Any]] = []

    with pymongo.MongoClient(DB_URI) as client:
        table = client.get_default_database()[netcat.DBT_INFO]

        query_params = {
            "filter": {"device_name": device_name},
            "projection": _projection(command_list),
            "sort": [("snapshot_timestamp", pymongo.DESCENDING)],
            "limit": search_depth,
        }

        netcat.LOGGER.debug(f"{netcat.fn()}: table='{netcat.DBT_INFO}', {query_params=}")

    return [netcat.decompress_device_data(_) for _ in table.find(**query_params)]


def get_command_status_list(search_depth: int = 0, field_list: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """ Get command snpshot status list, if no field list is specified result contains only timestamp of each snapshot """

    with pymongo.MongoClient(DB_URI) as client:
        table = client.get_default_database()[netcat.DBT_STATUS]

        query_params = {
            "filter": {"snapshot_name": "info_status"},
            "projection": {"_id": False, "snapshot_timestamp": True},
            "sort": [("snapshot_timestamp", pymongo.DESCENDING)],
            "limit": search_depth,
        }

        if field_list:
            query_params["projection"].update({_: True for _ in field_list})

        netcat.LOGGER.debug(f"{netcat.fn()}: table='{netcat.DBT_STATUS}', {query_params=}")

        return list(table.find(**query_params))


def get_dns_status() -> Dict[str, Any]:
    """ Get dns servers status """

    with pymongo.MongoClient(DB_URI) as client:
        table = client.get_default_database()[netcat.DBT_STATUS]

        query_params = {
            "filter": {"snapshot_name": "dns_status"},
            "projection": {"_id": False},
            "sort": [("snapshot_timestamp", pymongo.DESCENDING)],
        }

        netcat.LOGGER.debug(f"{netcat.fn()}: table='{netcat.DBT_STATUS}', {query_params=}")

        return table.find_one(**query_params)


def exception_handler_http(function: Callable[..., Any]) -> Any:
    """ Decorator to log pymongo exceptions and return html formated error message to be displayed by flask """

    from functools import wraps

    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)

        except pymongo.errors.PyMongoError as exception:
            netcat.LOGGER.error(f"PyMongo exception: '{exception}'")
            return netcat.http_error(f"PyMongo exception: '{exception}'")

    return wrapper


def exception_handler(function: Callable[..., Any]) -> Any:
    """ Decorator to log pymongo exceptions and exit process """

    from sys import exit
    from functools import wraps

    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)

        except pymongo.errors.PyMongoError as exception:
            netcat.LOGGER.error(f"PyMongo exception: '{exception}'")
            exit()

    return wrapper
