#!/usr/bin/env python3

"""

NetCAT config backup, deployment and monitoring system version 5.5 - 2020, Sebastian Majewski

netcatdynamodb.py (App version) - module containing shared functions for AWS DynamoDB support

"""

from typing import List, Dict, Tuple, Any, Callable, Optional, Union

import botocore.session  # type: ignore
import botocore.exceptions  # type: ignore
#import amazondax # type: ignore

import netcat


# For connetcion to DynamoDB to work the AWS CLI needs to be installed and configured with apropriate connectivity key
DB_CLIENT = botocore.session.get_session().create_client("dynamodb")

# For use with DAX accelerator
#DB_CLIENT = amazondax.AmazonDaxClient(botocore.session.get_session(), endpoints=["netcat.qrzev9.clustercfg.dax.use1.cache.amazonaws.com:8111"])


def _retry_on_http_error(function) -> Any:
    """ Retry operation if Botocore HTTP exception is catched """

    from sys import exit
    from functools import wraps

    @wraps(function)
    def wrapper(*args, **kwargs):

        retry_counter = 3
    
        while True:
            try:
                return function(*args, **kwargs)

            except botocore.exceptions.HTTPClientError:
                retry_counter -= 1
                if retry_counter:
                    netcat.LOGGER.warning("Botocore HTTPClientError exception, retrying operation")
                else:
                    netcat.LOGGER.error(f"Botocore HTTPClientError exception")
                    sys.exit()

    return wrapper


def _delay_start(function: Callable[..., Any]) -> Any:
    """ Delay start of DynamoDB operation to avoid synchronisation issues while multiprocessing """

    from functools import wraps
    from random import uniform
    from time import sleep

    @wraps(function)
    def wrapper(*args, **kwargs):
        sleep(uniform(0, 0.5))
        return function(*args, **kwargs)

    return wrapper


def _get_list(query_params: Dict[str, Any], search_depth: int = 0) -> List[Any]:
    """ Get list of records (up to given serch depth) based on given query params """

    results: List[Any] = []

    query_params["ScanIndexForward"] = False

    if search_depth:
        query_params["Limit"] = search_depth

    while True:
        response = DB_CLIENT.query(**query_params)
        results += [_fold(_) for _ in response.get("Items", [])]

        if "LastEvaluatedKey" not in response:
            break

        if search_depth:
            query_params["Limit"] -= len(response.get("Items"))

            if query_params["Limit"] == 0:
                break

        query_params["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    return results


def _fold(z: Any) -> Any:
    """ Fold DynamoDB low level interface query result into its original json format """

    def _trl(x, y):
        if y == "N":
            return int(x[y])
        if y == "NULL":
            return None
        return x[y]

    def _trd(z, x, y):
        if y == "N":
            return int(z[x][y])
        if y == "NULL":
            return None
        return z[x][y]

    if type(z) is list:
        return [_fold(x[y]) if (y := next(iter(x))) in {"M", "L"} else _trl(x, y) for x in z]

    elif type(z) is dict:
        return {x: _fold(z[x][y]) if (y := next(iter(z[x]))) in {"M", "L"} else _trd(z, x, y) for x in z}  # type: ignore


def _projection(command_list: Optional[List[str]] = []) -> str:
    """ Create DynamoDB projection from provided command list, '[]' for all commands to be included, 'None' for no commands to be included """

    if command_list:
        return f"device_name, device_type, snapshot_timestamp, output_formats.info.{', output_formats.info.'.join([netcat.encode_command(_) for _ in command_list])}"

    if command_list == []:
        return "device_name, device_type, snapshot_timestamp, output_formats.info"

    return "device_name, device_type, snapshot_timestamp"


@_delay_start
@_retry_on_http_error
def get_device_data(device_name: str, timestamp: int, command_list: Optional[List[str]] = []) -> Dict[str, Any]:
    """ Get output of all or given command(s) from device_name / timestamp document """

    query_params = {
        "TableName": netcat.DBT_INFO,
        "Key": {"device_name": {"S": device_name}, "snapshot_timestamp": {"N": str(timestamp)}},
        "ProjectionExpression": _projection(command_list),
    }

    netcat.LOGGER.debug(f"{netcat.fn()}: {query_params=}")

    return netcat.decompress_device_data(_fold(DB_CLIENT.get_item(**query_params).get("Item", {})))


@_delay_start
@_retry_on_http_error
def get_device_data_list__a(timestamp: int, device_type_list: List[str], command_list: Optional[List[str]] = []) -> List[Dict[str, Any]]:
    """ Get list of device_data items by given timestamp and device types """

    results: List[Dict[str, Any]] = []

    for device_type in device_type_list:

        query_params = {
            "TableName": netcat.DBT_INFO,
            "IndexName": "type-timestamp-index",
            "KeyConditionExpression": "device_type = :device_type AND snapshot_timestamp = :snapshot_timestamp",
            "ExpressionAttributeValues": {":device_type": {"S": device_type}, ":snapshot_timestamp": {"N": str(timestamp)}},
            "ProjectionExpression": _projection(command_list),
        }

        netcat.LOGGER.debug(f"{netcat.fn()}: {query_params=}")

        results += _get_list(query_params)

    return [netcat.decompress_device_data(_) for _ in results]


@_delay_start
@_retry_on_http_error
def get_device_data_list__b(device_name_list: List[str], command_list: Optional[List[str]]) -> List[Dict[str, Any]]:
    """ Get list of device_data items by device name list and latest timestamp available for each device """

    results: List[Dict[str, Any]] = []

    for device_name in device_name_list:

        query_params = {
            "TableName": netcat.DBT_INFO,
            "KeyConditionExpression": "device_name = :device_name",
            "ExpressionAttributeValues": {":device_name": {"S": device_name}},
            "ProjectionExpression": _projection(command_list),
        }

        netcat.LOGGER.debug(f"{netcat.fn()}: {query_params=}")

        results += _get_list(query_params, search_depth=1)

    return [netcat.decompress_device_data(_) for _ in results]


@_delay_start
@_retry_on_http_error
def get_device_data_list__c(device_name: str, command_list: Optional[List[str]] = [], search_depth: int = 0) -> List[Dict[str, Any]]:
    """ Get list of device_data items up to given search depth by device name  """

    query_params = {
        "TableName": netcat.DBT_INFO,
        "KeyConditionExpression": "device_name = :device_name",
        "ExpressionAttributeValues": {":device_name": {"S": device_name}},
        "ProjectionExpression": _projection(command_list),
    }

    netcat.LOGGER.debug(f"{netcat.fn()}: {query_params=}")

    return [netcat.decompress_device_data(_) for _ in _get_list(query_params, search_depth)]
 

@_delay_start
@_retry_on_http_error
def get_command_status_list(search_depth: int = 0, field_list: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """ Get command snpshot status list, if no field list is specified result contains only timestamp of each snapshot """

    query_params = {
        "TableName": netcat.DBT_STATUS,
        "KeyConditionExpression": "snapshot_name = :snapshot_name",
        "ExpressionAttributeValues": {":snapshot_name": {"S": "info_status"}},
        "ProjectionExpression": "snapshot_timestamp",
    }

    if field_list:
        query_params["ProjectionExpression"] += ", " + ", ".join(field_list)  # type: ignore

    netcat.LOGGER.debug(f"{netcat.fn()}: {query_params=}")

    return _get_list(query_params, search_depth)


@_delay_start
@_retry_on_http_error
def get_dns_status() -> Dict[str, Any]:
    """ Get dns servers status """

    query_params = {
        "TableName": netcat.DBT_STATUS,
        "KeyConditionExpression": "snapshot_name = :snapshot_name",
        "ExpressionAttributeValues": {":snapshot_name": {"S": "dns_status"}},
    }

    netcat.LOGGER.debug(f"{netcat.fn()}: {query_params=}")

    return next(iter(_get_list(query_params, search_depth=1)), {})


def exception_handler_http(function: Callable[..., Any]) -> Any:
    """ Decorator to log botocore exceptions and return html formated error message to be displayed by flask """

    from functools import wraps

    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)

        except botocore.exceptions.ClientError as exception:
            netcat.LOGGER.error(f"Botocore exception: '{exception}'")
            return netcat.http_error(f"Botocore exception: '{exception}'")

    return wrapper


def exception_handler(function: Callable[..., Any]) -> Any:
    """ Decorator to log botocore exceptions and exit process """

    from sys import exit
    from functools import wraps

    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)

        except botocore.exceptions.ClientError as exception:
            netcat.LOGGER.error(f"Botocore exception: '{exception}'")
            exit()

    return wrapper
