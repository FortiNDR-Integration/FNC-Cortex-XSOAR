"""    Fortinet FortiNDR Cloud Integration for Cortex XSOAR (aka Demisto)

       This integration allows fetching detections, entities, events and
       saved searches from Fortinet FortiNDR Cloud APIs, also allows for
       some management operations like creating scheduled pcap tasks,
       updating detection rules and resolving detections.
"""

import json
from datetime import datetime, timedelta

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from fnc import FncClient, FncClientLogger
from fnc.api import EndpointKey, FncApiClient, FncRestClient
from fnc.errors import ErrorMessages, ErrorType, FncClientError

TRAINING_ACC = "f6f6f836-8bcd-4f5d-bd61-68d303c4f634"
MAX_DETECTIONS = 10000
DEFAULT_DELAY = 10
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
USER_AGENT = "FortiNDRCloud_Cortex.v1.1.0"


class FncCortexRestClient(FncRestClient):
    client: BaseClient

    def __init__(self):
        self.client = BaseClient(base_url="ToBeIgnored")

    def validate_request(self, req_args: dict):
        if not req_args or "url" not in req_args:
            raise FncClientError(
                error_type=ErrorType.REQUEST_VALIDATION_ERROR,
                error_message=ErrorMessages.REQUEST_URL_NOT_PROVIDED,
            )

        if "method" not in req_args:
            raise FncClientError(
                error_type=ErrorType.REQUEST_VALIDATION_ERROR,
                error_message=ErrorMessages.REQUEST_METHOD_NOT_PROVIDED,
            )

    def send_request(self, req_args: dict = {}):
        url = req_args["url"]
        method = req_args["method"]
        headers = req_args.get("headers", {})
        timeout = req_args.get("timeout", 70)
        parameters = req_args.get("params", {})
        json_data = req_args.get("json", None)
        data = req_args.get("data", None)

        return self.client._http_request(
            method=method,
            full_url=url,
            params=parameters,
            data=data,
            json_data=json_data,
            headers=headers,
            timeout=timeout,
            resp_type="response"
        )


# implement a logger class using FncClientLogger
class FncCortexLogger(FncClientLogger):
    list_of_logs: list[tuple[str, str]] = []

    def info(self, msg):
        info_log = ('info', msg)
        self.list_of_logs.append(info_log)

    def debug(self, msg):
        info_log = ('debug', msg)
        self.list_of_logs.append(info_log)

    def warning(self, msg):
        info_log = ('info', msg)
        self.list_of_logs.append(info_log)

    def critical(self, msg):
        info_log = ('error', msg)
        self.list_of_logs.append(info_log)

    def error(self, msg):
        info_log = ('error', msg)
        self.list_of_logs.append(info_log)


FncCortexLog = FncCortexLogger()


class Client(BaseClient):
    @staticmethod
    def getUrl(api, testing=False) -> str:
        """Provide the base url to access the specific API.
        :param str api:  The specific API for which we need the base url.
        return: The requested base url
        rtype str
        """
        url: str = ""
        if testing:
            if api == "Detections":
                url = "https://detections-uat.icebrg.io/v1/"
            elif api == "Sensors":
                url = "https://sensor-uat.icebrg.io/v1/"
            elif api == "Entity":
                url = "https://entity-uat.icebrg.io/v1/entity/"
        else:
            if api == "Detections":
                url = "https://detections.icebrg.io/v1/"
            elif api == "Sensors":
                url = "https://sensor.icebrg.io/v1/"
            elif api == "Entity":
                url = "https://entity.icebrg.io/v1/entity/"

        return url

    @staticmethod
    def getClient(api, api_key, testing=False):
        """Provide the required Client instance to interact with
        the specific API.
        :param str api:  The specific API we need to interact with.
        :param str api_key: The API key to authenticate the request bwing made.
        return: The requested Client instance.
        rtype str
        """
        headers = {
            "Authorization": "IBToken " + api_key,
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        }

        match api:
            case "Detections":
                return DetectionClient(
                    base_url=Client.getUrl(api, testing), headers=headers
                )


class DetectionClient(Client):
    """Client that makes HTTP requests to the Detections API"""

    def getDetections(self, args: str = "") -> Dict[str, Any]:
        """Calls the GET /detections endpoint to retrieve the detections
        :return JSON response from /detections endpoint
        :rtype Dict[str, Any]
        """
        demisto.debug("DetectionClient.getDetections method has been called.")
        return self._http_request(method="GET", url_suffix="/detections" + args)

    def getDetectionRules(self, args: str = "") -> Dict[str, Any]:
        """Calls the GET /rules endpoint to retrieve the Detection Rules
        :param str args: some filters to be passed in the request
        :return JSON response from /rules endpoint
        :rtype Dict[str, Any]
        """
        demisto.debug("DetectionClient.getDetectionRules method has been called.")
        return self._http_request(method="GET", url_suffix="/rules" + args)

    def getDetectionEvents(self, args: str) -> Dict[str, Any]:
        """Calls the GET /events endpoint to retrieve
        the detection's events
            :param str args: some filters to be passed in the request
            :return JSON response from /events endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug("DetectionClient.getDetectionEvents method has been called.")

        return self._http_request(method="GET", url_suffix="/events" + args)

    def getDetectionRuleEvents(self, rule_uuid: str, args: str) -> Dict[str, Any]:
        """Calls the GET /rules/<rule_id>/events endpoint to retrieve
        the detection rule's events
            :param str rule_uuid: the id of the rulefor which the events
            need to be retrieved
            :param str args: some filters to be passed in the request
            :return JSON response from /rules/<rule_id>/events endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug("DetectionClient.getDetectionRuleEvents method has been called.")

        return self._http_request(
            method="GET", url_suffix="rules/" + rule_uuid + "/events" + args
        )

    def createDetectionRule(self, data) -> Dict[str, Any]:
        """Calls the POST endpoint to create a Detection rule
        :param Any data: data to be passed in the request
        :return JSON response from endpoint
        :rtype Dict[str, Any]
        """
        demisto.debug("DetectionClient.createDetectationRule method has been called.")

        return self._http_request(
            method="POST", url_suffix="/rules", data=json.dumps(data)
        )

    def resolveDetection(self, detection_id: str, data=None):
        """Calls the Put /detections/{detection_id}/resolve endpoint to
        resolve the provided detection
            :param str detection_id: the detection to be resolved
            :param Any data: data to be passed in the request
            :return JSON response from /detections/{detection_id}/resolve
            endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug("DetectionClient.resolveDetection method has been called.")

        return self._http_request(
            method="Put",
            url_suffix="detections/" + detection_id + "/resolve",
            data=json.dumps(data),
            return_empty_response=True,
        )


# Helper Methods


def _handle_fnc_endpoint(api_client: FncApiClient, endpoint: EndpointKey, param: dict):
    demisto.info(f"Handling {endpoint.value} Request.")

    # Add an action result object to self (BaseConnector) to represent
    # the action for this param
    param.pop("context", None)

    response = None
    exception = None
    request_summary = {"status": "", "error": "", "info": ""}

    try:
        response = api_client.call_endpoint(endpoint=endpoint, args=param)

        demisto.info(f"{endpoint.value} successfully completed.")
        request_summary.update({"status": "SUCCESS"})
        request_summary.update({"info": f"{len(response)} items retrieved."})
    except FncClientError as e:
        demisto.error(f"{endpoint.value} Request Failed. [{str(e)}]")
        request_summary.update({"status": "FAILURE"})
        request_summary.update({"error": str(e)})
        exception = e

    return {
        "response": response,
        "request_summary": request_summary,
        "exception": exception,
    }


def encodeArgsToURL(args, multiple_values: List = []):
    """Create the query string with the provided arguments
    :parm Dict[str, Any] args: Arguments to be included in the query string
    :return The querystring
    :rtype str
    """
    url = ""
    first = True

    for arg in args:
        values: List[Any] = []
        if arg in multiple_values:
            values.extend(args[arg].split(","))
        else:
            values.append(args[arg])

        for value in values:
            this_arg = str(arg) + "=" + str(value).strip()
            if first:
                url = url + "?" + this_arg
                first = False
            else:
                url = url + "&" + this_arg
    return url


def flattenFieldDict(field, field_dict):
    """Recursively flatten a dictionary field.
    :param str field: Field to be flatten
    :parm Dict[str, Any] field_dict: Dictionary containing the
    field to be flatten
    :return A new dictionary with the field flattened
    :rtype Dict[str, Any]
    """
    new_dict = {}
    for key in field_dict:
        if isinstance(field_dict[key], dict):
            new_dict.update(flattenFieldDict(field + "_" + key, field_dict[key]))
        else:
            new_dict[field + "_" + key] = field_dict[key]
    return new_dict


def flattenList(lt):
    """Recursively flatten a list.
    :parm List lt: List to be flatten
    :return A new flattened List
    :rtype List
    """
    string = ""
    for i in range(0, len(lt)):
        if isinstance(lt[i], dict):
            string = string + flattenDict(lt[i])
            if i + 1 < len(lt):
                string = string + "---" + "\n"
        elif isinstance(lt[i], list):
            string = string + flattenList(lt[i])
        else:
            string = string + str(lt[i])
            if i + 1 < len(lt):
                string = string + ", "
    return string


def flattenDict(dt):
    """Recursively flatten a dictionary.
    :parm Dict[str, Any] dt: Dictionary to be flatten
    :return A new flattened dictionary
    :rtype Dict[str, Any]
    """
    string = ""
    for key in dt:
        if isinstance(dt[key], list):
            string = string + str(key) + ": " + flattenList(dt[key]) + "\n"
        elif isinstance(dt[key], dict):
            string = string + str(key) + ": " + flattenDict(dt[key]) + "\n"
        else:
            string = string + str(key) + ": " + str(dt[key]) + "\n"
    return string


def formatEvents(r_json):
    """Format the events in the response to be shown as a table.
    :parm Any r_json: Received response
    :return The formated response
    :rtype list
    """
    columns = r_json["columns"] if "columns" in r_json else []
    data = r_json["data"] if "data" in r_json else []

    if not data:
        return []

    newData = []
    f = 0

    for row in data:
        if len(columns) != len(row):
            f += 1

        newRow = {}
        for i, field in enumerate(columns):
            newRow[field] = row[i]
        newData.append(newRow)

    demisto.info(
        f"{f} events' size did not matched the headers' size and were ignored."
    )
    return newData


def getStartDate(first_fetch_str) -> datetime:

    if not first_fetch_str or not first_fetch_str.strip():
        first_fetch_str = "7 days"

    start_date = dateparser.parse(first_fetch_str, settings={"TIMEZONE": "UTC"})
    assert start_date is not None, f"could not parse {first_fetch_str}"

    return start_date


def mapSeverity(severity) -> int:
    match severity:
        case "high":
            return 3
        case "moderate":
            return 2
        case "low":
            return 1
        case _:
            return 0


def getIncidents(result, end_date) -> tuple[Dict[str, int], List[dict[str, Any]]]:
    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    detections = result.outputs if result and isinstance(result, CommandResults) else []

    if detections is None or not isinstance(detections, list):
        detections = []

    demisto.info(f"Creating incidents from {len(detections)} detections")
    for detection in detections:
        severity = mapSeverity(detection["rule_severity"])
        incident = {
            "name": "Fortinet FortiNDR Cloud - " + detection["rule_name"],
            "occurred": detection["created"],
            "severity": severity,
            "details": detection["rule_description"],
            "dbotMirrorId": detection["uuid"],
            "rawJSON": json.dumps(detection),
            "type": "Fortinet FortiNDR Cloud Detection",
            "CustomFields": {  # Map specific XSOAR Custom Fields
                "fortindrcloudcategory": detection["rule_category"],
                "fortindrcloudconfidence": detection["rule_confidence"],
                "fortindrcloudstatus": detection["status"],
            },
        }

        incidents.append(incident)

    end_date_str = end_date.strftime(DATE_FORMAT)
    next_run = {"last_fetch": end_date_str}

    demisto.info(f"fetched {len(incidents)} incidents")
    demisto.debug(f"Last run set to: {end_date_str}")

    return next_run, incidents


# Commands Methods


def commandTestModule(client: FncApiClient):
    """Test that the module is up and running."""
    demisto.info("Testing connection to FortiNDR Cloud Services")

    try:
        commandGetSensors(client=client, args={})
        demisto.info("Connection successfully verified.")
        return "ok"
    except Exception as e:
        demisto.error(f"Module test failed: {e}")
        raise e


# Sensors API commands


def commandGetSensors(client: FncApiClient, args):
    """Get a list of all sensors."""
    demisto.info("CommandGetSensors has been called.")

    endpoint = EndpointKey.GET_SENSORS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Sensors"
    key = "sensors"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Sensors."

    demisto.info("CommandGetSensors successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetDevices(client: FncApiClient, args):
    """Get the number of devices."""
    demisto.info("CommandGetDevices has been called.")

    endpoint = EndpointKey.GET_DEVICES

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]["devices"]

    prefix = "FortiNDRCloud.Devices"
    key = "device_list"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Devices."

    demisto.info("CommandGetDevices successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetTasks(client: FncApiClient, args):
    """Get a list of all the PCAP tasks."""
    demisto.info("commandGetTasks has been called.")

    endpoint = EndpointKey.GET_TASK

    taskid = args.pop("task_uuid", "")
    if taskid:
        endpoint = EndpointKey.GET_TASK
        args.update({"task_id": taskid})
    else:
        endpoint = EndpointKey.GET_TASKS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Tasks"
    key = "pcap_task" if taskid != "" else "pcaptasks"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Tasks."

    demisto.info("CommandGetTasks successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandCreateTask(client: FncApiClient, args):
    """Create a new PCAP task."""
    demisto.info("commandCreateTask has been called.")

    endpoint = EndpointKey.CREATE_TASK

    sensor_ids = []
    if "sensor_ids" in args:
        sensor_ids = args["sensor_ids"].split(",")
        args.pop("sensor_ids")

    args["sensor_ids"] = sensor_ids

    result = _handle_fnc_endpoint(api_client=client, endpoint=endpoint, param=args)["response"]

    if "pcaptask" in result:

        demisto.info("CommandCreateTask successfully completed.")

        return CommandResults(readable_output="Task created successfully")
    else:
        raise Exception(f"Task creation failed with: {result}")


def commandGetEventsTelemetry(client: FncApiClient, args):
    """Get event telemetry data grouped by time"""
    demisto.info("commandGetEventsTelemetry has been called.")

    endpoint = EndpointKey.GET_TELEMETRY_EVENTS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Telemetry.Events"
    key = "data"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Event Telemetry."

    demisto.info("commandGetEventsTelemetry successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=formatEvents(result)
    )


def commandGetNetworkTelemetry(client: FncApiClient, args):
    """Get network telemetry data grouped by time"""
    demisto.info("commandGetNetworkTelemetry has been called.")

    endpoint = EndpointKey.GET_TELEMETRY_NETWORK

    latest_each_month = args.pop("latest_each_month", False)
    if latest_each_month:
        args.update({"latest_each_month": True})

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Telemetry.NetworkUsage"
    key = "network_usage"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Network Telemetry."

    demisto.info("commandGetNetworkTelemetry successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetPacketstatsTelemetry(client: FncApiClient, args):
    """Get packetstats telemetry data grouped by time."""
    demisto.info("commandGetPacketstatsTelemetry has been called.")

    endpoint = EndpointKey.GET_TELEMETRY_PACKETSTATS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Telemetry.Packetstats"
    key = "data"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Packetstats Telemetry."

    demisto.info("commandGetPacketstatsTelemetry successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


# Entity API commands


def commandGetEntitySummary(client: FncApiClient, args):
    """Get entity summary information about an IP or domain."""
    demisto.info("commandGetEntitySummary has been called.")
    endpoint = EndpointKey.GET_ENTITY_SUMMARY

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Entity.Summary"
    key = "summary"

    for log in FncCortexLog.list_of_logs:
        demisto.info("++++++++Log from logger+++++++++")
        demisto.info("log is => ", log)
        if log[0] == 'info':
            demisto.info(log[1])
        else:
            demisto.debug(log[1])

        FncCortexLog.list_of_logs.remove(log)

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Entity Summary."

    demisto.info("commandGetEntitySummary successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetEntityPdns(client: FncApiClient, args: Dict[str, Any]):
    """Get passive DNS information about an IP or domain."""
    demisto.info("commandGetEntityPdns has been called.")

    endpoint = EndpointKey.GET_ENTITY_PDNS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Entity.PDNS"
    key = "passivedns"

    if not result:
        raise Exception(f"We receive an invalid response from the server({result})")

    if "result_count" in result and result.get("result_count") == 0:
        return "We could not find any result for Get Entity PDNS."

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Entity PDNS."

    demisto.info("commandGetEntityPdns successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetEntityDhcp(client: FncApiClient, args: Dict[str, Any]):
    """Get DHCP information about an IP address."""
    demisto.info("commandGetEntityDhcp has been called.")

    endpoint = EndpointKey.GET_ENTITY_DHCP

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Entity.DHCP"
    key = "dhcp"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if "result_count" in result and result.get("result_count") == 0:
        return "We could not find any result for Get Entity DHCP."

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Entity DHCP."

    demisto.info("commandGetEntityDhcp successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetEntityFile(client: FncApiClient, args):
    """Get entity information about a file"""
    demisto.info("commandGetEntityFile has been called.")

    endpoint = EndpointKey.GET_ENTITY_FILE

    hash = args.pop("hash", "")
    args.update({"entity": hash})

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Entity.File"
    key = "file"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Entity File."

    demisto.info("commandGetEntityFile successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


# Detections API commands


def commandFetchIncidents(
    client: FncApiClient, account_uuid, params, last_run
) -> tuple[Dict[str, int], List[dict]]:
    demisto.info("Fetching incidents.")

    start_date = getStartDate(params.get("first_fetch"))

    last_fetch = last_run.get("last_fetch")
    if last_fetch is not None:
        demisto.debug(f"Incidents were last fetched on: {last_fetch}")
        start_date = datetime.strptime(last_fetch, DATE_FORMAT)

    delay = arg_to_number(arg=params.get("delay"), arg_name="delay", required=False)
    if not delay or delay < 0 or delay > DEFAULT_DELAY:
        delay = DEFAULT_DELAY

    # Get the utc datetime for now
    now = datetime.utcnow()
    end_date = now - timedelta(minutes=delay)

    if end_date < start_date:
        demisto.info(f"The time window [{start_date} to {end_date}] is not valid.")
        demisto.info("Waiting until next iteration.")
    else:
        start_date_str = datetime.strftime(start_date, DATE_FORMAT)
        end_date_str = datetime.strftime(end_date, DATE_FORMAT)
        demisto.info(f"Fetching detections between {start_date_str} and {end_date_str}")
        args = {
            "created_or_shared_start_date": start_date_str,
            "created_or_shared_end_date": end_date_str,
            "include": "rules,indicators",
            "sort_by": "device_ip",
            "sort_order": "asc",
            "limit": MAX_DETECTIONS,
            "offset": 0,
            "inc_polling": True,
        }

    status = params.get("status", "active")
    if status != "all":
        args["status"] = status

    if not params.get("muted", False):
        args["muted"] = False

    if not params.get("muted_device", False):
        args["muted_device"] = False

    if not params.get("muted_rule", False):
        args["muted_rule"] = False

    if account_uuid:
        args["account_uuid"] = account_uuid

    logged_args = args.copy()
    if "account_uuid" in logged_args:
        logged_args["account_uuid"] = "************"

    demisto.debug(f"Arguments being used for fetching detections: \n {logged_args} ")
    result = commandGetDetections(client, args)

    return getIncidents(result, end_date)


def addDetectionRules(result):
    """Create a new detection rule."""
    # Create a dictionary with the rules using its uuid as key
    rules = {}
    for rule in result.get("rules", []):
        rules[rule["uuid"]] = rule

    # Find the detection's rule in the dictionary and update the detection
    for detection in result.get("detections", []):
        rule = rules[detection["rule_uuid"]]

        detection.update({"rule_name": rule["name"]})
        detection.update({"rule_description": rule["description"]})
        detection.update({"rule_severity": rule["severity"]})
        detection.update({"rule_confidence": rule["confidence"]})
        detection.update({"rule_category": rule["category"]})
        # detection.update({'rule_signature': rule['query_signature']})

    return result


def getDetectionsInc(
    detectionClient: DetectionClient, result: Dict[str, Any], args
) -> Dict[str, Any]:
    """Get the remaining detections if there are more than
    the maximum allowed in a page.
    """
    if result is None:
        result = {"total_count": 0, "detections": [], "rules": []}

    next_piece: Dict[str, Any] = result
    while next_piece and next_piece["detections"]:
        offset = args.get("offset", 0) + MAX_DETECTIONS
        args.update({"offset": offset})
        demisto.info(f"Retrieving Detections with offset = {offset}.")
        next_piece = detectionClient.getDetections(encodeArgsToURL(args, ["include"]))

        count = 0
        if next_piece is not None:
            count = len(next_piece.get("detections", []))
            result.get("detections", []).extend(next_piece.get("detections", []))
            result.get("rules", []).extend(next_piece.get("rules", []))
            result["total_count"] += next_piece["total_count"]

        demisto.debug(f"{count} detections retrieved")

    return result


def commandGetDetections(client: FncApiClient, args):
    """Get a list of detections."""
    demisto.info("commandGetDetections has been called.")

    endpoint = EndpointKey.GET_DETECTIONS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Detections"
    key = "detections"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Detections."

    demisto.info("commandGetDetections successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetDetectionEvents(client: FncApiClient, args):
    """Get a list of the events associated to a specific detection."""
    demisto.info("CommandGetDetectionEvents has been called.")

    endpoint = EndpointKey.GET_DETECTION_EVENTS

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    events = []
    detection_uuid = args.get("detection_uuid", "")
    for event in result.get("events", []):
        rule_uuid = event.get("rule_uuid", "")
        event = event.get("event", {})
        if event:
            event["detection_uuid"] = detection_uuid
            event["rule_uuid"] = rule_uuid
            events.append(event)
    result["events"] = events

    prefix = "FortiNDRCloud.Detections"
    key = "events"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Detections Events."

    demisto.info("commandGetDetectionEvents successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetDetectionRules(client: FncApiClient, args):
    """Get a list of detection rules."""
    demisto.info("CommandGetDetectionRules has been called.")

    endpoint = EndpointKey.GET_RULES

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Rules"
    key = "rules"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Detection Rules."

    demisto.info("commandGetDetectionRules successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandGetDetectionRuleEvents(client: FncApiClient, args):
    """Get a list of the events that matched on a specific rule."""
    demisto.info("CommandGetDetectionRuleEvents has been called.")

    endpoint = EndpointKey.GET_RULE_EVENTS

    rule = args.pop("rule_uuid", "")
    args.update({"rule_id": rule})

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    prefix = "FortiNDRCloud.Detections"
    key = "events"

    if not result:
        raise Exception(f"We receive an invalid response from the server ({result})")

    if key not in result:
        raise Exception(
            f"We receive an invalid response from the server (The response does not contains the key: {key})"
        )

    if not result.get(key):
        return "We could not find any result for Get Detections Rule Events."

    demisto.info("commandGetDetectionRuleEvents successfully completed.")

    return CommandResults(
        outputs_prefix=prefix, outputs_key_field=key, outputs=result.get(key)
    )


def commandCreateDetectionRule(client: FncApiClient, args):
    """Create a new detection rule."""
    demisto.info("commandCreateDetectionRule has been called.")

    endpoint = EndpointKey.CREATE_RULE

    run_accts = [args["run_account_uuids"]]
    dev_ip_fields = [args["device_ip_fields"]]

    args.pop("run_account_uuids")
    args.pop("device_ip_fields")

    args["run_account_uuids"] = run_accts
    args["device_ip_fields"] = dev_ip_fields

    result: Dict[str, Any] = _handle_fnc_endpoint(
        api_client=client, endpoint=endpoint, param=args
    )["response"]

    if "rule" in result:

        demisto.info("commandCreateDetectionRule successfully completed.")

        return CommandResults(readable_output="Rule created successfully")
    else:
        raise Exception(f"Rule creation failed with: {result}")


def commandResolveDetection(client: FncApiClient, args):
    """Resolve a specific detection."""
    demisto.info("commandResolveDetection has been called.")

    endpoint = EndpointKey.RESOLVE_DETECTION

    if "detection_uuid" not in args:
        raise Exception(
            "Detection cannot be resolved: No detection_uuid has been provided."
        )

    if "resolution" not in args:
        raise Exception(
            "Detection cannot be resolved: No resolution has been provided."
        )

    detection = args.pop("detection_uuid", "")
    args.update({"detection_id": detection})
    result = _handle_fnc_endpoint(api_client=client, endpoint=endpoint, param=args)["response"]

    if not result:

        demisto.info("commandResolveDetection successfully completed.")

        return CommandResults(readable_output="Detection resolved successfully")
    else:
        raise Exception(f"Detection resolution failed with: {result}")


def main():
    # get command and args
    command = demisto.command()
    params = demisto.params()

    demisto.info(f"Starting to handle command {command}")

    logged_params = params.copy()
    if "api_key" in logged_params:
        logged_params["api_key"] = "*********"

    demisto.debug(f"Params being passed is {logged_params}")

    args: Dict[str, Any] = demisto.args()

    # initialize common args
    api_key = params.get("api_key", '')
    account_uuid = params.get("account_uuid")
    domain = params.get("domain", None)

    # attempt command execution
    try:
        restClient = FncCortexRestClient()

        fClient = FncClient.get_api_client(
            name=USER_AGENT,
            api_token=api_key,
            domain=domain,
            rest_client=restClient,
            logger=FncCortexLog
        )

        if isinstance(fClient, FncApiClient):
            fnc_api_Client = fClient

        if command == "test-module":
            return_results(commandTestModule(client=fnc_api_Client))

        elif command == "fetch-incidents":
            next_run, incidents = commandFetchIncidents(
                fnc_api_Client, account_uuid, params, demisto.getLastRun()
            )
            # saves next_run for the time fetch-incidents is invoked
            demisto.info("Saving checkpoint in Cortex")
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.info("Sending incidents to Cortex")
            demisto.incidents(incidents)

            demisto.info("Incidents successfully sent.")

        elif command == "fortindr-cloud-get-sensors":
            return_results(commandGetSensors(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-devices":
            return_results(commandGetDevices(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-tasks":
            return_results(commandGetTasks(fnc_api_Client, args))

        elif command == "fortindr-cloud-create-task":
            return_results(commandCreateTask(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-telemetry-events":
            return_results(
                commandGetEventsTelemetry(fnc_api_Client, args)
            )

        elif command == "fortindr-cloud-get-telemetry-network":
            return_results(
                commandGetNetworkTelemetry(fnc_api_Client, args)
            )

        elif command == "fortindr-cloud-get-telemetry-packetstats":
            return_results(
                commandGetPacketstatsTelemetry(fnc_api_Client, args)
            )

        elif command == "fortindr-cloud-get-detections":
            return_results(commandGetDetections(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-detection-events":
            return_results(commandGetDetectionEvents(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-detection-rules":
            return_results(commandGetDetectionRules(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-detection-rule-events":
            return_results(commandGetDetectionRuleEvents(fnc_api_Client, args))

        elif command == "fortindr-cloud-resolve-detection":
            return_results(commandResolveDetection(fnc_api_Client, args))

        elif command == "fortindr-cloud-create-detection-rule":
            return_results(commandCreateDetectionRule(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-entity-summary":
            return_results(commandGetEntitySummary(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-entity-pdns":
            return_results(commandGetEntityPdns(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-entity-dhcp":
            return_results(commandGetEntityDhcp(fnc_api_Client, args))

        elif command == "fortindr-cloud-get-entity-file":
            return_results(commandGetEntityFile(fnc_api_Client, args))

    # catch exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}", str(e)
        )


if __name__ in ("__main__", "__builtin__", "builtins"):

    main()
