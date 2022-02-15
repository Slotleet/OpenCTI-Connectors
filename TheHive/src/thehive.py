import os
from pickle import TRUE
import yaml
import time
import requests
import re
from urllib.parse import urlparse

from datetime import datetime
from dateutil.parser import parse
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
)
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact
from thehive4py.query import Gte, Eq, And

class TheHive:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.thehive_url = get_config_variable(
            "THEHIVE_URL", ["thehive", "url"], config
        )
        self.thehive_api_key = get_config_variable(
            "THEHIVE_API_KEY", ["thehive", "api_key"], config
        )
        self.thehive_import_from_date = get_config_variable(
            "THEHIVE_IMPORT_FROM_DATE",
            ["thehive", "import_from_date"],
            config,
            False,
            datetime.utcfromtimestamp(int(time.time())).strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.telegram_bot_url = get_config_variable(
            "THEHIVE_TELEGRAM_API_KEY", ["thehive", "telegram_api_key"], config
        )

        self.thehive_api = TheHiveApi(self.thehive_url, self.thehive_api_key)

    def run(self):
        self.helper.log_info("Starting TheHive Connector...")
        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_alert_date" in current_state:
                    last_alert_date = current_state["last_alert_date"]
                    self.helper.log_info(
                        "Connector last_alert_date: "
                        + datetime.utcfromtimestamp(last_alert_date).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_alert_date = parse(self.thehive_import_from_date).timestamp()
                    self.helper.log_info("Connector has no last_alert_date")

                self.helper.log_info(
                    "Get new alerts since last run ("
                    + datetime.utcfromtimestamp(last_alert_date).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    + ")"
                )
                query = And(
                    Eq("status", "New"), Gte("createdAt", int(last_alert_date * 1000))
                )
                alerts = self.thehive_api.find_alerts(query=query, range="all").json()
                now = datetime.utcfromtimestamp(timestamp)
                try:
                    for alert in alerts:
                        observables = self.thehive_api.get_alert(alert["_id"]).json()
                        for observable in observables["artifacts"]:
                            if observable["dataType"] == "ip":
                                if self.helper.api.stix_cyber_observable.list(search=observable["data"]):
                                    observables["tags"].append("OPENCTI")
                                    observables["tlp"] = 3
                                    observables["severity"] = 4
                                    updated = self.thehive_api.update_alert(
                                    alert=Alert(json=observables),
                                    alert_id=observables["_id"],
                                    fields=["tags", "tlp", "severity"],
                                    )
                                if updated:
                                    message = "ID:" + observables["id"] + "\n" + observables["title"] + "\n" + observable["data"].replace(".", "[.]") + " has matched our Threat intel"
                                    requests.post(self.telegram_bot_url + "/sendMessage?chat_id=177767479&text=" + message)
                            if observable["dataType"] == "domain" :
                                if self.helper.api.stix_cyber_observable.list(search=observable["data"]):
                                    observables["tags"].append("OPENCTI")
                                    observables["tlp"] = 3
                                    observables["severity"] = 4
                                    updated = self.thehive_api.update_alert(
                                    alert=Alert(json=observables),
                                    alert_id=observables["_id"],
                                    fields=["tags", "tlp", "severity"],
                                    )
                                if updated:
                                    message = "ID:" + observables["id"] + "\n" + observables["title"] + "\n" + observable["data"].replace(".", "[.]") + " has matched our Threat intel"
                                    requests.post(self.telegram_bot_url + "/sendMessage?chat_id=177767479&text=" + message)
                            if observable["dataType"] == "url" :
                                data = urlparse(observable["data"]).netloc
                                if self.helper.api.stix_cyber_observable.list(search=data.replace("www.", "")):
                                    observables["tags"].append("OPENCTI")
                                    observables["tlp"] = 3
                                    observables["severity"] = 4
                                    updated = self.thehive_api.update_alert(
                                    alert=Alert(json=observables),
                                    alert_id=observables["_id"],
                                    fields=["tags", "tlp", "severity"],
                                    )
                                if updated:
                                    message = "ID:" + observables["id"] + "\n" + observables["title"] + "\n" + observable["data"].replace(".", "[.]") + " has matched our Threat intel"
                                    requests.post(self.telegram_bot_url + "/sendMessage?chat_id=177767479&text=" + message)
                            if observable["dataType"] == "hash" :
                                if self.helper.api.stix_cyber_observable.list(search=observable["data"]):
                                    observables["tags"].append("OPENCTI")
                                    observables["tlp"] = 3
                                    observables["severity"] = 4
                                    updated = self.thehive_api.update_alert(
                                    alert=Alert(json=observables),
                                    alert_id=observables["_id"],
                                    fields=["tags", "tlp", "severity"],
                                    )
                                if updated:
                                    message = "ID:" + observables["id"] + "\n" + observables["title"] + "\n" + observable["data"] + " has matched our Threat intel"
                                    requests.post(self.telegram_bot_url + "/sendMessage?chat_id=177767479&text=" + message)
                except Exception as e:
                    self.helper.log_error(str(e))
                # Store the current timestamp as a last run
                message = (
                    "Connector successfully run \n status : Nothing found in new alerts storing last_run as "
                    + str(timestamp)
                )
                self.helper.log_info(message)
                current_state = self.helper.get_state()
                if current_state is None:
                    current_state = {"last_alert_date": timestamp}
                else:
                    current_state["last_alert_date"] = timestamp
                self.helper.set_state(current_state)
                time.sleep(60)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        theHiveConnector = TheHive()
        theHiveConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
