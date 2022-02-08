import os
import yaml
import time
import urllib.request
import ssl
import certifi
import re

from stix2 import Bundle, ExternalReference, TLP_WHITE
from datetime import datetime
from dateutil.parser import parse
from pycti import (
    SimpleObservable,
    OpenCTIStix2Utils,
    OpenCTIConnectorHelper,
    get_config_variable,
)


class TorExitNode:
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
        self.tor_url = get_config_variable(
            "TOR_EXIT_NODE_URL", ["tor", "exit_node_url"], config
        )
        self.create_indicators = get_config_variable(
            "TOR_CREATE_INDICATORS", ["tor", "create_indicators"], config
        )
        self.tor_labels = get_config_variable("TOR_LABELS", ["tor", "labels"], config)
        self.interval = get_config_variable(
            "TOR_INTERVAL", ["tor", "interval"], config, True
        )
        self.identity = self.helper.api.identity.create(
            type="Organization",
            name="Tor Project",
            description="Tor Exit Nodes are the gateways where encrypted Tor traffic hits the Internet. This means an exit node can be abused to monitor Tor traffic (after it leaves the onion network).",
        )

    def get_interval(self):
        return int(self.interval) * 60 * 60 * 24

    def next_run(self, seconds):
        return

    def flatten(self, t):
        return [item for sublist in t for item in sublist]

    def run(self):
        self.helper.log_info("Starting TorExitNode Connector...")
        external_reference = ExternalReference(
            source_name="Tor Project",
            url="https://torproject.org/",
            description="free and open-source software for enabling anonymous communication.",
        )

        while True:
            try:
                # Get the current timestamp and check
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")
                # If the last_run is more than interval-1 day
                if last_run is None or (
                    (timestamp - last_run) > ((int(self.interval) - 1) * 60 * 60 * 24)
                ):
                    self.helper.log_info("Connector will run!")
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "TorExitNode run @ " + now.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )
                    try:
                        ips = []  # Empty lists for ips
                        response = urllib.request.urlopen(
                            self.tor_url,
                            context=ssl.create_default_context(cafile=certifi.where()),
                        )
                        resp = response.read()
                        replace_space = resp.decode("UTF-8").replace(" ", ",")
                        replace_newline = replace_space.replace("\n", ",")
                        replace_space_with_comma = replace_newline.replace(" ", ",")
                        split_lines = replace_space_with_comma.split(",")
                        for i in split_lines:
                            ips.append(
                                re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", i)
                            )
                        clear_lists = [ele for ele in ips if ele != []]
                        flatten = self.flatten(clear_lists)
                        bundle_objects = []
                        for ipaddress in flatten:

                            stix_observable = SimpleObservable(
                                id=OpenCTIStix2Utils.generate_random_stix_id(
                                    "x-opencti-simple-observable"
                                ),
                                key="IPv4-Addr.value",
                                value=ipaddress,
                                description="VX Vault URL",
                                x_opencti_score=100,
                                labels=["TorExitNode"],
                                object_marking_refs=[TLP_WHITE],
                                created_by_ref=self.identity["standard_id"],
                                x_opencti_create_indicator=True,
                                external_references=[external_reference],
                            )
                            bundle_objects.append(stix_observable)
                        bundle = Bundle(
                            objects=bundle_objects, allow_custom=True
                        ).serialize()
                        self.helper.send_stix2_bundle(
                            bundle,
                            update=True,
                            work_id=work_id,
                        )
                    except Exception as e:
                        self.helper.log_error(str(e))
                        # Store the current timestamp as a last run
                    message = "Connector successfully run, storing last_run as " + str(
                        timestamp
                    )
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        TorExitNodeConnector = TorExitNode()
        TorExitNodeConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
