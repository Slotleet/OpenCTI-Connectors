# OpenCTI Template Connector

<!-- 
General description of the connector 
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

# Tor-Exit-Node Connector 

The Tor-Exit-Node Connector can be used to imoport exit node related to tor network from ```https://check.torproject.org/exit-addresses``` Directly.

## Installation

### Requirements

- OpenCTI Platform >= 5.1.4

### Configuration

| Config Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `exit_node_url`                        | `TOR_EXIT_NODE_URL`                       | Yes          | The URL of the Tor-Exit-Node Addresses.                                                                                                                           |
| `labels`                      | `TOR_LABELS`                     | Yes          | Indicators label.                                                                                |
| `interval`                       | `TOR_INTERVAL`                      | Yes          | Interval in days before a new import is considered.                                                                                         |

### Debugging ###

<!-- Any additional information to help future users debug and report detailed issues concerning this connector --> 

### Additional information

<!-- 
Any additional information about this connector 
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->

