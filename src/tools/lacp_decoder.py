#!/usr/bin/env python3

# Copyright 2020 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tool to decode and help debug LACP port states.

See README.md for more information.
"""

import argparse


def status_decoder(status):
    """Extract the bits from the status integer into a list we can work with easier."""
    decoded_status = [(status >> bit) & 1 for bit in range(8 - 1, -1, -1)]
    decoded_status.reverse()
    return decoded_status


def main(args):
    """Run the application."""
    try:
        port_state = int(args.port_state)
    except (TypeError, ValueError):
        raise Exception("port_state has to be integer")

    if args.second_port_state:
        try:
            second_port_state = int(args.second_port_state)
        except (TypeError, ValueError):
            raise Exception("second_port_state has to be integer")
    else:
        second_port_state = None

    states = {
        0: {"name": "LACP Activity", 1: "Active LACP", 0: "Passive LACP"},
        1: {"name": "LACP Timeout", 1: "Short", 0: "Long"},
        2: {
            "name": "Aggregability",
            1: "Aggregatable",
            0: "Individual",
        },
        3: {"name": "Synchronization", 1: "Link in sync", 0: "Link out of sync"},
        4: {
            "name": "Collecting",
            1: "Ingress traffic: Accepting",
            0: "Ingress traffic: Rejecting",
        },
        5: {
            "name": "Distributing",
            1: "Egress traffic: Sending",
            0: "Egress traffic: Not sending",
        },
        6: {
            "name": "Is Defaulted",
            1: "Defaulted settings",
            0: "Settings are received from LACP PDU",
        },
        7: {"name": "Link Expiration", 1: "Yes", 0: "No"},
    }
    status = status_decoder(port_state)

    for i, entry in enumerate(status):
        status_string = "{0}: {1}".format(states[i]["name"], states[i][entry])
        if second_port_state:
            second_status = status_decoder(second_port_state)
            if entry == second_status[i]:
                status_string = "(Equal for both ports) {0}".format(status_string)
            else:
                status_string += " (Port 1) / {0} (Port 2)".format(states[i][second_status[i]])
        print(status_string)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("port_state")
    parser.add_argument("second_port_state", nargs="?", default=None)
    main(parser.parse_args())
