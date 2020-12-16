#!/usr/bin/env python3

import argparse


def status_decoder(status):
    decoded_status = [(status >> bit) & 1 for bit in range(8 - 1, -1, -1)]
    decoded_status.reverse()
    return decoded_status


def main(args):
    try:
        port_state = int(args.port_state)
    except (TypeError, ValueError):
        raise Exception('port_state has to be integer')

    if args.second_port_state:
        try:
            second_port_state = int(args.second_port_state)
        except (TypeError, ValueError):
            raise Exception('second_port_state has to be integer')
    else:
        second_port_state = None

    states = {
        0: {
            "name": "LACP Activity",
            1: "Active LACP",
            0: "Passive LACP"
        },
        1: {
            "name": "LACP Timeout",
            1: "Short",
            0: "Long"
        },
        2: {
            "name": "Aggregability",
            1: "Aggregatable",
            0: "Individual",
        },
        3: {
            "name": "Synchronization",
            1: "Link in sync",
            0: "Link out of sync"
        },
        4: {
            "name": "Collecting",
            1: "Ingress traffic: Accepting",
            0: "Ingress traffic: Rejecting",
        },
        5: {
            "name": "Distributing",
            1: "Egress traffic: Sending",
            0: "Egress trafic: Not sending"
        },
        6: {
            "name": "Is Defaulted",
            1: "Defaulted settings",
            0: "Settings are received from LACP PDU"
        },
        7: {
            "name": "Link Expiration",
            1: "Yes",
            0: "No"
        }

    }
    status = status_decoder(port_state)

    for i, entry in enumerate(status):
        status_string = "{0}: {1}".format(states[i]['name'], states[i][entry])
        if second_port_state:
            second_status = status_decoder(second_port_state)
            if entry == second_status[i]:
                status_string = "(Equal for both ports) {0}".format(
                    status_string)
            else:
                status_string += " (Port 1) / {0} (Port 2)".format(
                    states[i][second_status[i]])
        print(status_string)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("port_state")
    parser.add_argument("second_port_state", nargs='?', default=None)
    main(parser.parse_args())
