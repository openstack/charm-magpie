#!/usr/bin/env python3
# Copyright 2023 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm for Magpie."""

import json
import logging
import os
from typing import Dict, List

import ops
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from magpie_tools import (
    CollectDataConfig,
    DnsConfig,
    HostWithIp,
    Iperf,
    PingConfig,
    check_dns,
    check_ping,
    collect_local_data,
    configure_lldpd,
)
from ops.model import ActiveStatus

logger = logging.getLogger(__name__)


class MagpieCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.iperf_action, self._on_iperf_action)
        self.framework.observe(self.on.info_action, self._on_info_action)
        self.framework.observe(self.on.ping_action, self._on_ping_action)
        self.framework.observe(self.on.dns_action, self._on_dns_action)
        self.framework.observe(self.on.update_status, self._on_update_status)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.magpie_relation_changed, self._on_peers_changed)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

        self._grafana_agent = COSAgentProvider(
            self,
            metrics_endpoints=[
                {"path": "/metrics", "port": 80},
            ],
            dashboard_dirs=["./src/grafana_dashboards"],
        )

    def _on_install(self, event):
        os.system("apt update")
        os.system("apt install -y iperf")

    def _on_start(self, event):
        iperf = Iperf(self.model.name, self.app.name, self.model.unit.name, with_prometheus=False)
        cidr: str = self.config.get("iperf_listen_cidr")  # type: ignore
        fallback_bind_address: str = str(self.model.get_binding("magpie").network.bind_address)  # type: ignore
        iperf.listen(cidr, fallback_bind_address)
        self._on_update_status(event)
        configure_lldpd()

    def _on_config_changed(self, event):
        pass

    def _on_peers_changed(self, event):
        self._on_update_status(event)

    def _get_peer_units(self) -> Dict[ops.model.Unit, dict]:  # unit -> unit relation data
        units = {}
        for relation in self.model.relations["magpie"]:
            for unit in relation.units:  # Set[Unit]
                units[unit] = relation.data[unit]
        return units

    def _on_update_status(self, event):
        n_peers = len(self._get_peer_units())
        self.unit.status = ActiveStatus(f'Ready, with {n_peers} peer{"s" if n_peers != 1 else ""}')

    def _on_iperf_action(self, event):
        total_run_time = event.params["total-run-time"]
        batch_time = event.params["batch-time"]
        concurrency_progression = [int(i) for i in event.params["concurrency-progression"].split()]
        filter_units = event.params["units"].split()
        min_speed = event.params["min-speed"]
        with_prometheus = len(self.model.relations["cos-agent"]) > 0

        units = []
        for host_with_ip in self._get_peer_addresses():
            if not filter_units or host_with_ip.name in filter_units:
                units.append(host_with_ip)

        iperf = Iperf(self.model.name, self.app.name, self.model.unit.name, with_prometheus)
        results = iperf.batch_hostcheck(
            units,
            total_run_time,
            batch_time,
            concurrency_progression,
            min_speed,
        )
        data = json.dumps(results, indent=2)
        event.set_results({"output": data})

    def _on_info_action(self, event):
        local_ip: str = str(self.model.get_binding("magpie").network.ingress_addresses[0])  # type: ignore
        data = json.dumps(
            collect_local_data(
                CollectDataConfig(
                    required_mtu=event.params["required-mtu"],
                    bonds_to_check=event.params["bonds-to-check"],
                    lacp_passive_mode=event.params["lacp-passive-mode"],
                    local_ip=local_ip,
                )
            ),
            indent=2,
        )
        event.set_results({"output": data})

    def _get_peer_addresses(self) -> List[HostWithIp]:
        addresses = []
        for unit, data in self._get_peer_units().items():
            ip = data.get("ingress-address")
            if ip:
                addresses.append(HostWithIp(name=unit.name, ip=ip))
        return addresses

    def _on_ping_action(self, event):
        data: Dict[str, str] = check_ping(
            self._get_peer_addresses(),
            PingConfig(
                timeout=event.params["timeout"],
                tries=event.params["tries"],
                interval=event.params["interval"],
                required_mtu=event.params["required-mtu"],
            ),
        )
        event.set_results({"output": json.dumps(data, indent=2)})

    def _on_dns_action(self, event):
        data = check_dns(
            self._get_peer_addresses(),
            DnsConfig(
                server=event.params["server"],
                tries=event.params["tries"],
                timeout=event.params["timeout"],
            ),
        )
        event.set_results({"output": json.dumps(data, indent=2)})


if __name__ == "__main__":  # pragma: nocover
    ops.main(MagpieCharm)  # type: ignore
