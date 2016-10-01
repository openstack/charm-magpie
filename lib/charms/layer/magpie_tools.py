#!/usr/bin/env python

import os
import subprocess
import re
from charmhelpers.core import hookenv


def ping(input, ping_time, ping_tries):
    ping_string = "ping -c {} -w {} {} > /dev/null 2>&1"\
        .format(ping_tries, ping_time, input)
    hookenv.log('Ping command: {}'.format(ping_string), 'DEBUG')
    response = os.system(ping_string)
    if response == 0:
        return 0
    else:
        return 1


def check_local_hostname():
    local_hostname = subprocess.check_output('hostname', shell=True)\
        .decode('utf-8').rstrip()
    lookup_cmd = "getent hosts {}'".format(local_hostname)
    hookenv.log('Looking up local hostname: {}'.format(local_hostname))
    try:
        result = subprocess.check_output(lookup_cmd, shell=True)\
            .decode('utf-8').rstrip()
        result = ''
        stderr = 0
    except subprocess.CalledProcessError as exc:
        result = local_hostname
        stderr = exc.returncode
    return result, stderr


def check_nodes(nodes):
    cfg = hookenv.config()
    cfg_check_local_hostname = cfg.get('check_local_hostname')
    if cfg_check_local_hostname:
        no_hostname = check_local_hostname()
        if no_hostname[0] == '':
            no_hostname = ', local hostname ok'
            hookenv.log('Local hostname lookup OK: {}'.format(str(no_hostname)), 'INFO')
        else:
            no_hostname = ', local hostname failed: '
            hookenv.log('Local hostname lookup FAILED: {}'format(str(no_hostname)), 'ERROR')

    no_ping = check_ping(nodes)
    no_dns = check_dns(nodes)
    hookenv.log("Units with DNS problems: " + str(no_dns))
    try:
        dns_status
    except NameError:
        dns_status = ''

    if not no_ping:
        no_ping = 'icmp ok'
    else:
        no_ping = 'icmp failed: ' + str(no_ping)

    if no_dns == ([], [], []):
        dns_status = ', dns ok'
    else:
        no_rev = no_dns[0]
        no_fwd = no_dns[1]
        no_match = no_dns[2]
        if no_match != []:
            dns_status = ', match dns failed: ' + str(no_match)
        else:
            if no_rev:
                no_rev = ', rev dns failed: ' + str(no_rev)
                if no_fwd != []:
                    no_fwd = ', fwd dns failed: ' + str(no_fwd)
                elif no_fwd == []:
                    no_fwd = ''
        if no_rev == []:
            no_rev = ''
        if no_fwd == []:
            no_fwd = ''
        dns_status = '{}{}{}'\
            .format(dns_status, str(no_rev), str(no_fwd))

    if check_local_hostname:
        check_status = '{}{}{}'.format(no_ping, str(no_hostname), str(dns_status))
    else:
        check_status = '{}{}'.format(no_ping, str(dns_status))

    if 'failed' in check_status:
        workload = 'blocked'
    else:
        workload = 'active'
    hookenv.status_set(workload, check_status)
    reactive_state = {'icmp': no_ping, 'dns': dns_status}
    return reactive_state


def check_ping(nodes):
    cfg = hookenv.config()
    ping_time = cfg.get('ping_timeout')
    ping_tries = cfg.get('ping_tries')
    try:
        unreachable
    except NameError:
        unreachable = []
    for node in nodes:
        unit_id = node[0].split('/')[1]
        hookenv.log('Pinging unit_id: ' + str(unit_id), 'INFO')
        if ping(node[1], ping_time, ping_tries) == 1:
            hookenv.log('Ping FAILED for unit_id: ' + str(unit_id), 'ERROR')
            if unit_id not in unreachable:
                unreachable.append(unit_id)
        else:
            hookenv.log('Ping OK for unit_id: ' + str(unit_id), 'INFO')
            if unit_id in unreachable:
                unreachable.remove(unit_id)

    return unreachable


def check_dns(nodes):
    cfg = hookenv.config()
    dns_server = cfg.get('dns_server')
    dns_tries = cfg.get('dns_tries')
    dns_time = cfg.get('dns_time')
    try:
        norev
    except NameError:
        norev = []
    try:
        nofwd
    except NameError:
        nofwd = []
    try:
        nomatch
    except NameError:
        nomatch = []
    hookenv.log("DNS (ALL NODES): {}".format(nodes))
    for node in nodes:
        ip = node[1]
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            hookenv.log("private-address appears to be a hostname: {},"
                        " attempting forward lookup...", 'WARN')
            ip = forward_dns(ip, dns_server, dns_tries, dns_time)[0]
        else:
            hookenv.log('private-address appears to be an IP', 'INFO')
        unit_id = node[0].split('/')[1]
        hookenv.log("Reverse lookup for ip: {}, node: {},"
                    " unit_id: {}".format(ip, node[0], unit_id), 'INFO')
        reverse, r_stderr = reverse_dns(ip, dns_server, dns_tries, dns_time)
        hookenv.log("Reverse result for unit_id: {}, hostname: {},"
                    " exitcode: {}".format(unit_id,  str(reverse),
                                           str(r_stderr)))
        if r_stderr:
            hookenv.log("Reverse FAILED for"
                        " unit_id: {}".format(unit_id), 'ERROR')
            if unit_id not in norev:
                norev.append(unit_id)
            continue
        else:
            hookenv.log("Reverse OK for unit_id: {}".format(unit_id), 'INFO')
            if unit_id in norev:
                norev.remove(unit_id)
            hookenv.log("Forward lookup for hostname: {}, node: {},"
                        " unit_id: {}".format(str(reverse), node[0], unit_id),
                        'INFO')
            forward, f_stderr = forward_dns(reverse, dns_server,
                                            dns_tries, dns_time)
            hookenv.log("Forward result for unit_id: {}, ip: {},"
                        " exitcode: {}".format(unit_id,  forward,
                                               str(f_stderr)))
            if f_stderr:
                hookenv.log("Forward FAILED for"
                            " unit_id: {}".format(unit_id), 'ERROR')
                if unit_id not in nofwd:
                    nofwd.append(unit_id)
            else:
                hookenv.log("Forward OK for"
                            " unit_id: {}".format(unit_id), 'INFO')
                if unit_id in nofwd:
                    nofwd.remove(unit_id)
                if ip != forward:
                    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
                                    forward):
                        forward = "Can not resolve hostname to IP {}"\
                                  .format(repr(forward))
                    hookenv.log("Original IP and Forward MATCH FAILED for"
                                " unit_id: {}, Original: {}, Forward: {}"
                                .format(unit_id, ip, forward), 'ERROR')
                    if unit_id not in nomatch:
                        nomatch.append(unit_id)
                else:
                    hookenv.log("Original IP and Forward MATCH OK for unit_id:"
                                " {}, Original: {}, Forward: {}"
                                .format(unit_id, ip, forward),
                                'INFO')
                    if unit_id in nomatch:
                        nomatch.remove(unit_id)

    return norev, nofwd, nomatch


def reverse_dns(input, dns_server, tries, timeout):
    cmd = '/usr/bin/dig -x ' + input + ' +short +tries={} +time={}'\
        .format(tries, timeout)
    if dns_server:
        cmd = '{} @{}'.format(cmd, dns_server)
    hookenv.log('DNS Reverse command: {}'.format(cmd), 'DEBUG')
    try:
        result = subprocess.check_output(cmd, shell=True)\
            .decode('utf-8').rstrip()
        stderr = 0
    except subprocess.CalledProcessError as exc:
        result = "Reverse DNS lookup error: " + str(exc.output)
        stderr = exc.returncode
    if result == '':
        result = 'No reverse response'
        stderr = 1
    return result, stderr


def forward_dns(input, dns_server, tries, timeout):
    cmd = '/usr/bin/dig ' + input + ' +short +tries={} +time={}'\
        .format(tries, timeout)
    if dns_server:
        cmd = '{} @{}'.format(cmd, dns_server)
    hookenv.log('DNS Forward command: {}'.format(cmd), 'DEBUG')
    try:
        result = subprocess.check_output(cmd, shell=True)\
            .decode('utf-8').rstrip()
        stderr = 0
    except subprocess.CalledProcessError as exc:
        result = "Forward DNS lookup error: " + str(exc.output)
        stderr = exc.returncode
    if result == '':
        result = 'No forward response'
        stderr = 1
    return result, stderr
