import os
import subprocess
from charmhelpers.core import hookenv


def ping(input):
    #hookenv.log("unit is: " + input[0], 'INFO')
    #hookenv.log("ip is: " + input[1], 'INFO')
    response = os.system("ping -c 1 " + input + " > /dev/null 2>&1")
    if response == 0:
        return 0
    else:
        return 1


def check_nodes(nodes):
    no_ping = check_ping(nodes)
    no_dns = check_dns(nodes)
    hookenv.log("NO DNS IS: " + str(no_dns))
    try:
        dns_status
    except NameError:
        dns_status = ''

    if not no_ping:
        no_ping = 'ALL ICMP OK'
    else:
        no_ping = 'ICMP DOWN: ' + str(no_ping)

    if no_dns == ([], [], []):
        dns_status = 'ALL DNS OK'
    else:
        no_rev = no_dns[0]
        no_fwd = no_dns[1]
        no_match = no_dns[2]
        if no_match != []:
            dns_status = 'NO DNS MATCH: ' + str(no_match)
        else:
            if not no_rev:
                no_rev = 'REV DNS OK'
            else:
                no_rev = 'NO REV DNS: ' + str(no_rev)
                if no_fwd != []:
                    no_fwd = ', NO FWD DNS: ' + str(no_fwd)
                elif no_fwd == []:
                    no_fwd = ''
        dns_status = dns_status + str(no_rev) + str(no_fwd)

        no_dns = dns_status
    #if not no_rev_dns:
    #    no_rev_dns = 'OK'

    check_status = no_ping + ', ' + str(dns_status)
    hookenv.status_set('active', check_status)


def check_ping(nodes):
    try:
        unreachable
    except NameError:
        unreachable = []
    for node in nodes:
        unit_id = node[0].split('/')[1]
        if ping(node[1]) == 1:
            if unit_id not in unreachable:
                unreachable.append(unit_id)
        else:
            if unit_id in unreachable:
                unreachable.remove(unit_id)

    return unreachable


def check_dns(nodes):
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
    for node in nodes:
        hookenv.log("ALL NODES: " + str(nodes))
        hookenv.log("DNS for node: " + str(node))
        ip = node[1]
        unit_id = node[0].split('/')[1]
        hookenv.log("DNS for ip: " + ip)
        reverse, r_stderr = dns(ip, reverse=True)
        hookenv.log("REVERSE: " + str(reverse) + str(r_stderr))
        if r_stderr:
            if unit_id not in norev:
                norev.append(unit_id)
            continue
        else:
            if unit_id in norev:
                norev.remove(unit_id)
            forward, f_stderr = dns(reverse, reverse=False)
            hookenv.log("FORWARD: " + str(forward) + str(f_stderr))
            if f_stderr:
                if unit_id not in nofwd:
                    nofwd.append(unit_id)
            else:
                if unit_id in nofwd:
                    nofwd.remove(unit_id)
                if ip != forward:
                    if unit_id not in nomatch:
                        nomatch.append(unit_id)
    return norev, nofwd, nomatch


def dns(input, reverse=None):
    hookenv.log("input: " + str(input))
    if reverse:
        cmd = '/usr/bin/dig -x ' + input + ' +short +time=3 +tries=1'
        hookenv.log(cmd, 'INFO')
        try:
            result = subprocess.check_output(cmd, shell=True)\
                .decode('utf-8').rstrip()
            stderr = 0
        except subprocess.CalledProcessError as exc:
            result = "REV ERR" + str(exc.returncode)
            stderr = exc.returncode
        return result, stderr
    else:
        cmd = '/usr/bin/dig ' + input + ' +short +time=3 +tries=1'
        hookenv.log(cmd, 'INFO')
        try:
            result = subprocess.check_output(cmd, shell=True)\
                .decode('utf-8').rstrip()
            stderr = 0
        except subprocess.CalledProcessError as exc:
            result = "FWD ERR" + str(exc.returncode)
            stderr = exc.returncode
        return result, stderr
