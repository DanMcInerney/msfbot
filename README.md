msf-netpwn
------
PROJECT IN PROGRESS. Waits for a Metasploit shell on an Active Directory environment then automatically privilege escalates to domain admin.

#### Installation
This install is only tested on Kali. Clone into the repo, enter the cloned folder and run install.sh. Open a new terminal and start metasploit with the included rc file. Back in the original terminal continue by entering the newly-created virtual environment with pipenv. Finally, enter the included msfrpc/ folder and install it now that you're inside the virtual environment.

```
git clone https://github.com/DanMcInerney/msf-autopwn
cd msf-autopwn
In a new terminal: msfconsole -r msfrpc.rc
pipenv install --three
pipenv shell
cd msfrpc && python2 setup install && cd ..
```

#### Usage
```./msf-netpwn.py ```

#### Current progress
Listens for session, performs AV-resistant domain recon (with wmic), lateral spread, does mimikatz/hashdump, does lateral movement with psexec_psh.

#### To do
* Needs a lot more testing, only have a couple windows labs to test this in
* Need to change lateral movement to something more red teamy than psexec_psh, maybe use the LOLbin extexport.exe to remotely load a shelltered payload on remote box using wmic?
* Add --stealth flag. Have it work for speed normally unless this switch is given and then use red team tactics instead.
