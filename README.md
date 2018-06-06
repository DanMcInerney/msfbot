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
