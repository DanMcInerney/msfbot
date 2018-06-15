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
Async is working and error handling for when sessions die unexepectedly is in place. I think the error handling should probably be DRY'd out. But right now the script will start, wait for a session to be found, do recon on that session and if that session is domain-joined, it'll do domain recon like getting domain controllers and domain admins. 

#### To do
* domain privesc
** ms14-068? that might be hard to implement
** GPP
* mimikatz boxes with admin shells
* basic privesc if user is not admin
* get spreading function working (include AMSI bypass)
* Long-term: incorporate BloodHound graph CSV ingestion for more efficient attack pathing
