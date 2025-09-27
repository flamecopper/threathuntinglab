# Threat Hunting Professional v2 - Complete Step-by-Step Lab Manual

## Lab 1: IOCs & YARA Rule Creation

### Network Setup
- **Lab Network:** `172.15.161.0/24`
- **Your IP:** `172.16.151.50`
- **Credentials:** `elshunter:ahuntingweg0!`
- **Target Sample:** `C:\Users\elshunter\Desktop\malware – don't run\END OF YEAR FINANCIALS REPORT.exe`

### Tools Required
- WINMD5Free
- Strings.exe
- Mandiant IOC Editor
- Mandiant Redline
- YARA (yara-3.6.2-win64)

### Step-by-Step Execution

#### Task 1: Extract MD5 Hash
1. **Launch WINMD5Free**
2. **Browse and select malware sample**
3. **Copy the resulting MD5 hash**

#### Task 2: Extract Strings
```cmd
"C:\Users\elshunter\Desktop\tools\strings.exe" "C:\Users\elshunter\Desktop\malware – don't run\END OF YEAR FINANCIALS REPORT.exe" > "C:\Users\elshunter\Desktop\strings.txt"
```

#### Task 3: Create IOC in Mandiant IOC Editor
1. **Open Mandiant IOC Editor**
2. **Create new IOC**
3. **Add Items:**
   - File MD5 hash (from Task 1)
   - File size (get from file properties)
   - 2 interesting strings (from strings.txt)

#### Task 4: Test IOC with Redline
1. **Open Mandiant Redline**
2. **Create IOC Search Collector**
3. **Import your IOC file**
4. **Enable "Strings Collection"**
5. **Save collector to HUNT folder**
6. **Run as Administrator:**
   ```cmd
   cd C:\Users\elshunter\Desktop\HUNT
   RunRedlineAudit.bat
   ```
7. **Open analysis session and check IOC Reports tab**

#### Task 5: Create YARA Rule
1. **Navigate to:** `C:\Users\elshunter\Desktop\tools\yara-3.6.2-win64\rules`
2. **Edit skeleton file `eoyfr.yar`:**
   ```yara
   rule eoyfr_malware {
       meta:
           description = "End of Year Financials Report malware"
       strings:
           $md5 = "your_md5_hash_here"
           $string1 = "first_extracted_string"
           $string2 = "second_extracted_string"
       condition:
           2 of them
   }
   ```
3. **Test YARA rule:**
   ```cmd
   cd C:\Users\elshunter\Desktop\tools\yara-3.6.2-win64
   Yara64.exe .\rules\eoyfr.yar "C:\Users\elshunter\Desktop\malware – don't run"
   ```
4. **If no matches, modify condition to `1 of them`**

#### Task 6: Handle Unicode Strings
- For Unicode strings, add `fullword wide` modifier:
  ```yara
  $unicode_string = "allyourbasearebelongtous" fullword wide
  ```

---

## Lab 2-3: Memory Analysis with Redline & Volatility

### Network Setup
- **Hunting Workstation:** `172.16.151.50` (elshunter:ahuntingweg0!)
- **Target Machine:** `172.16.151.75` (elshunter:ahuntingweg0!)

### Redline Memory Analysis Procedure

#### Task 1: Analyze Pre-existing Memory Image
1. **Open Mandiant Redline**
2. **Load AnalysisSession1.mans**
3. **Navigate to "Analysis Data" > "Processes"**
4. **Look for suspicious processes:**
   - Check "Redlined" processes (highlighted in red)
   - Focus on: conhost.exe, Meterpreter_Payload_Detection.exe, svchost.exe
5. **Examine `1sass.exe` (note the typo):**
   - **Wrong spelling:** Should be `lsass.exe`
   - **Wrong parent:** Should be `wininit.exe`
   - **Wrong path:** Should be `C:\Windows\system32`
   - **Wrong user:** Should be `SYSTEM`
   - **Network connections:** Check for connections to `172.16.151.133`

#### Task 2: Timeline Analysis
1. **Go to Timeline view**
2. **Search for "1sass"**
3. **Trace execution sequence:**
   - `hh.exe` executed `1sass.chm`
   - `1sass.chm` spawned `1sass.exe`

#### Task 3: Live Memory Collection
1. **Create Standard Collector with "Acquire Memory Image"**
2. **Deploy to target via network share:**
   ```cmd
   \\172.16.151.75\C$\HUNT\
   ```
3. **Run on target as administrator:**
   ```cmd
   RunRedlineAudit.bat
   ```
4. **Analyze new session following above steps**

### Volatility Memory Analysis

#### Task 1: Profile Identification
```bash
volatility -f <memory_image>.vmem imageinfo
```
**Expected output:** Profile suggestions (use highest confidence, e.g., WinXPSP2x86)

#### Task 2: Process Analysis
```bash
# List running processes
python vol.py -f apta.vmem --profile=WinXPSP2x86 pslist

# Scan for hidden processes
python vol.py -f apta.vmem --profile=WinXPSP2x86 psscan

# Cross-view process analysis
python vol.py -f apta.vmem --profile=WinXPSP2x86 psxview
```

#### Task 3: Network Connections
```bash
python vol.py -f apta.vmem --profile=WinXPSP2x86 connscan
```

#### Task 4: Code Injection Detection
```bash
# Detect injected code
python vol.py -f apta.vmem --profile=WinXPSP2x86 malfind -p 856

# Check API hooks
python vol.py -f apta.vmem --profile=WinXPSP2x86 apihooks -p 856
```

#### Task 5: Rootkit Detection (APTB Analysis)
```bash
# Check for SSDT hooks
python vol.py -f aptb.vmem --profile=WinXPSP2x86 ssdt | select-string -NotMatch -Pattern 'ntoskrnl|win32k'

# List modules
python vol.py -f aptb.vmem --profile=WinXPSP2x86 modules

# Extract malicious driver
mkdir output
python vol.py -f aptb.vmem --profile=WinXPSP2x86 moddump -b 0xff0d1000 --dump-dir="output"
```

**Expected Findings:**
- **APTA:** Zeus malware with injected code in svchost.exe (PID 856)
- **APTB:** Black Energy rootkit with 14 hooked SSDT functions

---

## Lab 4: Empire Detection

### Network Setup
- **child-dc01:** `10.100.10.253` (VNC: vnc@3L$-CHILDL0c@l)
- **UATSERVER:** `10.100.11.150` (Domain: ELS-CHILD\Administrator)

### Detection Tools Setup

#### Task 1: EIF (Evil Inject Finder) Detection
1. **VNC to child-dc01 (10.100.10.253)**
2. **Open PowerShell as Administrator**
3. **Navigate to Hunting Empire folder on Desktop**
4. **Execute EIF Parser:**
   ```powershell
   cd "C:\Users\Administrator\Desktop\Hunting Empire\Detection Method 1 - EIF Parser-master"
   .\eif_parser.ps1 -ComputerName uatserver.els-child.els.local -EIF_Path "C:\Users\Administrator\Desktop\Hunting Empire\Detection Method 1 - EIF Parser-master\EvilInjectFinder64.exe"
   ```
5. **Check results in:** `C:\Users\Administrator\Desktop\Hunting Empire\Detection Method 1 - EIF Parser-master\Results`

#### Task 2: Get-InjectedThread Detection
1. **Copy Get-InjectedThread.ps1 to UATSERVER:**
   ```powershell
   # From child-dc01
   Copy-Item "C:\Users\Administrator\Desktop\Hunting Empire\Detection Method 2\Get-InjectedThread.ps1" "\\uatserver.els-child.els.local\C$\"
   ```
2. **Connect via PSRemoting:**
   ```powershell
   New-PSSession –Name PSC1 –ComputerName uatserver.els-child.els.local
   Enter-PSSession –Name PSC1
   cd C:\
   Import-Module .\Get-InjectedThread.ps1
   Get-InjectedThread
   ```

#### Task 3: NorkNork Persistence Detection
1. **Copy NorkNork.exe to UATSERVER:**
   ```powershell
   Copy-Item "C:\Users\Administrator\Desktop\Hunting Empire\Detection Method 3\NorkNork-master\NorkNork.exe" "\\uatserver.els-child.els.local\C$\"
   ```
2. **Execute via PSRemoting:**
   ```powershell
   New-PSSession –Name PSC2 –ComputerName uatserver.els-child.els.local
   Enter-PSSession –Name PSC2
   cd C:\
   .\NorkNork.exe
   ```

### Expected Detection Results
- **EIF:** PowerShell DLLs in explorer.exe (System.Management.Automation)
- **Get-InjectedThread:** Injected threads in explorer.exe
- **NorkNork:** Base64 encoded Empire stager in registry with C2 URL format (login/process.php)

---

## Lab 5: Responder/Inveigh Detection

### Network Setup
- **UATSERVER:** `10.100.11.150` (VNC: vnc@3L$-CHILDL0c@l)

### Detection Methods

#### Task 1: CredDefense ResponderGuard Detection
1. **VNC to UATSERVER**
2. **Open PowerShell as Administrator**
3. **Navigate to Case 1 folder on Desktop**
4. **Execute ResponderGuard:**
   ```powershell
   powershell -ep bypass
   Import-Module .\ResponderGuard.ps1
   Invoke-ResponderGuard –CidrRange 10.100.11.0/24 –LoggingEnabled -HoneyTokenSeed
   ```

#### Task 2: Honey Credentials Monitoring
1. **Clear Security logs in Event Viewer**
2. **In separate PowerShell window:**
   ```powershell
   powershell -ep bypass
   Import-Module .\Find-HoneyAccount.ps1
   Find-HoneyAccount HoneyUser
   ```
3. **Run ResponderGuard again (from Task 1)**
4. **Monitor for Event ID 4648 usage**

#### Task 3: Sysmon Network Analysis
1. **Clear Sysmon Operational logs**
2. **Simulate SMB connection:** 
   - Right-click Windows taskbar → Run → `\\10.100.11.102`
3. **Execute detection script:**
   ```powershell
   powershell -ep bypass
   Import-Module .\Get-WinEventData.ps1
   .\Find-UntrustedSMBConnections.ps1
   ```

#### Task 4: PowerShell Script Block Logging
1. **Enable registry key for script block logging**
2. **Execute Inveigh:**
   ```powershell
   powershell -ep bypass
   Import-Module .\Invoke-Inveigh.ps1
   Invoke-Inveigh -IP 10.100.11.150
   ```
3. **Check Event Viewer:** Applications and Services Logs → Microsoft → Windows → PowerShell → Operational → Event ID 4104

---

## Lab 6: WMI/Process Spoofing/Token Theft

### Network Setup
- **Endpoint:** `172.16.85.105:65520` (adminELS:Nu3pmkfyX)

### Detection Procedures

#### Task 1: WMI Abuse Detection
1. **RDP to compromised endpoint**
2. **Open PowerShell as Administrator**
3. **Search for WMI spawning PowerShell:**
   ```powershell
   Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=1} | Where-Object {$_.Properties[20].Value -like "*wmi*"} | fl
   ```

#### Task 2: Parent Process Spoofing Detection
1. **Analyze Sysmon logs for mspaint.exe creation (11/2/2020 11:40:56 AM)**
2. **Check SilkService logs for Process ID discrepancies:**
   - Real parent: PowerShell (ProcessID field)
   - Spoofed parent: explorer.exe (parent field)
3. **Correlate Sysmon Event ID 8 (CreateRemoteThread)**

#### Task 3: Access Token Theft Detection
1. **Query Event ID 4656 for suspicious handle requests:**
   ```powershell
   Get-WinEvent -FilterHashtable @{logname="Security"; id=4656} | Where-Object {$_.Properties -contains "0x1400" -or $_.Properties -contains "0x1000"}
   ```
2. **Look for non-SYSTEM processes requesting handles:**
   - Focus on Tokens.exe requesting handle to Sysmon64.exe
   - Access mask: 0x1400 (PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION)
3. **Correlate with subsequent SYSTEM shell creation**

---

## Lab 7-9: Advanced ELK Detection Labs

### Lab 7: Basic PowerShell Detection (ELK: 172.16.85.100:5601)

#### PowerShell Framework Detection
```
winlog.event_data.ScriptBlockText:(PowerUp OR Mimikatz OR NinjaCopy OR Get-ModifiablePath OR AllChecks OR AmsiBypass OR PsUACme OR Invoke-DLLInjection OR Invoke-ReflectivePEInjection OR Invoke-Shellcode OR Get-GPPPassword OR Get-Keystrokes OR Get-TimedScreenshot OR PowerView)
```

#### Suspicious Parent Processes
```
winlog.event_data.ParentImage:(*mshta.exe OR *rundll32.exe OR *regsvr32.exe OR *services.exe OR *winword.exe OR *wmiprvse.exe OR *powerpnt.exe OR *excel.exe) AND winlog.event_data.Image:*powershell.exe
```

#### Disguised PowerShell
```
winlog.event_data.Description:*PowerShell AND NOT (winlog.event_data.Image:*powershell.exe OR winlog.event_data.Image:*powershell_ise.exe)
```

#### Base64 Encoded Commands
```
(winlog.event_data.Description:*PowerShell OR winlog.event_data.Image:*powershell.exe) AND winlog.event_data.CommandLine:*-e*
```

### Lab 8: Advanced ELK Detection (ELK: 172.16.85.101)

#### LOLBAS pcwutl.dll Detection
```
process.name:rundll32.exe AND process.args:pcwutl.dll AND process.args:LaunchApplication
```

#### UAC Bypass Detection (cliconfg.exe)
```
event.id:7 AND process.name:cliconfg.exe AND file.path:NTWDBLIB.dll
```

#### RDP Enablement Detection
```
event.id:1 AND process.name:netsh.exe AND process.args:localport:3389 AND process.args:action:allow
```

### Lab 9: ELK Detection Playground (ELK: 172.16.85.102:5601, SSH: hunter:hunter)

#### Account Discovery Detection
```
winlog.event_id:(4798 OR 4799) AND winlog.event_data.CallerProcessName:(net OR net1) AND winlog.computer_name:MSEDGEWIN10
```

#### Accessibility Features Persistence
```
winlog.event_id:1 AND winlog.event_data.Image:(*sethc.exe OR *utilman.exe OR *osk.exe OR *magnify.exe) AND winlog.event_data.Description:"Windows Command Processor" AND winlog.computer_name:DC1.insecurebank.local
```

---

## Lab 10-12: Advanced Splunk Detection Labs

### Lab 10: BOTS v1 Analysis (Splunk: 172.16.84.101:8000, admin:elsnalyst)

#### Password Brute Force Detection
```splunk
index=botsv1 sourcetype=stream:http dest=192.168.250.70 http_method=POST form_data=*user*pass*
| stats count by src
```

#### Geographic Analysis
```splunk
index=botsv1 sourcetype=stream:http dest=192.168.250.70 http_method=POST form_data=*user*pass*
| iplocation src 
| geostats latfield=lat longfield=lon count by src
```

#### Process Analysis
```splunk
index=botsv1 sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational
| stats values(ParentImage) by process
```

### Lab 11: BOTS v2 Analysis (Splunk: 172.16.84.102:8000)

#### PowerShell Empire SSL Certificate Detection
```splunk
index=botsv2 sourcetype=stream:tcp ssl_issuer="C=US"
```

#### FTP Exfiltration Detection
```splunk
index=botsv2 sourcetype=stream:ftp src=* dest=160.153.91.7
| table _time src filename method methodparameter reply_content
```

#### DNS Exfiltration with Entropy Analysis
```splunk
index=botsv2 sourcetype=stream:dns hildegardsfarm.com message_type=QUERY
| eval query=mvdedup(query) 
| eval list="mozilla" 
| `ut_parse_extended(query,list)` 
| `ut_shannon(ut_subdomain)` 
| table src dest query ut_subdomain ut_shannon
```

### Lab 12: Active Directory Attacks (Splunk: 172.16.84.103:8000)

#### Kerberos Brute Force Detection
```splunk
# Non-existing accounts (Status 0x6)
index=adhunting sourcetype=XmlWinEventLog EventCode=4768 Status=0x6
| transaction IpAddress maxpause=5m 
| where eventcount > 5

# Password failures (Status 0x18)
index=adhunting EventCode=4771 Status=0x18
| transaction Computer maxpause=5m 
| where eventcount > 5
```

#### Kerberoasting Detection
```splunk
# Vulnerable encryption types
index=adhunting EventCode=4769 EncryptionType IN (0x1, 0x3, 0x11, 0x12, 0x17, 0x18)

# Excessive service ticket requests
index=adhunting EventCode=4769 ServiceName=*$ 
| stats count by Computer IpAddress
```

#### DCSync Detection
```splunk
index=adhunting source=xmlwineventlog:security EventCode=4662 Properties="1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" OR Properties="1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
```

---

## Lab 13-15: Network Analysis & Forensics

### Lab 13: Zeek Network Analysis

#### Long Connection Detection
```bash
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk 'BEGIN {FS="\t"} {arr[$1 FS $2 FS $3 FS $4] += $5} END {for (key in arr) printf "%s%s%s\n", key, FS, arr[key]}' | sort -nrk 5 | head -n 10
```

#### User Agent Analysis
```bash
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -n | head -n 10
```

#### DNS Analysis with RITA
```bash
rita show-exploded-dns -H --limit 10 zeeklogs
```

### Lab 14: PCAP Analysis (NetworkMiner + Wireshark)

#### NetworkMiner Analysis Workflow
1. **Load PCAP in NetworkMiner**
2. **Check Hosts tab for anomalies:**
   - Non-domain naming conventions
   - Suspicious MAC addresses (BEEEEFDEEAD, DEEEADBEEEEF)
   - Kali Linux indicators
3. **Examine Sessions tab for unusual traffic**
4. **Review DNS tab for suspicious queries**

#### Wireshark Deep Analysis
1. **Apply host filters based on NetworkMiner findings**
2. **Look for ARP poisoning patterns**
3. **Check TCP retransmissions and port usage**
4. **Analyze SSL/TLS certificate anomalies**

### Lab 15: Web Shell Detection

#### LOKI Scanner
```bash
cd C:\loki-0.22.0
loki.exe -p C:\inetpub\testdir
```

#### NeoPI Entropy Analysis
```bash
cd NeoPI
python neopi.py -d C:\inetpub\testdir
```

#### PowerShell File Stacking
```powershell
.\Get-TimeDiffFileStacking.ps1 c:\inetpub\testdir "7/12/2017 9:00am"
```

#### Hash Baseline Comparison
```powershell
Get-ChildItem -Path c:\inetpub\testdir -File -Recurse | Get-FileHash -Algorithm MD5 | Export-CSV C:\Current.csv
.\Compare-FileHashesList.ps1 -ReferenceFile C:\Baseline.csv -DifferenceFile C:\Current.csv
```

---

## Lab 16-17: OSQuery & Linux Analysis

### Lab 16: OSQuery at Scale (172.16.80.200 client, 172.16.80.201 fleet, hunter:hunter)

#### Enrollment Process
```bash
ssh hunter@172.16.80.200
cd Desktop
sudo ./osquery-enroll.sh
```

#### Linux Process Injection Queries
```sql
-- Check ptrace scope
SELECT * FROM system_controls WHERE name='kernel.yama.ptrace_scope';

-- Detect injected libraries
SELECT process_memory_map.*, pid as mpid 
FROM process_memory_map 
LEFT JOIN processes USING (pid) 
WHERE process_memory_map.path LIKE '/%' 
AND process_memory_map.pseudo != 1 
AND process_memory_map.path NOT LIKE '/lib%' 
AND process_memory_map.permissions LIKE '%x%';
```

#### Library Injection Simulation
```bash
cd ~/Downloads/linux-inject
./sample-target &
# Disable ptrace protection temporarily
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
./inject -n sample-target sample-library.so
# Re-enable protection
echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### Lab 17: Linux Memory Analysis (Volatility)

#### Profile Creation and Analysis
```bash
# Check kernel modules
python vol.py --profile=LinuxProfile-26.32 linux_check_modules -f infection.memory

# Syscall table analysis
python vol.py --profile=LinuxProfile-26.32 linux_check_syscall -f infection.memory

# Process analysis
python vol.py --profile=LinuxProfile-26.32 linux_pslist -f infection.memory

# Network connections
python vol.py --profile=LinuxProfile-26.32 linux_netstat -f infection.memory
```

---

## Lab 18-20: Advanced Splunk Scenarios

### Lab 18: Complex PowerShell Empire Detection (Splunk: 172.16.84.104:8000)

#### Empire Stager Detection
```splunk
index=* EventCode=4104 AND (psversiontable.psversion.major OR system.management.automation.utils OR system.management.automation.amsiutils)
| eval MessageDeobfuscated = replace(Message, "%", " ")
| search (EnableScriptBlockLogging OR enablescriptblockinvocationlogging OR cachedgrouppolicysettings OR ServerCertificateValidationCallback OR expect100continue)
```

#### WMI Persistence Detection
```splunk
index=winsysmon EventCode=19 OR EventCode=20 OR EventCode=21
| table _time, EventCode, Operation, Consumer, Query, Destination
```

#### Unmanaged PowerShell Detection
```splunk
index=* host_application!="powershell*" 
| rex field=Message "HostApplication=(?<HostApplication>[^,]*)"
| search HostApplication!="*powershell*" HostApplication!="*.exe"
| stats count by host HostApplication
```

### Lab 19: CrackMapExec Detection (Splunk: 172.16.84.105:8000)

#### SMB File Access Detection (Zeek)
```splunk
index=zeek sourcetype=zeek:smb_files action=SMB::FILE_OPEN
| table id.resp_h, id.resp_p, id.orig_h, name
```

#### NTLM Authentication Analysis
```splunk
index=zeek sourcetype=zeek:ntlm
| table id.resp_h, username, domainname, success
```

#### Random Filename Detection (CrackMapExec signatures)
```splunk
index=zeek sourcetype=zeek:smb_files name="[A-Z0-9]{6}"
| table _time, id.orig_h, id.resp_h, name, action
```

### Lab 20: Advanced Splunk Hunts (Splunk: 172.16.84.106:8000)

#### Renamed PowerShell Detection
```splunk
index=winsysmon EventCode=1 AND Description="Windows PowerShell" AND Image!="*powershell.exe" AND Image!="*powershell_ise.exe"
| rex field=Hashes "MD5=(?<MD5>[A-F0-9]+)"
| table _time, Computer, User, Image, cmdline, ParentImage, MD5
```

#### Encoded PowerShell Commands
```splunk
index=* EventCode=1 
| eval cmdline = replace(cmdline, "[-/]([EeNnCcOoDdIiNnGg])+", "-encoding")
| search Image="*powershell.exe" (cmdline="-enc*" OR cmdline="-en*" OR cmdline="-e *" OR cmdline="-ec*")
| table _time Computer User cmdline
```

#### Administrative Share Abuse (T1077)
```splunk
index=winsysmon EventCode=1 ParentImage="*rundll32.exe" CommandLine="*ADMIN$*127.0.0.1*"
```

#### Downloaded Office Documents
```splunk
index=winsysmon EventCode=15 TargetFilename="*.doc" Contents="*Zone.Identifier*"
| table _time Computer TargetFilename Contents
```

---

## General Execution Guidelines

### Pre-Lab Setup Checklist
1. **Verify network connectivity to all lab environments**
2. **Ensure proper credentials for each lab**
3. **Check tool availability and paths**
4. **Clear previous logs when required**
5. **Take snapshots before major modifications**

### Common Troubleshooting
- **PowerShell execution policy:** Use `-ExecutionPolicy Bypass`
- **Network connectivity:** Verify VPN/lab network access
- **Tool permissions:** Run as Administrator when required
- **Log clearing:** Clear relevant logs between exercises
- **Time synchronization:** Ensure proper time sync for correlation

### Detection Best Practices
- **Start broad, narrow down:** Begin with high-level indicators
- **Correlate multiple sources:** Combine Sysmon, Security, PowerShell logs
- **Baseline normal behavior:** Understand environment patterns
- **Chain detections:** Link related events across time
- **Validate findings:** Confirm with multiple detection methods

### Lab Environment Management
- **Take notes:** Document findings and command modifications
- **Save queries:** Keep working detection rules for future use
- **Test variations:** Try different parameter combinations
- **Time awareness:** Account for lab time windows and log retention
- **Clean up:** Reset environment state between major exercises