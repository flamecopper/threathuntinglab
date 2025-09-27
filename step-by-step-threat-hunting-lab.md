# Threat Hunting Professional v2 - Step-by-Step Detailed Lab Notes

## Lab 1: IOCs & YARA Rule Creation

**Objective:** Detect malware through custom IOCs and YARA rules.

### Network and Tool Setup
- Lab Network: `172.15.161.0/24`, Your IP: `172.16.151.50`
- Credential: `elshunter:ahuntingweg0!`
- Folder: `C:\Users\elshunter\Desktop\malware – don't run\END OF YEAR FINANCIALS REPORT.exe`
- Tools: WINMD5Free, Strings, Mandiant IOC Editor, Mandiant Redline, YARA

### Procedure
1. **MD5 Hash Extraction**:
   - Launch WINMD5Free
   - Input target malware sample
   - Note MD5 result
2. **Extract Strings from Binary**:
   - Open cmd and run:
     ```
     "C:\Users\elshunter\Desktop\tools\strings.exe" "C:\Users\elshunter\Desktop\malware – don't run\END OF YEAR FINANCIALS REPORT.exe" > "C:\Users\elshunter\Desktop\strings.txt"
     ```
3. **Create IOC (Indicator of Compromise):**
   - Open Mandiant IOC Editor
   - Create a new indicator
   - Add File MD5, File Size, and 2 extracted strings from above
4. **Test IOC in Redline:**
   - Go to IOC Search Collector
   - Import IOC file, enable Strings Collection
   - Run Collector via `RunRedlineAudit.bat` elevated cmd
   - Review results under IOC Reports
5. **Create YARA Rule:**
   - Edit skeleton rule in `tools\yara-3.6.2-win64\rules\eoyfr.yar`
   - Specify hash and strings as conditions
   - Run:
     ```
     Yara64.exe .\rules\eoyfr.yar "C:\Users\elshunter\Desktop\malware – don't run"
     ```
   - If no hits, adjust: `condition: 1 of them`
6. **Unicode Handling in YARA:**
   - Use modifier `fullword wide` for Unicode strings
   - Example: `"allyourbasearebelongtous" fullword wide`

---

## Lab 2: Memory Analysis with Redline & Volatility

**Goal:** Detect injected code and rootkits

### Redline Procedure
1. **Analyze Provided Memory Image:**
   - Start Redline
   - Open AnalysisSession1.mans
   - Look for conhost.exe (unmapped binary), suspicious processes (Meterpreter_Payload_Detection.exe, svchost.exe, VGAuthService.exe)
   - Identify process masquerading (look for `1sass.exe`, check spelling, parent, path, user, connections)
   - Timeline review for suspicious execution:
     - Use Timeline view
     - Search for sequence (hh.exe > 1sass.chm > `1sass.exe`)
2. **Live Memory Collection:**
   - Create Standard Collector, enable "Acquire Memory Image"
   - Deploy via network share, run `RunRedlineAudit.bat` elevated
   - Open new session, repeat above checks

### Volatility Procedure
1. **Identify Image Profile:**
   - Run:
     ```
     volatility -f <image>.vmem imageinfo
     ```
   - Use suggested profile (e.g.: WinXPSP2x86)
2. **Process Analysis:**
   - List processes:
     ```
     python vol.py -f <image>.vmem --profile=WinXPSP2x86 pslist
     python vol.py -f <image>.vmem --profile=WinXPSP2x86 psxview
     ```
   - Scan for injection:
     ```
     python vol.py -f <image>.vmem --profile=WinXPSP2x86 malfind -p <PID>
     python vol.py -f <image>.vmem --profile=WinXPSP2x86 apihooks -p <PID>
     ```
3. **Rootkit Detection:**
   - SSDT hooks:
     ```
     python vol.py -f <image>.vmem --profile=WinXPSP2x86 ssdt | select-string -NotMatch -Pattern 'ntoskrnl|win32k'
     ```
---

## Lab 3: Empire Detection

**Goal:** Detect PowerShell Empire techniques on endpoints

### Tools & Detection
1. **EIF (Evil Inject Finder):**
   ```powershell
   .\eif_parser.ps1 -ComputerName uatserver.els-child.els.local -EIF_Path "C:\path\to\EvilInjectFinder.exe"
   ```
2. **Get-InjectedThread PowerShell:**
   ```powershell
   New-PSSession –Name PSC1 –ComputerName uatserver.els-child.els.local
   Enter-PSSession –Name PSC1
   Import-Module .\Get-InjectedThread.ps1
   Get-InjectedThread
   ```
3. **NorkNork (Persistence):**
   ```powershell
   New-PSSession –Name PSC2 –ComputerName uatserver.els-child.els.local
   Enter-PSSession –Name PSC2
   .\NorkNork.exe
   ```

---
## Lab 4: Web Shell Hunting

**Goal:** Locate and validate web shells across directories using multiple techniques

### Techniques
1. **LOKI IOC Scanner:**
   - Run from `C:\loki0.22.0`:
     ```
     loki.exe -p C:\inetpub\testdir
     ```
2. **NeoPI (Entropy-based):**
   - Run from tools folder:
     ```
     cd NeoPI
     python neopi.py -d C:\inetpub\testdir
     ```
3. **File Stacking by Creation Time:**
   - Powershell:
     ```powershell
     .\Get-TimeDiffFileStacking.ps1 c:\inetpub\testdir "7/12/2017 9:00am"
     ```
4. **MD5 Hash Baseline Compare:**
   - Powershell:
     ```powershell
     Get-ChildItem -Path c:\inetpub\testdir -File -Recurse | Get-FileHash -Algorithm MD5 | Export-CSV C:\Current.csv
     .\Compare-FileHashesList.ps1 -ReferenceFile C:\Baseline.csv -DifferenceFile C:\Current.csv
     ```

---
## Lab 5: Network & Insider Threat Hunting

**Goal:** Detect suspicious hosts and traffic in PCAPs

### Steps
1. **Load PCAP in NetworkMiner**
   - Open PCAP in NetworkMiner
   - Analyze Hosts tab for anomalies (IDs, names, domains)
2. **Wireshark Deep Packet Inspection**
   - Apply filters:
     - By device IP
     - Check DNS/SSL queries and TCP port usage
3. **Identify Top Priority Host**
   - Look for devices out of domain, unusual MAC addresses, strange web traffic

---
## Lab 6: Osquery/Linux Injection Hunting

**Goal:** Detect injected libraries, changes to ptrace scope, process memory

### Setup
- Osquery client: `172.16.80.200` (hunter)
- Kolide Fleet server: `172.16.80.201` (hunter)

### Steps
1. **Enroll Endpoint:**
   - SSH to client:
     ```
     cd Desktop
     sudo ./osquery-enroll.sh
     ```
2. **Query for ptrace scope:**
   - Osqueryi:
     ```sql
     SELECT * FROM system_controls WHERE name='kernel.yama.ptrace_scope';
     ```
3. **Process Memory Analysis:**
   - Osqueryi:
     ```sql
     SELECT process_memory_map.*, pid as mpid FROM process_memory_map LEFT JOIN processes USING (pid) WHERE process_memory_map.path LIKE '/%' AND process_memory_map.pseudo != 1 AND process_memory_map.path NOT LIKE '/lib%' AND process_memory_map.permissions LIKE '%x%';
     ```
4. **Library Injection Simulation:**
   - Run:
     ```bash
     cd ~/Downloads/linux-inject
     ./sample-target
     ./inject -n sample-target sample-library.so
     echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
     ./inject -n sample-target sample-library.so
     ```
   - Change back ptrace scope:
     ```bash
     echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
     ```

---

* (Continue expansion for advanced ELK/Splunk network logs, persistence, AD attacks, endpoint detection, memory forensic, Sigma-based detection, CrackMapExec, Linux rootkit detection, etc as needed for full hands-on notes.)

---

## Usage
- Each lab section includes precise commands and file paths for real execution.
- Adjust network and credential info as needed for lab environment.
- All detection queries can be pasted directly into ELK/Splunk/Kibana, PowerShell, CMD, osqueryi, or specific forensic/endpoint tools.
- For advanced/unlisted labs, request further step-by-step guidance or expand as needed for a particular lab scenario.
