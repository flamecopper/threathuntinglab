# Threat Hunting Labwork - Concise Notes

## Lab 1: IOCs and YARA Rules

### Objective
Create IOCs and YARA rules to detect malware samples.

### Tools Required
- WINMD5Free
- Strings
- Mandiant IOC Editor
- Mandiant Redline
- YARA

### Lab Network
- Network: 172.15.161.0/24
- Your IP: 172.16.151.50
- Credentials: elshunter:ahuntingweg0!

### Malware Sample
- File: "END OF YEAR FINANCIALS REPORT.exe"
- Location: Desktop folder "MALWARE – DON'T RUN"

### Procedures

#### Task 1: Create IOC
1. Use WINMD5FREE to get MD5 hash of malware sample
2. Open Mandiant IOC Editor
3. Create new indicator with:
   - MD5 hash (Add Item > FileItem > File MD5)
   - File size (Add Item > FileItem > File Size)
   - Extract 2 strings using `strings.exe` command:
     ```
     C:\Users\elshunter\Desktop\tools\strings.exe "c:\users\elshunter\desktop\malware – don't run\end of year financials report.exe" >> c:\users\elshunter\desktop\strings.txt
     ```

#### Task 2: Test IOC with Redline
1. Create IOC Search Collector in Redline
2. Select IOC folder and enable Strings collection
3. Save collector to HUNT folder
4. Run `RunRedlineAudit.bat` from elevated command prompt
5. Open analysis session and check IOC Reports tab

#### Task 3: Create YARA Rule
1. Open skeleton YAR file in tools\yara-3.6.2-win64
2. Add malware hash and 2 strings from IOC
3. Test rule with: `Yara64.exe .\rules\eoyfr.yar "target_folder"`

#### Task 4: YARA Rule Testing
- If no hits, change condition from "2 of them" to "1 of them"
- Test against both desktop and C:\Windows\System32 locations

#### Task 5: Review yarGen Output
- Check `yargen_rules.yar` for additional strings
- Add "fullword wide" modifier for Unicode strings like "allyourbasearebelongtous"

### Key Takeaways
- Test IOCs and YARA rules thoroughly
- More signatures = better detection, but avoid false positives
- Consider Unicode string encoding in YARA rules

---

## Lab 2: Memory Analysis (Hunting Malware Part 1)

### Objective
Use Redline for memory analysis to detect DLL injection and rootkits.

### Network Configuration
- Hunting Workstation: 172.16.151.50 (elshunter:ahuntingweg0!)
- Administrative Assistant: 172.16.151.75 (elshunter:ahuntingweg0!)

### Analysis Workflow

#### Task 1: Analyze Pre-existing Memory Image
1. Load AnalysisSession1.mans in Redline
2. Examine Redlined processes:
   - conhost.exe (PID 3316) - unmapped binary
   - Meterpreter_Payload_Detection.exe - spawned from command shell
   - svchost.exe - unexpected arguments
   - VGAuthService.exe - unsigned DLLs

#### Task 2: Identify Suspicious Activity
1. Check Hierarchical Processes view
2. Look for **1sass.exe (PID 2816)** - masquerading as lsass.exe
3. Suspicious indicators:
   - Incorrect spelling (1sass vs lsass)
   - Wrong parent process (should be wininit.exe)
   - Wrong path (should be C:\Windows\system32)
   - Wrong username (should be SYSTEM)
   - Network connections to 172.16.151.133

#### Task 3: Timeline Analysis
1. Use Timeline view to trace execution
2. Search for "1sass" to find 4 entries
3. Identify trigger: `hh.exe` executed `1sass.chm` before malicious binary

#### Task 4: Live Memory Collection
1. Create Standard Collector with "Acquire Memory Image" enabled
2. Deploy to target machine via network share
3. Run `RunRedlineAudit.bat` with elevated privileges
4. Analyze new session for suspicious activity

### Detection Indicators
- **Process masquerading**: 1sass.exe vs lsass.exe
- **Injected memory sections**: Check Memory Sections > Injected
- **Suspicious network activity**: Unexpected connections
- **File execution chains**: CHM files leading to executables

---

## Lab 3: Advanced Memory Analysis (Hunting Malware Part 2)

### Objective
Analyze memory images for code injection and rootkits using Redline and Volatility.

### Tools
- Mandiant Redline
- Volatility Framework

### Analysis Targets
- **APTA.vmem**: Code injection analysis
- **APTB.vmem**: Rootkit detection

#### APTA Analysis (Code Injection)
1. **Redline Analysis**:
   - 24 processes with injected code
   - Check Memory Sections > Injected Memory Sections
   - Review Hooks for SSDT/IDT/Untrusted hooks

2. **Volatility Analysis**:
   ```bash
   # Determine profile
   python vol.py -f apta.vmem imageinfo
   # Profile: WinXPSP2x86
   
   # Process analysis
   python vol.py -f apta.vmem --profile=WinXPSP2x86 pslist
   python vol.py -f apta.vmem --profile=WinXPSP2x86 psscan
   python vol.py -f apta.vmem --profile=WinXPSP2x86 psxview
   
   # Network connections
   python vol.py -f apta.vmem --profile=WinXPSP2x86 connscan
   
   # Code injection detection
   python vol.py -f apta.vmem --profile=WinXPSP2x86 malfind -p 856
   python vol.py -f apta.vmem --profile=WinXPSP2x86 apihooks -p 856
   ```

3. **Key Findings**:
   - Hidden processes: cmd.exe (124), VMip.exe (1944)
   - svchost.exe (856) with injected code and hooked APIs
   - Hooked APIs: NtCreateThread, ZwCreateThread
   - **Malware identified**: Zeus

#### APTB Analysis (Rootkit Detection)
1. **Volatility Rootkit Detection**:
   ```bash
   # SSDT hook detection
   python vol.py -f aptb.vmem --profile=WinXPSP2x86 ssdt | select-string -NotMatch -Pattern 'ntoskrnl|win32k'
   
   # Module extraction
   python vol.py -f aptb.vmem --profile=WinXPSP2x86 modules
   python vol.py -f aptb.vmem --profile=WinXPSP2x86 moddump -b 0xff0d1000 --dump-dir="output"
   ```

2. **Key Findings**:
   - Malicious driver: 00004A2A.sys
   - 14 hooked SSDT functions
   - Base address: 0xff0d1000
   - **Malware identified**: Black Energy

### Memory Analysis Best Practices
- Use multiple tools (Redline + Volatility) for comprehensive analysis
- Look for process hiding techniques (psxview plugin)
- Check for hooked system calls and APIs
- Extract and analyze suspicious modules
- Correlate network connections with process activity

---

## Lab 4: Empire Detection

### Objective
Detect PowerShell Empire using multiple detection tools.

### Network Configuration
- child-dc01: 10.100.10.253 (VNC: vnc@3L$-CHILDL0c@l)
- UATSERVER: 10.100.11.150 (Domain: ELS-CHILD\Administrator)

### Detection Tools
- **EIF (Evil Inject Finder)**: Detects reflective DLL injection
- **Get-InjectedThread.ps1**: Identifies memory injection
- **NorkNork**: Detects persistence mechanisms

### Empire Detection Techniques

#### 1. Process Injection Detection (PSInject)
Empire uses reflective DLL injection to migrate into stable processes like explorer.exe.

**EIF Detection**:
```powershell
.\eif_parser.ps1 -ComputerName uatserver.els-child.els.local -EIF_Path "C:\path\to\EvilInjectFinder.exe"
```

**Get-InjectedThread Detection**:
```powershell
New-PSSession –Name PSC1 –ComputerName uatserver.els-child.els.local
Enter-PSSession –Name PSC1
Import-Module .\Get-InjectedThread.ps1
Get-InjectedThread
```

#### 2. Persistence Detection
**NorkNork Detection**:
```powershell
New-PSSession –Name PSC2 –ComputerName uatserver.els-child.els.local
Enter-PSSession –Name PSC2
.\NorkNork.exe
```

### Detection Indicators
- **PowerShell DLLs in explorer.exe**: System.Management.Automation
- **Injected threads**: Memory injection signatures
- **Registry persistence**: Base64 encoded PowerShell commands
- **C2 patterns**: login/process.php URL format, XOR routines

### Empire Characteristics
- **Common injection**: PSInject technique
- **Persistence methods**: Registry, WMI, scheduled tasks
- **C2 communication**: HTTP with specific URL patterns
- **Obfuscation**: Base64 encoding, XOR encryption

---

## Lab 5: Responder/Inveigh Detection

### Objective
Detect LLMNR/NBT-NS/MDNS poisoning attacks using multiple detection methods.

### Network Configuration
- UATSERVER: 10.100.11.150 (VNC: vnc@3L$-CHILDL0c@l)

### Detection Tools
- **CredDefense (ResponderGuard)**: Detects rogue responses
- **PowerShell**: Event log analysis
- **Sysmon**: Network connection monitoring

### Detection Methods

#### 1. CredDefense Detection
```powershell
Import-Module .\ResponderGuard.ps1
Invoke-ResponderGuard –CidrRange 10.100.11.0/24 –LoggingEnabled -HoneyTokenSeed
```

#### 2. Honey Credentials Monitoring
Monitor Security Event ID 4648 for credential usage:
```powershell
Import-Module .\Find-HoneyAccount.ps1
Find-HoneyAccount HoneyUser
```

#### 3. Sysmon Network Analysis
Monitor Event ID 3 for SMB connections to untrusted IPs:
```powershell
Import-Module .\Get-WinEventData.ps1
.\Find-UntrustedSMBConnections.ps1
```

#### 4. PowerShell Script Block Logging
Enable logging to detect Inveigh execution:
- Event ID 4104 in PowerShell Operational log
- Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`

### Attack Detection Indicators
- **UDP responses** to non-existent resources
- **Event ID 4648**: Honey credential usage
- **SMB connections** to untrusted IPs (ports 445/139)
- **PowerShell script blocks** containing LLMNR poisoning code

---

## Lab 6: WMI/Process Spoofing/Token Theft

### Objective
Hunt for WMI abuse, parent process spoofing, and access token theft.

### Endpoint Configuration
- Target: 172.16.85.105:65520 (adminELS:Nu3pmkfyX)

### Detection Techniques

#### 1. WMI Abuse Detection
**Search for WMI spawning PowerShell**:
```powershell
Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=1} | Where-Object {$_.Properties[20].Value -like "*wmi*"}
```

**Indicators**:
- WmiPrvSE.exe spawning powershell.exe
- PowerShell remoting enablement
- Event correlation with login events

#### 2. Parent Process Spoofing Detection
**Key Events**:
- Sysmon EventID 1: mspaint.exe creation
- Sysmon EventID 8: Remote thread creation
- SilkService logs: ProcessID vs parent discrepancy

**Analysis**:
- Real parent: powershell.exe (ProcessID)
- Spoofed parent: explorer.exe (parent field)
- Detection through process correlation

#### 3. Access Token Theft Detection
**Monitor Event ID 4656**:
- Process requesting handle with access mask 0x1400 or 0x1000
- Focus on non-SYSTEM user processes
- Look for Tokens.exe accessing Sysmon64.exe

**Detection Query**:
```powershell
# Search for Event ID 4656 with suspicious access masks
Get-WinEvent -FilterHashtable @{logname="Security"; id=4656}
```

### Key Detection Points
- **WMI spawning PowerShell**: Unusual parent-child relationship
- **Process spoofing**: Mismatched parent process IDs
- **Token theft**: Suspicious handle requests to system processes
- **Privilege escalation**: SYSTEM shell creation after token access

---

## Lab 7: ELK/PowerShell Detection

### Objective
Create ELK detection rules for PowerShell-based attacks.

### ELK Configuration
- Address: 172.16.85.100:5601

### Detection Rules

#### 1. PowerShell Framework Detection
```
winlog.event_data.ScriptBlockText:(PowerUp OR Mimikatz OR NinjaCopy OR Get-ModifiablePath OR AllChecks OR AmsiBypass OR PsUACme OR Invoke-DLLInjection OR Invoke-ReflectivePEInjection OR Invoke-Shellcode OR Get-GPPPassword OR Get-Keystrokes OR Get-TimedScreenshot OR PowerView)
```

#### 2. Suspicious Parent Processes
```
winlog.event_data.ParentImage:(*mshta.exe OR *rundll32.exe OR *regsvr32.exe OR *services.exe OR *winword.exe OR *wmiprvse.exe) AND winlog.event_data.Image:*powershell.exe
```

#### 3. Disguised PowerShell
```
winlog.event_data.Description:*PowerShell AND NOT (winlog.event_data.Image:*powershell.exe OR winlog.event_data.Image:*powershell_ise.exe)
```

#### 4. Base64 Encoded Commands
```
(winlog.event_data.Description:*PowerShell OR winlog.event_data.Image:*powershell.exe) AND winlog.event_data.CommandLine:*-e*
```

#### 5. GZIP Compression
```
winlog.event_data.ScriptBlockText:*H4sI*
```

#### 6. XOR Obfuscation
```
winlog.event_data.ScriptBlockText:(*bxor* AND *join*)
```

#### 7. Assembly Loading
```
winlog.event_data.ScriptBlockText:((*Load*) AND (*ReadAllBytes* OR *LoadFile*))
```

#### 8. Download Activity
```
winlog.event_data.ScriptBlockText:(*WebClient* OR *DownloadData* OR *DownloadFile* OR *DownloadString* OR *curl* OR *wget* OR *RestMethod*)
```

### Detection Categories
- **Framework detection**: Known PowerShell attack tools
- **Process analysis**: Suspicious parent-child relationships
- **Obfuscation**: Base64, XOR, GZIP compression
- **File operations**: Assembly loading, downloads
- **Evasion**: Renamed executables, encoding

---

## General Lab Best Practices

### Network Analysis
- Use NetworkMiner for initial PCAP overview
- Apply Wireshark for detailed packet analysis
- Focus on suspicious hostnames, MAC addresses, and traffic patterns
- Look for protocol anomalies (wrong source/destination ports)

### Memory Analysis
- Use multiple tools (Redline + Volatility) for comprehensive coverage
- Check for process masquerading and injection
- Analyze network connections and file execution chains
- Extract and examine suspicious modules/drivers

### Endpoint Detection
- Monitor PowerShell execution and script block logging
- Detect process injection through memory analysis
- Use ETW and API monitoring for advanced threats
- Correlate multiple event sources for accurate detection

### Tool Combinations
- **Static analysis**: IOCs, YARA rules, file hashes
- **Dynamic analysis**: Memory dumps, process monitoring
- **Network analysis**: Traffic patterns, C2 communication
- **Log analysis**: Windows events, Sysmon, PowerShell logs