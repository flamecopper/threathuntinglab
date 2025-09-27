# Threat Hunting Professional v2 - Complete Lab Notes

## Lab 1: IOCs and YARA Rules
### Network: 172.15.161.0/24 | IP: 172.16.151.50 | Creds: elshunter:ahuntingweg0!

**Objective**: Create IOCs and YARA rules for malware detection

### Tools Required
- WINMD5Free, Strings, Mandiant IOC Editor, Mandiant Redline, YARA

### Procedures
1. **Create IOC**: Get MD5 hash, file size, extract 2 strings using `strings.exe`
2. **Test IOC**: Use Redline IOC Search Collector
3. **Create YARA Rule**: Add hash + 2 strings, test with `Yara64.exe`
4. **Optimize Rules**: Adjust conditions (2 of them → 1 of them), add Unicode modifiers

---

## Lab 2-3: Memory Analysis (Hunting Malware)
### Network: 172.16.151.50 | Target: 172.16.151.75

**Tools**: Mandiant Redline, Volatility Framework

### Key Detection Indicators
- **Process masquerading**: 1sass.exe vs lsass.exe (wrong parent, path, user)
- **Code injection**: Check Memory Sections > Injected
- **Volatility commands**:
  ```bash
  python vol.py -f apta.vmem --profile=WinXPSP2x86 pslist/psscan/psxview
  python vol.py -f apta.vmem --profile=WinXPSP2x86 malfind -p 856
  python vol.py -f aptb.vmem --profile=WinXPSP2x86 ssdt | select-string -NotMatch "ntoskrnl|win32k"
  ```

### Identified Threats
- **Zeus malware** (APTA): Injected code, hooked APIs
- **Black Energy rootkit** (APTB): 14 hooked SSDT functions

---

## Lab 4: Empire Detection
### Network: 10.100.10.253 (child-dc01), 10.100.11.150 (UATSERVER)

**Tools**: EIF, Get-InjectedThread.ps1, NorkNork

### Detection Methods
1. **PSInject Detection**: `.\eif_parser.ps1 -ComputerName uatserver`
2. **Thread Injection**: `Get-InjectedThread` in PowerShell session
3. **Persistence**: `.\NorkNork.exe` for registry analysis

### Empire Characteristics
- PowerShell DLLs in explorer.exe
- Base64 encoded commands
- C2 pattern: login/process.php URLs

---

## Lab 5: Responder/Inveigh Detection
### Network: 10.100.11.150 (UATSERVER)

### Detection Tools & Methods
1. **CredDefense**: `Invoke-ResponderGuard –CidrRange 10.100.11.0/24`
2. **Honey Credentials**: Monitor Event ID 4648
3. **Sysmon**: Event ID 3 for SMB connections
4. **PowerShell Logging**: Event ID 4104 for script blocks

---

## Lab 6: WMI/Process Spoofing/Token Theft
### Endpoint: 172.16.85.105:65520 | Creds: adminELS:Nu3pmkfyX

### Detection Techniques
1. **WMI Abuse**: WmiPrvSE.exe spawning powershell.exe
2. **Process Spoofing**: Mismatched parent process IDs in SilkService logs
3. **Token Theft**: Event ID 4656 with access mask 0x1400/0x1000

---

## Lab 7: ELK/PowerShell Detection
### ELK: 172.16.85.100:5601

### Detection Rules
1. **Framework Detection**: `PowerUp OR Mimikatz OR NinjaCopy`
2. **Suspicious Parents**: `*mshta.exe OR *rundll32.exe` spawning PowerShell
3. **Disguised PowerShell**: PowerShell description without PowerShell image
4. **Base64 Commands**: `-e*` parameter detection
5. **Obfuscation**: GZIP (*H4sI*), XOR (*bxor* AND *join*)

---

## Lab 8-9: Splunk Hunting Labs

### Lab 8: Basic Splunk (Boss of SOC v1)
**Splunk**: 172.16.84.101:8000 | admin:elsnalyst

#### Password Brute Force Detection
```splunk
index=botsv1 sourcetype=stream:http dest=192.168.250.70 http_method=POST form_data=*user*pass*
| stats count by src
```

#### Geolocation Analysis
```splunk
index=botsv1 sourcetype=stream:http dest=192.168.250.70 http_method=POST form_data=*user*pass*
| iplocation src | geostats latfield=lat longfield=lon count by src
```

### Lab 9: Advanced Splunk (Boss of SOC v2)
**Splunk**: 172.16.84.102:8000

#### PowerShell Empire Detection
```splunk
index=botsv2 sourcetype=stream:tcp ssl_issuer="C=US" 
index=botsv2 sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational dest=45.77.65.211
```

#### FTP Exfiltration
```splunk
index=botsv2 ftp sourcetype=stream:ftp src=* dest=160.153.91.7
| table time src filename method methodparameter reply_content
```

#### DNS Exfiltration
```splunk
index=botsv2 sourcetype=stream:dns hildegardsfarm.com message_type=QUERY
| eval query=mvdedup(query) | eval list=mozilla | `ut_parse_extended(query,list)` 
| `ut_shannon(ut_subdomain)` | table src dest query ut_subdomain ut_shannon
```

---

## Lab 10: Active Directory Attacks (Splunk)
**Splunk**: 172.16.84.103:8000

### Brute Force Detection
```splunk
# Kerberos non-existing accounts
index=adhunting sourcetype=XmlWinEventLog EventCode=4768 Status=0x6
| transaction IpAddress maxpause=5m | where eventcount > 5

# NTLM authentication failures  
index=adhunting source=XmlWinEventLog:Security EventCode=4776 Status=0xC0000064
| transaction Workstation maxpause=5m | where eventcount > 5
```

### Kerberoasting Detection
```splunk
# Service ticket requests with vulnerable encryption
index=adhunting EventCode=4769 EncryptionType IN (0x1, 0x3, 0x11, 0x12, 0x17, 0x18)

# Excessive service requests
index=adhunting EventCode=4769 ServiceName=*$ | stats count by Computer IpAddress
```

---

## Lab 11: Network Hunting Forensics
### Zeek Analysis Commands

**Long Connection Detection**:
```bash
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration
| awk 'BEGIN {FS="\t"} {arr[$1 FS $2 FS $3 FS $4] += $5} END {for (key in arr) printf "%s%s%s\n", key, FS, arr[key]}'
| sort -nrk 5 | head -n 10
```

**User Agent Analysis**:
```bash
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -n | head -n 10
```

**DNS Analysis with RITA**:
```bash
rita show-exploded-dns -H --limit 10 zeeklogs
```

---

## Lab 12: Osquery at Scale
### Network: 172.16.80.200 (client), 172.16.80.201 (fleet)
### Creds: hunter:hunter

### Linux Process Injection Detection
```sql
# ptrace scope monitoring
SELECT * FROM system_controls WHERE name='kernel.yama.ptrace_scope';

# Injected memory detection
SELECT process_memory_map.*, pid as mpid FROM process_memory_map 
LEFT JOIN processes USING (pid) WHERE process_memory_map.path LIKE '/%' 
AND process_memory_map.pseudo != 1 AND process_memory_map.path NOT LIKE '/lib%'
AND process_memory_map.permissions LIKE '%x%';
```

---

## Lab 13-14: Insider Threats (Network Analysis)

### PCAP Analysis Tools: NetworkMiner, Wireshark

#### Key Indicators
- **Rogue devices**: Non-domain machines, suspicious naming (rogue1)
- **Fake MAC addresses**: BEEEEFDEEAD, DEEEADBEEEEF  
- **Unusual traffic patterns**: TCP retransmissions, wrong port usage
- **Kali Linux detection**: Hostname changes, suspicious tools

#### Analysis Workflow
1. Load PCAP in NetworkMiner for overview
2. Check Hosts tab for anomalies
3. Examine Sessions and DNS tabs
4. Use Wireshark for detailed packet analysis
5. Look for ARP poisoning, MITM attacks

---

## Lab 15-16: Web Shells Detection

### Tools: LOKI IOC Scanner, NeoPI, PowerShell scripts

#### Detection Methods
1. **LOKI Scanning**: Signature-based detection
2. **NeoPI Analysis**: Entropy-based detection  
3. **File Stacking**: Creation time analysis
4. **Baseline Comparison**: MD5 hash differences
5. **Log Analysis**: IIS logs with Log Parser Studio

#### PowerShell Detection Scripts
```powershell
# File stacking by creation time
.\Get-TimeDiffFileStacking.ps1 C:\ "7/12/2017 9:00am"

# Hash comparison
.\Compare-FileHashesList.ps1 -ReferenceFile C:\Baseline.csv -DifferenceFile C:\Current.csv
```

---

## Lab 17: Advanced Endpoint Hunting

### .NET Assembly Detection via ETW
```powershell
# Custom ETW script for .NET assembly loading
# Monitor for in-memory .NET execution (BYOL techniques)
```

### Process Injection Detection
- **Memhunter**: Automated ETW-based detection
- **Captain**: API hooking for malicious events
- **Process Hacker 2**: Manual memory inspection

---

## Lab 18-19: Advanced Splunk Labs

### Lab 18: Complex Attack Scenarios
**Splunk**: 172.16.84.104:8000

#### PowerShell Empire Stager Detection
```splunk
index=* EventCode=4104 AND (psversiontable.psversion.major OR system.management.automation.utils)
| eval MessageDeobfuscated = replace(Message, "%", " ")
| search (EnableScriptBlockLogging OR ServerCertificateValidationCallback)
```

#### WMI Persistence Detection
```splunk
index=winsysmon EventCode=19 OR EventCode=20 OR EventCode=21
| table time, EventCode, Operation, Consumer, Query, Destination
```

### Lab 19: CrackMapExec Detection
**Splunk**: 172.16.84.105:8000

#### SMB Activity Detection
```splunk
index=zeek sourcetype=zeek:smb_files action=SMB::FILE_OPEN
| table id.resp_h, id.resp_p, id.orig_h, name
```

#### NTLM Authentication
```splunk
index=zeek sourcetype=zeek:ntlm
| table id.resp_h, username, domainname, success
```

---

## Lab 20: Linux Memory Analysis

### Volatility Linux Plugins
```bash
# Check for hidden LKMs
python vol.py --profile=LinuxProfile-2632 linux_check_modules -f infection.memory

# Syscall table analysis  
python vol.py --profile=LinuxProfile-2632 linux_check_syscall -f infection.memory

# Process analysis
python vol.py --profile=LinuxProfile-2632 linux_pslist -f infection.memory
```

### Rootkit Detection
- **Diamorphine**: Module hiding techniques
- **Reptile**: Advanced syscall hooking
- **LiME**: Memory acquisition tool

---

## General Best Practices

### Network Analysis
- Use NetworkMiner for PCAP overview, Wireshark for detailed analysis
- Focus on anomalous hostnames, MAC addresses, traffic patterns
- Look for protocol violations and suspicious user agents

### Memory Analysis  
- Use multiple tools (Redline + Volatility) for comprehensive coverage
- Check for process masquerading, injection, and network connections
- Extract suspicious modules and analyze execution chains

### Log Analysis
- Monitor PowerShell execution and script block logging
- Detect process injection through memory analysis tools
- Use ETW and API monitoring for advanced threats
- Correlate multiple event sources for accurate detection

### Tool Combinations
- **Static analysis**: IOCs, YARA rules, file hashes
- **Dynamic analysis**: Memory dumps, process monitoring  
- **Network analysis**: Traffic patterns, C2 communication
- **Endpoint detection**: Sysmon, PowerShell, ETW logs
