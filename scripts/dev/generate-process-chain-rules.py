#!/usr/bin/env python3
"""Generate crates/telltale-rules/data/process-chain.yaml.

Provenance: the parent/child pairs, source severities, MITRE technique IDs, and
human-readable reasons come from the irflow-timeline process-tree rule library
(https://github.com/r3nzsec/irflow-timeline, src/detection-rules.js). This
script re-expresses that behavioural reference in Telltale's rule vocabulary and
applies Telltale's own scoring model — it is not a mechanical severity copy.

Scoring model (see docs/process-chain-detections.md):

    score = tier_base + specificity + parent_confidence + impact,
            clamped into the tier band

    tier_base: informational 0, low 20, medium 40, high 55, critical 80
    tier_max:  informational 0, low 39, medium 49, high 79, critical 100

Run:  python3 scripts/dev/generate-process-chain-rules.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "crates" / "telltale-rules" / "data" / "process-chain.yaml"

# --------------------------------------------------------------------------
# Source library (verbatim pairs from detection-rules.js CHAIN_RULES).
# --------------------------------------------------------------------------

SOURCE = r"""
# Execution
winword.exe|cmd.exe|3|Word -> cmd - macro execution|T1204.002
winword.exe|powershell.exe|3|Word -> PowerShell - macro execution|T1059.001
winword.exe|wscript.exe|3|Word -> WScript - VBS macro dropper|T1059.005
winword.exe|cscript.exe|3|Word -> CScript - VBS macro dropper|T1059.005
winword.exe|msdt.exe|3|Word -> msdt - Follina (CVE-2022-30190)|T1203
winword.exe|bash.exe|3|Word -> bash - unusual execution chain|T1059.004
excel.exe|cmd.exe|3|Excel -> cmd - macro or DDE execution|T1204.002
excel.exe|powershell.exe|3|Excel -> PowerShell - macro execution|T1059.001
excel.exe|wscript.exe|3|Excel -> WScript - VBS dropper|T1059.005
excel.exe|cscript.exe|3|Excel -> CScript - VBS dropper|T1059.005
powerpnt.exe|cmd.exe|3|PowerPoint -> cmd - action or macro|T1204.002
powerpnt.exe|powershell.exe|3|PowerPoint -> PowerShell - action or macro|T1059.001
powerpnt.exe|wscript.exe|3|PowerPoint -> WScript - PowerPoint spawning WScript|T1059.005
outlook.exe|cmd.exe|2|Outlook -> cmd - embedded object or preview|T1566.001
outlook.exe|powershell.exe|3|Outlook -> PowerShell - phishing execution|T1566.001
outlook.exe|wscript.exe|2|Outlook -> WScript - script attachment|T1566.001
outlook.exe|cscript.exe|2|Outlook -> CScript - script attachment|T1566.001
outlook.exe|msdt.exe|3|Outlook -> msdt - Follina variant|T1203
onenote.exe|cmd.exe|3|OneNote -> cmd - embedded script or HTA|T1204.002
onenote.exe|powershell.exe|3|OneNote -> PowerShell - embedded payload|T1059.001
onenote.exe|wscript.exe|3|OneNote -> WScript - embedded VBS|T1059.005
onenote.exe|cscript.exe|3|OneNote -> CScript - embedded VBS|T1059.005
msaccess.exe|cmd.exe|3|Access -> cmd - macro execution|T1204.002
msaccess.exe|powershell.exe|3|Access -> PowerShell - macro execution|T1059.001
mspub.exe|cmd.exe|3|Publisher -> cmd - macro execution|T1204.002
mspub.exe|powershell.exe|3|Publisher -> PowerShell - macro execution|T1059.001
wscript.exe|cmd.exe|2|WScript -> cmd - VBS or JS payload stage 2|T1059.005
wscript.exe|powershell.exe|2|WScript -> PowerShell - VBS to PowerShell stager|T1059.005
wscript.exe|cscript.exe|1|WScript -> CScript - script engine switch|T1059.005
cscript.exe|cmd.exe|2|CScript -> cmd - script payload|T1059.005
cscript.exe|powershell.exe|2|CScript -> PowerShell - script stager|T1059.005
powershell.exe|powershell.exe|1|PowerShell -> PowerShell - double-hop or AMSI bypass|T1059.001
powershell.exe|cmd.exe|0|PowerShell -> cmd - context-dependent, commonly benign|T1059.003
powershell.exe|wscript.exe|1|PowerShell -> WScript - polyglot or evasion|T1059.005
powershell.exe|cscript.exe|1|PowerShell -> CScript - script execution|T1059.005
powershell.exe|bash.exe|1|PowerShell -> bash - cross-subsystem execution|T1059.004
cmd.exe|powershell.exe|1|cmd -> PowerShell - common in multi-stage payloads|T1059.001
cmd.exe|wscript.exe|1|cmd -> WScript - script execution|T1059.005
cmd.exe|cscript.exe|1|cmd -> CScript - script execution|T1059.005
svchost.exe|cmd.exe|2|svchost -> cmd - service abuse or lateral movement|T1569.002
svchost.exe|powershell.exe|2|svchost -> PowerShell - service-based execution|T1569.002
svchost.exe|wscript.exe|2|svchost -> WScript - unusual service behaviour|T1059.005
svchost.exe|cscript.exe|2|svchost -> CScript - unusual service behaviour|T1059.005
wmiprvse.exe|cmd.exe|2|WMIPrvSE -> cmd - WMI lateral movement|T1047
wmiprvse.exe|powershell.exe|2|WMIPrvSE -> PowerShell - WMI execution|T1047
searchprotocolhost.exe|cmd.exe|2|SearchProtocolHost -> cmd - exploitation|T1203
searchindexer.exe|cmd.exe|2|SearchIndexer -> cmd - exploitation|T1203
csrss.exe|cmd.exe|3|CSRSS -> cmd - kernel-mode process injection|T1055
csrss.exe|powershell.exe|3|CSRSS -> PowerShell - critical anomaly|T1055
smss.exe|cmd.exe|3|SMSS -> cmd - bootkit or rootkit indicator|T1055
smss.exe|powershell.exe|3|SMSS -> PowerShell - critical anomaly|T1055
winlogon.exe|cmd.exe|2|winlogon -> cmd - Sticky Keys or accessibility backdoor|T1055
winlogon.exe|powershell.exe|2|winlogon -> PowerShell - exploitation|T1055
spoolsv.exe|cmd.exe|3|spoolsv -> cmd - PrintNightmare|T1203
spoolsv.exe|powershell.exe|3|spoolsv -> PowerShell - PrintNightmare|T1203
spoolsv.exe|net.exe|2|spoolsv -> net - PrintNightmare account creation|T1203
dllhost.exe|cmd.exe|2|dllhost -> cmd - COM object hijack execution|T1546.015
dllhost.exe|powershell.exe|2|dllhost -> PowerShell - COM hijack|T1546.015
services.exe|cmd.exe|2|services -> cmd - malicious service installed|T1543.003
services.exe|powershell.exe|2|services -> PowerShell - malicious service|T1543.003
chrome.exe|cmd.exe|2|Chrome -> cmd - browser exploitation|T1189
chrome.exe|powershell.exe|3|Chrome -> PowerShell - browser exploitation|T1189
msedge.exe|cmd.exe|2|Edge -> cmd - browser exploitation|T1189
msedge.exe|powershell.exe|3|Edge -> PowerShell - browser exploitation|T1189
firefox.exe|cmd.exe|2|Firefox -> cmd - browser exploitation|T1189
firefox.exe|powershell.exe|3|Firefox -> PowerShell - browser exploitation|T1189
iexplore.exe|cmd.exe|2|Internet Explorer -> cmd - browser exploitation|T1189
iexplore.exe|powershell.exe|3|Internet Explorer -> PowerShell - browser exploitation|T1189
acrord32.exe|cmd.exe|3|Acrobat Reader -> cmd - PDF exploitation|T1203
acrord32.exe|powershell.exe|3|Acrobat Reader -> PowerShell - PDF exploitation|T1203
foxitreader.exe|cmd.exe|3|Foxit Reader -> cmd - PDF exploitation|T1203
foxitreader.exe|powershell.exe|3|Foxit Reader -> PowerShell - PDF exploitation|T1203
w3wp.exe|cmd.exe|3|IIS worker -> cmd - web shell execution|T1190
w3wp.exe|powershell.exe|3|IIS worker -> PowerShell - web shell execution|T1190
w3wp.exe|csc.exe|3|IIS worker -> csc - web shell compilation|T1190
java.exe|cmd.exe|2|java -> cmd - web shell (Tomcat or WebLogic)|T1190
java.exe|powershell.exe|2|java -> PowerShell - web shell|T1190
java.exe|bash.exe|2|java -> bash - web shell via WSL|T1190
javaw.exe|cmd.exe|2|javaw -> cmd - web shell|T1190
tomcat.exe|cmd.exe|3|Tomcat -> cmd - web shell|T1190
httpd.exe|cmd.exe|3|Apache -> cmd - web shell|T1190
msexchangemailboxreplication.exe|cmd.exe|3|Exchange mailbox replication -> cmd - ProxyShell or OWASSRF|T1190
umworkerprocess.exe|cmd.exe|3|Exchange UM worker -> cmd - ProxyLogon exploitation|T1190
umworkerprocess.exe|powershell.exe|3|Exchange UM worker -> PowerShell - exploitation|T1190
sqlservr.exe|cmd.exe|3|SQL Server -> cmd - xp_cmdshell or SQL injection|T1190
sqlservr.exe|powershell.exe|3|SQL Server -> PowerShell - SQL injection|T1190
nginx.exe|cmd.exe|3|nginx -> cmd - web shell|T1190
# Defense Evasion
winword.exe|mshta.exe|3|Word -> mshta - HTA proxy execution|T1218.005
winword.exe|regsvr32.exe|3|Word -> regsvr32 - COM scriptlet execution|T1218.010
winword.exe|rundll32.exe|3|Word -> rundll32 - DLL proxy execution|T1218.011
excel.exe|mshta.exe|3|Excel -> mshta - HTA execution|T1218.005
excel.exe|regsvr32.exe|3|Excel -> regsvr32 - Squiblydoo|T1218.010
excel.exe|rundll32.exe|3|Excel -> rundll32 - DLL execution|T1218.011
powerpnt.exe|mshta.exe|3|PowerPoint -> mshta - PowerPoint spawning mshta|T1218.005
outlook.exe|mshta.exe|3|Outlook -> mshta - HTML attachment execution|T1218.005
outlook.exe|regsvr32.exe|3|Outlook -> regsvr32 - COM scriptlet execution|T1218.010
outlook.exe|rundll32.exe|2|Outlook -> rundll32 - DLL proxy execution|T1218.011
onenote.exe|mshta.exe|3|OneNote -> mshta - embedded HTA|T1218.005
rundll32.exe|cmd.exe|2|rundll32 -> cmd - DLL proxy to shell|T1218.011
rundll32.exe|powershell.exe|2|rundll32 -> PowerShell - DLL proxy execution|T1218.011
rundll32.exe|cscript.exe|2|rundll32 -> CScript - proxy execution|T1218.011
rundll32.exe|wscript.exe|2|rundll32 -> WScript - proxy execution|T1218.011
rundll32.exe|rundll32.exe|2|rundll32 -> rundll32 - injection or hollowing|T1218.011
regsvr32.exe|cmd.exe|2|regsvr32 -> cmd - Squiblydoo or COM scriptlet|T1218.010
regsvr32.exe|powershell.exe|2|regsvr32 -> PowerShell - scriptlet execution|T1218.010
regsvr32.exe|wscript.exe|2|regsvr32 -> WScript - COM registration abuse|T1218.010
regsvr32.exe|cscript.exe|2|regsvr32 -> CScript - COM registration abuse|T1218.010
regsvr32.exe|mshta.exe|2|regsvr32 -> mshta - chained proxy execution|T1218.010
mshta.exe|cmd.exe|2|mshta -> cmd - HTA payload execution|T1218.005
mshta.exe|powershell.exe|3|mshta -> PowerShell - HTA to PowerShell cradle|T1218.005
mshta.exe|wscript.exe|2|mshta -> WScript - chained script execution|T1218.005
mshta.exe|cscript.exe|2|mshta -> CScript - chained script execution|T1218.005
mshta.exe|rundll32.exe|2|mshta -> rundll32 - chained proxy execution|T1218.005
mshta.exe|regsvr32.exe|2|mshta -> regsvr32 - chained proxy execution|T1218.005
cmstp.exe|cmd.exe|2|CMSTP -> cmd - INF-based bypass|T1218.003
cmstp.exe|powershell.exe|2|CMSTP -> PowerShell - INF-based bypass|T1218.003
msiexec.exe|cmd.exe|2|msiexec -> cmd - malicious MSI custom action|T1218.007
msiexec.exe|powershell.exe|2|msiexec -> PowerShell - MSI payload|T1218.007
msiexec.exe|rundll32.exe|1|msiexec -> rundll32 - MSI DLL custom action|T1218.007
cmd.exe|msiexec.exe|1|cmd -> msiexec - remote MSI install|T1218.007
installutil.exe|cmd.exe|2|InstallUtil -> cmd - .NET payload execution|T1218.004
msbuild.exe|cmd.exe|2|MSBuild -> cmd - inline task execution|T1127.001
msbuild.exe|powershell.exe|2|MSBuild -> PowerShell - inline task execution|T1127.001
xwizard.exe|cmd.exe|2|xwizard -> cmd - COM object hijack|T1218
pcalua.exe|cmd.exe|2|pcalua -> cmd - proxy execution|T1218
pcalua.exe|powershell.exe|2|pcalua -> PowerShell - proxy execution|T1218
pcalua.exe|mshta.exe|2|pcalua -> mshta - proxy execution|T1218
forfiles.exe|cmd.exe|1|forfiles -> cmd - indirect command execution|T1202
forfiles.exe|powershell.exe|2|forfiles -> PowerShell - indirect execution|T1202
wscript.exe|mshta.exe|2|WScript -> mshta - chained execution|T1218.005
wscript.exe|rundll32.exe|2|WScript -> rundll32 - DLL load via script|T1218.011
wscript.exe|regsvr32.exe|2|WScript -> regsvr32 - COM registration abuse|T1218.010
cscript.exe|mshta.exe|2|CScript -> mshta - chained execution|T1218.005
cscript.exe|rundll32.exe|2|CScript -> rundll32 - DLL load via script|T1218.011
powershell.exe|mshta.exe|2|PowerShell -> mshta - proxy execution|T1218.005
powershell.exe|rundll32.exe|2|PowerShell -> rundll32 - DLL proxy execution|T1218.011
powershell.exe|regsvr32.exe|2|PowerShell -> regsvr32 - COM scriptlet|T1218.010
cmd.exe|mshta.exe|2|cmd -> mshta - HTA execution|T1218.005
cmd.exe|rundll32.exe|1|cmd -> rundll32 - DLL execution|T1218.011
cmd.exe|regsvr32.exe|1|cmd -> regsvr32 - COM registration|T1218.010
cmd.exe|netsh.exe|1|cmd -> netsh - firewall manipulation|T1562.004
svchost.exe|mshta.exe|3|svchost -> mshta - service hijack indicator|T1218.005
svchost.exe|rundll32.exe|1|svchost -> rundll32 - DLL service execution|T1218.011
svchost.exe|regsvr32.exe|2|svchost -> regsvr32 - COM registration abuse|T1218.010
wmiprvse.exe|mshta.exe|3|WMIPrvSE -> mshta - WMI-based proxy execution|T1218.005
wmiprvse.exe|rundll32.exe|2|WMIPrvSE -> rundll32 - WMI proxy execution|T1218.011
wmiprvse.exe|regsvr32.exe|2|WMIPrvSE -> regsvr32 - WMI proxy execution|T1218.010
werfault.exe|cmd.exe|2|WerFault -> cmd - crash handler abuse or injection|T1036
werfault.exe|powershell.exe|2|WerFault -> PowerShell - process injection indicator|T1036
spoolsv.exe|rundll32.exe|2|spoolsv -> rundll32 - spooler exploitation|T1203
cmd.exe|wevtutil.exe|3|cmd -> wevtutil - event log clearing or tampering|T1070.001
powershell.exe|wevtutil.exe|3|PowerShell -> wevtutil - event log clearing|T1070.001
cmd.exe|fsutil.exe|1|cmd -> fsutil - timestomping or USN journal deletion|T1070
powershell.exe|fsutil.exe|1|PowerShell -> fsutil - artifact manipulation|T1070
powershell.exe|netsh.exe|1|PowerShell -> netsh - firewall modification|T1562.004
powershell.exe|mpcmdrun.exe|1|PowerShell -> MpCmdRun - Defender manipulation|T1562.001
cmd.exe|taskkill.exe|1|cmd -> taskkill - process termination|T1562.001
powershell.exe|taskkill.exe|1|PowerShell -> taskkill - security tool termination|T1562.001
cmd.exe|fltmc.exe|3|cmd -> fltMC - minifilter unload (EDR bypass)|T1562.001
powershell.exe|fltmc.exe|3|PowerShell -> fltMC - minifilter or driver unload|T1562.001
bash.exe|cmd.exe|1|bash -> cmd - cross-subsystem execution|T1202
wsl.exe|cmd.exe|1|WSL -> cmd - cross-subsystem execution|T1202
wsl.exe|powershell.exe|1|WSL -> PowerShell - cross-subsystem execution|T1202
# Command And Control
winword.exe|certutil.exe|3|Word -> certutil - download cradle|T1105
winword.exe|bitsadmin.exe|3|Word -> bitsadmin - BITS download|T1197
excel.exe|certutil.exe|3|Excel -> certutil - download cradle|T1105
rundll32.exe|certutil.exe|2|rundll32 -> certutil - staged download|T1105
cmd.exe|certutil.exe|2|cmd -> certutil - LOLBin download or decode|T1105
powershell.exe|certutil.exe|2|PowerShell -> certutil - download or decode fallback|T1105
cmd.exe|bitsadmin.exe|2|cmd -> bitsadmin - BITS job download|T1197
powershell.exe|bitsadmin.exe|2|PowerShell -> bitsadmin - BITS download|T1197
wscript.exe|certutil.exe|2|WScript -> certutil - download stage|T1105
svchost.exe|certutil.exe|2|svchost -> certutil - download via service|T1105
wmiprvse.exe|certutil.exe|2|WMIPrvSE -> certutil - WMI-staged download|T1105
cmd.exe|wget.exe|1|cmd -> wget - file download|T1105
anydesk.exe|cmd.exe|2|AnyDesk -> cmd - remote access tool abuse|T1219
anydesk.exe|powershell.exe|2|AnyDesk -> PowerShell - remote access tool abuse|T1219
teamviewer.exe|cmd.exe|2|TeamViewer -> cmd - remote access tool abuse|T1219
teamviewer.exe|powershell.exe|2|TeamViewer -> PowerShell - remote access tool abuse|T1219
teamviewer_service.exe|cmd.exe|2|TeamViewer service -> cmd - remote access tool abuse|T1219
teamviewer_service.exe|powershell.exe|2|TeamViewer service -> PowerShell - remote access tool abuse|T1219
screenconnect.clientservice.exe|cmd.exe|2|ScreenConnect -> cmd - RMM abuse|T1219
screenconnect.clientservice.exe|powershell.exe|2|ScreenConnect -> PowerShell - RMM abuse|T1219
screenconnect.windowsclient.exe|cmd.exe|2|ScreenConnect client -> cmd - RMM abuse|T1219
screenconnect.windowsclient.exe|powershell.exe|2|ScreenConnect client -> PowerShell - RMM abuse|T1219
ateraagent.exe|cmd.exe|2|Atera -> cmd - RMM abuse|T1219
ateraagent.exe|powershell.exe|2|Atera -> PowerShell - RMM abuse|T1219
splashtop.exe|cmd.exe|2|Splashtop -> cmd - RMM abuse|T1219
splashtop.exe|powershell.exe|2|Splashtop -> PowerShell - RMM abuse|T1219
cmd.exe|ngrok.exe|3|cmd -> ngrok - reverse tunnel for command and control|T1572
powershell.exe|ngrok.exe|3|PowerShell -> ngrok - tunnel establishment|T1572
cmd.exe|chisel.exe|3|cmd -> Chisel - SOCKS proxy tunnel|T1572
powershell.exe|chisel.exe|3|PowerShell -> Chisel - proxy tunnel|T1572
cmd.exe|plink.exe|2|cmd -> plink - SSH tunnel|T1572
powershell.exe|plink.exe|2|PowerShell -> plink - SSH tunnel|T1572
w3wp.exe|certutil.exe|3|IIS worker -> certutil - web shell download|T1190
# Persistence
winword.exe|schtasks.exe|2|Word -> schtasks - persistence via macro|T1053.005
taskeng.exe|cmd.exe|1|Task Engine -> cmd - scheduled task execution|T1053.005
taskeng.exe|powershell.exe|1|Task Engine -> PowerShell - scheduled task execution|T1053.005
taskhostw.exe|cmd.exe|1|TaskHost -> cmd - scheduled task execution|T1053.005
taskhostw.exe|powershell.exe|1|TaskHost -> PowerShell - scheduled task execution|T1053.005
cmd.exe|schtasks.exe|1|cmd -> schtasks - scheduled task creation|T1053.005
powershell.exe|schtasks.exe|1|PowerShell -> schtasks - scheduled task creation|T1053.005
rundll32.exe|schtasks.exe|2|rundll32 -> schtasks - DLL-based persistence|T1053.005
mshta.exe|schtasks.exe|2|mshta -> schtasks - HTA persistence install|T1053.005
cmd.exe|reg.exe|1|cmd -> reg - Run key persistence|T1547.001
powershell.exe|reg.exe|1|PowerShell -> reg - Run key modification|T1547.001
cmd.exe|sc.exe|1|cmd -> sc - service creation or modification|T1543.003
powershell.exe|sc.exe|1|PowerShell -> sc - service manipulation|T1543.003
cmd.exe|wmic.exe|1|cmd -> wmic - WMI event subscription|T1546.003
powershell.exe|wmic.exe|1|PowerShell -> wmic - WMI persistence|T1546.003
cmd.exe|xcopy.exe|0|cmd -> xcopy - startup folder persistence|T1547.001
cmd.exe|copy.exe|0|cmd -> copy - startup folder persistence|T1547.001
winlogon.exe|sethc.exe|3|winlogon -> sethc - Sticky Keys backdoor|T1546.008
sethc.exe|cmd.exe|3|sethc -> cmd - accessibility backdoor active|T1546.008
utilman.exe|cmd.exe|3|utilman -> cmd - accessibility backdoor|T1546.008
osk.exe|cmd.exe|3|On-Screen Keyboard -> cmd - accessibility backdoor|T1546.008
narrator.exe|cmd.exe|3|Narrator -> cmd - accessibility backdoor|T1546.008
magnify.exe|cmd.exe|3|Magnifier -> cmd - accessibility backdoor|T1546.008
displayswitch.exe|cmd.exe|3|DisplaySwitch -> cmd - accessibility backdoor|T1546.008
atbroker.exe|cmd.exe|3|ATBroker -> cmd - accessibility backdoor|T1546.008
# Discovery
rundll32.exe|net.exe|1|rundll32 -> net - post-exploitation reconnaissance|T1087.002
powershell.exe|whoami.exe|1|PowerShell -> whoami - user context enumeration|T1033
cmd.exe|whoami.exe|1|cmd -> whoami - user context enumeration|T1033
powershell.exe|systeminfo.exe|1|PowerShell -> systeminfo - system fingerprinting|T1082
cmd.exe|systeminfo.exe|1|cmd -> systeminfo - system fingerprinting|T1082
powershell.exe|hostname.exe|0|PowerShell -> hostname - hostname discovery|T1082
cmd.exe|hostname.exe|0|cmd -> hostname - hostname discovery|T1082
powershell.exe|nltest.exe|1|PowerShell -> nltest - domain trust enumeration|T1482
cmd.exe|nltest.exe|1|cmd -> nltest - domain trust enumeration|T1482
powershell.exe|dsquery.exe|1|PowerShell -> dsquery - Active Directory object enumeration|T1018
cmd.exe|dsquery.exe|1|cmd -> dsquery - Active Directory enumeration|T1018
powershell.exe|dsget.exe|1|PowerShell -> dsget - Active Directory attribute query|T1087.002
powershell.exe|csvde.exe|1|PowerShell -> csvde - bulk Active Directory export|T1087.002
powershell.exe|ldifde.exe|1|PowerShell -> ldifde - LDAP data export|T1087.002
cmd.exe|csvde.exe|1|cmd -> csvde - bulk Active Directory export|T1087.002
powershell.exe|net1.exe|1|PowerShell -> net1 - net.exe proxy|T1087.002
cmd.exe|net1.exe|1|cmd -> net1 - net.exe proxy|T1087.002
powershell.exe|ipconfig.exe|0|PowerShell -> ipconfig - network configuration discovery|T1016
cmd.exe|ipconfig.exe|0|cmd -> ipconfig - network configuration discovery|T1016
powershell.exe|arp.exe|0|PowerShell -> arp - ARP table discovery|T1016
cmd.exe|arp.exe|0|cmd -> arp - ARP table discovery|T1016
powershell.exe|nslookup.exe|0|PowerShell -> nslookup - DNS reconnaissance|T1018
cmd.exe|nslookup.exe|0|cmd -> nslookup - DNS reconnaissance|T1018
powershell.exe|netstat.exe|0|PowerShell -> netstat - network connection discovery|T1049
cmd.exe|netstat.exe|0|cmd -> netstat - network connection discovery|T1049
powershell.exe|route.exe|0|PowerShell -> route - routing table discovery|T1016
cmd.exe|route.exe|0|cmd -> route - routing table discovery|T1016
powershell.exe|nbtstat.exe|0|PowerShell -> nbtstat - NetBIOS discovery|T1016
cmd.exe|tracert.exe|0|cmd -> tracert - route tracing|T1016
cmd.exe|pathping.exe|0|cmd -> pathping - route tracing|T1016
powershell.exe|tasklist.exe|0|PowerShell -> tasklist - process enumeration|T1057
cmd.exe|tasklist.exe|0|cmd -> tasklist - process enumeration|T1057
powershell.exe|qprocess.exe|0|PowerShell -> qprocess - terminal services process list|T1057
powershell.exe|icacls.exe|0|PowerShell -> icacls - permission enumeration|T1083
cmd.exe|icacls.exe|0|cmd -> icacls - permission enumeration|T1083
cmd.exe|accesschk.exe|1|cmd -> accesschk - Sysinternals permission check|T1083
powershell.exe|adfind.exe|3|PowerShell -> AdFind - bulk Active Directory enumeration|T1018
cmd.exe|adfind.exe|3|cmd -> AdFind - bulk Active Directory enumeration|T1018
powershell.exe|bloodhound.exe|3|PowerShell -> BloodHound - Active Directory attack path mapping|T1087.002
cmd.exe|sharphound.exe|3|cmd -> SharpHound - BloodHound data collector|T1087.002
powershell.exe|sharphound.exe|3|PowerShell -> SharpHound - Active Directory collector|T1087.002
powershell.exe|seatbelt.exe|2|PowerShell -> Seatbelt - GhostPack host survey|T1082
cmd.exe|seatbelt.exe|2|cmd -> Seatbelt - GhostPack host survey|T1082
svchost.exe|whoami.exe|2|svchost -> whoami - post-exploitation via service|T1033
svchost.exe|net.exe|1|svchost -> net - reconnaissance via service context|T1087.002
w3wp.exe|whoami.exe|3|IIS worker -> whoami - web shell reconnaissance|T1190
w3wp.exe|net.exe|3|IIS worker -> net - web shell enumeration|T1190
# Credential Access
powershell.exe|rubeus.exe|3|PowerShell -> Rubeus - Kerberos attack tool|T1558.003
cmd.exe|rubeus.exe|3|cmd -> Rubeus - Kerberos attack tool|T1558.003
lsass.exe|cmd.exe|3|LSASS -> cmd - credential dumping or injection|T1003.001
lsass.exe|powershell.exe|3|LSASS -> PowerShell - process injection into LSASS|T1003.001
lsass.exe|rundll32.exe|3|LSASS -> rundll32 - skeleton key or SSP injection|T1003.001
cmd.exe|procdump.exe|3|cmd -> ProcDump - LSASS memory dump|T1003.001
powershell.exe|procdump.exe|3|PowerShell -> ProcDump - LSASS memory dump|T1003.001
cmd.exe|mimikatz.exe|3|cmd -> Mimikatz - credential dumping|T1003.001
powershell.exe|mimikatz.exe|3|PowerShell -> Mimikatz - credential dumping|T1003.001
cmd.exe|sekurlsa.exe|3|cmd -> sekurlsa - credential extraction|T1003.001
cmd.exe|lazagne.exe|3|cmd -> LaZagne - credential recovery from applications|T1555
powershell.exe|lazagne.exe|3|PowerShell -> LaZagne - credential harvesting|T1555
cmd.exe|wbadmin.exe|2|cmd -> wbadmin - backup-based credential extraction|T1003.003
cmd.exe|diskshadow.exe|2|cmd -> diskshadow - NTDS.dit shadow copy|T1003.003
cmd.exe|ntdsutil.exe|3|cmd -> ntdsutil - Active Directory database extraction|T1003.003
powershell.exe|ntdsutil.exe|3|PowerShell -> ntdsutil - NTDS.dit dump|T1003.003
cmd.exe|klist.exe|0|cmd -> klist - Kerberos ticket inspection|T1558
powershell.exe|klist.exe|0|PowerShell -> klist - Kerberos ticket enumeration|T1558
cmd.exe|esentutl.exe|2|cmd -> esentutl - ESE database extraction|T1003.003
powershell.exe|esentutl.exe|2|PowerShell -> esentutl - locked file copy|T1003.003
# Lateral Movement
psexesvc.exe|cmd.exe|2|PsExecSvc -> cmd - remote execution (target side)|T1570
psexesvc.exe|powershell.exe|2|PsExecSvc -> PowerShell - remote execution (target side)|T1570
services.exe|psexesvc.exe|2|services -> PsExecSvc - inbound lateral movement|T1570
wsmprovhost.exe|cmd.exe|2|WinRM -> cmd - remote PowerShell session to shell|T1021.006
wsmprovhost.exe|powershell.exe|2|WinRM -> PowerShell - remote PowerShell session|T1021.006
wsmprovhost.exe|whoami.exe|2|WinRM -> whoami - remote session reconnaissance|T1021.006
wsmprovhost.exe|net.exe|2|WinRM -> net - remote session enumeration|T1021.006
mmc.exe|cmd.exe|2|MMC -> cmd - DCOM lateral movement|T1021.003
mmc.exe|powershell.exe|2|MMC -> PowerShell - DCOM execution|T1021.003
sshd.exe|cmd.exe|1|sshd -> cmd - SSH-based remote access|T1021.004
sshd.exe|powershell.exe|1|sshd -> PowerShell - SSH remote execution|T1021.004
cmd.exe|gpupdate.exe|1|cmd -> gpupdate - GPO-based deployment|T1484.001
powershell.exe|gpupdate.exe|1|PowerShell -> gpupdate - GPO-based deployment|T1484.001
# Collection
cmd.exe|rar.exe|2|cmd -> rar - archive creation for exfiltration|T1560.001
powershell.exe|rar.exe|2|PowerShell -> rar - data staging|T1560.001
cmd.exe|7z.exe|1|cmd -> 7z - archive creation|T1560.001
powershell.exe|7z.exe|1|PowerShell -> 7z - data staging|T1560.001
cmd.exe|7za.exe|2|cmd -> 7za - archive creation (common in ransomware toolkits)|T1560.001
cmd.exe|makecab.exe|1|cmd -> makecab - LOLBin archive creation|T1560.001
powershell.exe|makecab.exe|1|PowerShell -> makecab - LOLBin archive creation|T1560.001
# Exfiltration
cmd.exe|ftp.exe|1|cmd -> ftp - FTP data transfer|T1048.003
powershell.exe|ftp.exe|1|PowerShell -> ftp - FTP data transfer|T1048.003
cmd.exe|scp.exe|1|cmd -> scp - SCP file transfer|T1048
cmd.exe|sftp.exe|1|cmd -> sftp - SFTP file transfer|T1048
cmd.exe|rclone.exe|3|cmd -> rclone - cloud storage exfiltration|T1567.002
powershell.exe|rclone.exe|3|PowerShell -> rclone - cloud storage exfiltration|T1567.002
cmd.exe|megasync.exe|3|cmd -> MEGASync - cloud exfiltration|T1567.002
cmd.exe|megacmd.exe|3|cmd -> MEGAcmd - cloud exfiltration CLI|T1567.002
powershell.exe|megacmd.exe|3|PowerShell -> MEGAcmd - cloud exfiltration|T1567.002
"""

# Rules that need an explicit id/variant because the same parent->child pair
# carries more than one behavioural interpretation in the source library, or
# because a blanket pair would mislabel routine administration.
#
# Each entry: (parent, child, category) -> dict of overrides.
EXPLICIT: list[dict] = [
    # --- vssadmin: administrative shadow-copy access vs ransomware deletion ---
    dict(
        id="procchain.credaccess.vssadmin_shadow_access",
        parent="cmd", child="vssadmin", category="credential_access",
        tier="medium", technique="T1003.003",
        reason="cmd -> vssadmin - shadow copy created or listed, a precursor to NTDS.dit or SAM extraction",
        cmdline_none=[r"\bdelete\b", r"\bresize\b"],
        title="cmd created or listed a Volume Shadow Copy",
    ),
    dict(
        id="procchain.credaccess.vssadmin_shadow_access_ps",
        parent="powershell", child="vssadmin", category="credential_access",
        tier="medium", technique="T1003.003",
        reason="PowerShell -> vssadmin - shadow copy created or listed, a precursor to NTDS.dit or SAM extraction",
        cmdline_none=[r"\bdelete\b", r"\bresize\b"],
        title="PowerShell created or listed a Volume Shadow Copy",
    ),
    dict(
        id="procchain.impact.vssadmin_shadow_delete",
        parent="cmd", child="vssadmin", category="impact",
        tier="critical", technique="T1490", impact=True,
        reason="cmd -> vssadmin - shadow copies deleted or resized away, the canonical ransomware recovery-inhibition step",
        cmdline_any=[r"delete\s+shadows", r"resize\s+shadowstorage"],
        title="cmd deleted Volume Shadow Copies",
    ),
    dict(
        id="procchain.impact.vssadmin_shadow_delete_ps",
        parent="powershell", child="vssadmin", category="impact",
        tier="critical", technique="T1490", impact=True,
        reason="PowerShell -> vssadmin - shadow copies deleted or resized away, the canonical ransomware recovery-inhibition step",
        cmdline_any=[r"delete\s+shadows", r"resize\s+shadowstorage"],
        title="PowerShell deleted Volume Shadow Copies",
    ),
    # --- wbadmin: backup inspection vs catalog deletion ---
    dict(
        id="procchain.impact.wbadmin_backup_delete",
        parent="cmd", child="wbadmin", category="impact",
        tier="critical", technique="T1490", impact=True,
        reason="cmd -> wbadmin - backup catalog or system state backups deleted, inhibiting recovery",
        cmdline_any=[r"delete\s+(catalog|systemstatebackup|backup)"],
        title="cmd deleted Windows Backup data",
    ),
    dict(
        id="procchain.impact.wbadmin_backup_delete_ps",
        parent="powershell", child="wbadmin", category="impact",
        tier="critical", technique="T1490", impact=True,
        reason="PowerShell -> wbadmin - backup catalog or system state backups deleted, inhibiting recovery",
        cmdline_any=[r"delete\s+(catalog|systemstatebackup|backup)"],
        title="PowerShell deleted Windows Backup data",
    ),
    # --- bcdedit: routine boot inspection vs recovery sabotage ---
    dict(
        id="procchain.impact.bcdedit_recovery_disable",
        parent="cmd", child="bcdedit", category="impact",
        tier="critical", technique="T1490", impact=True,
        reason="cmd -> bcdedit - Windows recovery or boot failure handling disabled",
        cmdline_any=[r"recoveryenabled\s+no", r"bootstatuspolicy\s+ignoreallfailures", r"\bsafeboot\b"],
        title="cmd disabled Windows recovery via bcdedit",
    ),
    dict(
        id="procchain.impact.bcdedit_recovery_disable_ps",
        parent="powershell", child="bcdedit", category="impact",
        tier="critical", technique="T1490", impact=True,
        reason="PowerShell -> bcdedit - Windows recovery or boot failure handling disabled",
        cmdline_any=[r"recoveryenabled\s+no", r"bootstatuspolicy\s+ignoreallfailures", r"\bsafeboot\b"],
        title="PowerShell disabled Windows recovery via bcdedit",
    ),
    dict(
        id="procchain.discovery.bcdedit_enumerate",
        parent="cmd", child="bcdedit", category="discovery",
        tier="informational", technique="T1082",
        reason="cmd -> bcdedit - boot configuration inspected",
        cmdline_none=[r"\bset\b", r"\bdelete\b", r"/set", r"/delete"],
        title="cmd inspected boot configuration",
    ),
    # --- wmic: WMI query vs persistence vs shadow-copy deletion ---
    dict(
        id="procchain.impact.wmic_shadowcopy_delete",
        parent="cmd", child="wmic", category="impact",
        tier="critical", technique="T1490", impact=True,
        reason="cmd -> wmic - shadow copies deleted through WMI, a ransomware recovery-inhibition step",
        cmdline_any=[r"shadowcopy.*\bdelete\b"],
        title="cmd deleted shadow copies via WMI",
    ),
    dict(
        id="procchain.impact.wmic_shadowcopy_delete_ps",
        parent="powershell", child="wmic", category="impact",
        tier="critical", technique="T1490", impact=True,
        reason="PowerShell -> wmic - shadow copies deleted through WMI, a ransomware recovery-inhibition step",
        cmdline_any=[r"shadowcopy.*\bdelete\b"],
        title="PowerShell deleted shadow copies via WMI",
    ),
    dict(
        id="procchain.persistence.wmic_event_subscription",
        parent="cmd", child="wmic", category="persistence",
        tier="medium", technique="T1546.003",
        reason="cmd -> wmic - WMI event subscription or remote process creation",
        cmdline_any=[r"eventfilter", r"eventconsumer", r"__filtertoconsumerbinding", r"process\s+call\s+create", r"/node:"],
        title="cmd used wmic for WMI persistence or remote execution",
    ),
    dict(
        id="procchain.persistence.wmic_event_subscription_ps",
        parent="powershell", child="wmic", category="persistence",
        tier="medium", technique="T1546.003",
        reason="PowerShell -> wmic - WMI event subscription or remote process creation",
        cmdline_any=[r"eventfilter", r"eventconsumer", r"__filtertoconsumerbinding", r"process\s+call\s+create", r"/node:"],
        title="PowerShell used wmic for WMI persistence or remote execution",
    ),
    dict(
        id="procchain.discovery.wmic_query",
        parent="cmd", child="wmic", category="discovery",
        tier="low", technique="T1047",
        reason="cmd -> wmic - host inventory query through WMI",
        cmdline_none=[r"shadowcopy", r"eventfilter", r"eventconsumer", r"process\s+call\s+create", r"/node:"],
        title="cmd queried host inventory via wmic",
    ),
    dict(
        id="procchain.discovery.wmic_query_ps",
        parent="powershell", child="wmic", category="discovery",
        tier="low", technique="T1047",
        reason="PowerShell -> wmic - host inventory query through WMI",
        cmdline_none=[r"shadowcopy", r"eventfilter", r"eventconsumer", r"process\s+call\s+create", r"/node:"],
        title="PowerShell queried host inventory via wmic",
    ),
    # --- reg: Run-key persistence vs credential hive export ---
    dict(
        id="procchain.credaccess.reg_hive_export",
        parent="cmd", child="reg", category="credential_access",
        tier="high", technique="T1003.002",
        reason="cmd -> reg - SAM, SECURITY, or SYSTEM hive saved to disk for offline credential extraction",
        cmdline_any=[r"\bsave\b.*\b(sam|security|system)\b", r"\bexport\b.*\b(sam|security)\b"],
        title="cmd exported a credential registry hive",
    ),
    dict(
        id="procchain.credaccess.reg_hive_export_ps",
        parent="powershell", child="reg", category="credential_access",
        tier="high", technique="T1003.002",
        reason="PowerShell -> reg - SAM, SECURITY, or SYSTEM hive saved to disk for offline credential extraction",
        cmdline_any=[r"\bsave\b.*\b(sam|security|system)\b", r"\bexport\b.*\b(sam|security)\b"],
        title="PowerShell exported a credential registry hive",
    ),
    dict(
        id="procchain.persistence.reg_run_key",
        parent="cmd", child="reg", category="persistence",
        tier="medium", technique="T1547.001",
        reason="cmd -> reg - autorun registry key written",
        cmdline_any=[r"currentversion\\\\run", r"currentversion\\\\runonce", r"\\\\winlogon\\\\", r"image\s+file\s+execution\s+options"],
        title="cmd wrote an autorun registry key",
    ),
    dict(
        id="procchain.persistence.reg_run_key_ps",
        parent="powershell", child="reg", category="persistence",
        tier="medium", technique="T1547.001",
        reason="PowerShell -> reg - autorun registry key written",
        cmdline_any=[r"currentversion\\\\run", r"currentversion\\\\runonce", r"\\\\winlogon\\\\", r"image\s+file\s+execution\s+options"],
        title="PowerShell wrote an autorun registry key",
    ),
    dict(
        id="procchain.discovery.reg_query",
        parent="cmd", child="reg", category="discovery",
        tier="informational", technique="T1012",
        reason="cmd -> reg - registry queried",
        cmdline_any=[r"\bquery\b"],
        title="cmd queried the registry",
    ),
    dict(
        id="procchain.discovery.reg_query_ps",
        parent="powershell", child="reg", category="discovery",
        tier="informational", technique="T1012",
        reason="PowerShell -> reg - registry queried",
        cmdline_any=[r"\bquery\b"],
        title="PowerShell queried the registry",
    ),
    # --- sc: service enumeration vs service creation ---
    dict(
        id="procchain.persistence.sc_service_create",
        parent="cmd", child="sc", category="persistence",
        tier="medium", technique="T1543.003",
        reason="cmd -> sc - Windows service created or reconfigured",
        cmdline_any=[r"\b(create|config)\b"],
        title="cmd created or reconfigured a Windows service",
    ),
    dict(
        id="procchain.persistence.sc_service_create_ps",
        parent="powershell", child="sc", category="persistence",
        tier="medium", technique="T1543.003",
        reason="PowerShell -> sc - Windows service created or reconfigured",
        cmdline_any=[r"\b(create|config)\b"],
        title="PowerShell created or reconfigured a Windows service",
    ),
    dict(
        id="procchain.discovery.sc_service_query",
        parent="cmd", child="sc", category="discovery",
        tier="informational", technique="T1007",
        reason="cmd -> sc - Windows service enumeration",
        cmdline_none=[r"\bcreate\b", r"\bconfig\b", r"\bdelete\b"],
        title="cmd enumerated Windows services",
    ),
    dict(
        id="procchain.discovery.sc_service_query_ps",
        parent="powershell", child="sc", category="discovery",
        tier="informational", technique="T1007",
        reason="PowerShell -> sc - Windows service enumeration",
        cmdline_none=[r"\bcreate\b", r"\bconfig\b", r"\bdelete\b"],
        title="PowerShell enumerated Windows services",
    ),
    # --- net: account discovery vs share discovery vs account manipulation ---
    dict(
        id="procchain.discovery.net_account_enum",
        parent="cmd", child="net", category="discovery",
        tier="low", technique="T1087.002",
        reason="cmd -> net - local or domain account enumeration",
        cmdline_any=[r"\b(user|group|localgroup|accounts)\b"],
        cmdline_none=[r"/add", r"/delete"],
        title="cmd enumerated accounts with net",
    ),
    dict(
        id="procchain.discovery.net_account_enum_ps",
        parent="powershell", child="net", category="discovery",
        tier="low", technique="T1087.002",
        reason="PowerShell -> net - local or domain account enumeration",
        cmdline_any=[r"\b(user|group|localgroup|accounts)\b"],
        cmdline_none=[r"/add", r"/delete"],
        title="PowerShell enumerated accounts with net",
    ),
    dict(
        id="procchain.discovery.net_share_enum",
        parent="cmd", child="net", category="discovery",
        tier="low", technique="T1135",
        reason="cmd -> net - network share discovery",
        cmdline_any=[r"\b(view|share|use)\b"],
        title="cmd enumerated network shares with net",
    ),
    dict(
        id="procchain.discovery.net_share_enum_ps",
        parent="powershell", child="net", category="discovery",
        tier="low", technique="T1135",
        reason="PowerShell -> net - network share discovery",
        cmdline_any=[r"\b(view|share|use)\b"],
        title="PowerShell enumerated network shares with net",
    ),
    dict(
        id="procchain.persistence.net_account_add",
        parent="cmd", child="net", category="persistence",
        tier="high", technique="T1136.001",
        reason="cmd -> net - account created or added to a privileged group",
        cmdline_any=[r"\b(user|group|localgroup)\b.*\s/add"],
        title="cmd created or elevated an account with net",
    ),
    dict(
        id="procchain.persistence.net_account_add_ps",
        parent="powershell", child="net", category="persistence",
        tier="high", technique="T1136.001",
        reason="PowerShell -> net - account created or added to a privileged group",
        cmdline_any=[r"\b(user|group|localgroup)\b.*\s/add"],
        title="PowerShell created or elevated an account with net",
    ),
    # --- psexec: operator lateral movement vs mass deployment ---
    dict(
        id="procchain.lateral.psexec_remote_exec",
        parent="cmd", child="psexec", category="lateral_movement",
        tier="medium", technique="T1570",
        reason="cmd -> PsExec - remote execution initiated from this host",
        cmdline_none=[r"@\S+"],
        title="cmd launched PsExec against a remote host",
    ),
    dict(
        id="procchain.lateral.psexec_remote_exec_ps",
        parent="powershell", child="psexec", category="lateral_movement",
        tier="medium", technique="T1570",
        reason="PowerShell -> PsExec - remote execution initiated from this host",
        cmdline_none=[r"@\S+"],
        title="PowerShell launched PsExec against a remote host",
    ),
    dict(
        id="procchain.impact.psexec_mass_deployment",
        parent="cmd", child="psexec", category="impact",
        tier="critical", technique="T1486", impact=True,
        reason="cmd -> PsExec - payload pushed to a host list, the deployment pattern used for mass ransomware execution",
        cmdline_any=[r"@\S+"],
        title="cmd used PsExec with a target host list",
    ),
    dict(
        id="procchain.impact.psexec_mass_deployment_ps",
        parent="powershell", child="psexec", category="impact",
        tier="critical", technique="T1486", impact=True,
        reason="PowerShell -> PsExec - payload pushed to a host list, the deployment pattern used for mass ransomware execution",
        cmdline_any=[r"@\S+"],
        title="PowerShell used PsExec with a target host list",
    ),
    # --- wevtutil / fltmc / cipher: only the destructive invocation is critical ---
    dict(
        id="procchain.evasion.wevtutil_log_clear",
        parent="cmd", child="wevtutil", category="defense_evasion",
        tier="critical", technique="T1070.001", impact=True,
        reason="cmd -> wevtutil - Windows event log cleared",
        cmdline_any=[r"\bcl\b", r"clear-log"],
        title="cmd cleared a Windows event log",
    ),
    dict(
        id="procchain.evasion.wevtutil_log_clear_ps",
        parent="powershell", child="wevtutil", category="defense_evasion",
        tier="critical", technique="T1070.001", impact=True,
        reason="PowerShell -> wevtutil - Windows event log cleared",
        cmdline_any=[r"\bcl\b", r"clear-log"],
        title="PowerShell cleared a Windows event log",
    ),
    dict(
        id="procchain.discovery.wevtutil_log_query",
        parent="cmd", child="wevtutil", category="discovery",
        tier="informational", technique="T1654",
        reason="cmd -> wevtutil - event log queried or enumerated",
        cmdline_none=[r"\bcl\b", r"clear-log", r"\bsl\b"],
        title="cmd queried a Windows event log",
    ),
    dict(
        id="procchain.evasion.fltmc_unload",
        parent="cmd", child="fltmc", category="defense_evasion",
        tier="critical", technique="T1562.001", impact=True,
        reason="cmd -> fltMC - filesystem minifilter unloaded, which detaches endpoint security drivers",
        cmdline_any=[r"\bunload\b", r"\bdetach\b"],
        title="cmd unloaded a filesystem minifilter",
    ),
    dict(
        id="procchain.evasion.fltmc_unload_ps",
        parent="powershell", child="fltmc", category="defense_evasion",
        tier="critical", technique="T1562.001", impact=True,
        reason="PowerShell -> fltMC - filesystem minifilter unloaded, which detaches endpoint security drivers",
        cmdline_any=[r"\bunload\b", r"\bdetach\b"],
        title="PowerShell unloaded a filesystem minifilter",
    ),
    dict(
        id="procchain.discovery.fltmc_enumerate",
        parent="cmd", child="fltmc", category="discovery",
        tier="informational", technique="T1518.001",
        reason="cmd -> fltMC - loaded minifilters enumerated, often used to fingerprint endpoint security",
        cmdline_none=[r"\bunload\b", r"\bdetach\b"],
        title="cmd enumerated loaded minifilters",
    ),
    dict(
        id="procchain.impact.cipher_wipe",
        parent="cmd", child="cipher", category="impact",
        tier="high", technique="T1485", impact=True,
        reason="cmd -> cipher - free space overwritten, which destroys deleted-file recovery",
        cmdline_any=[r"/w"],
        title="cmd wiped free space with cipher",
    ),
    dict(
        id="procchain.impact.cipher_wipe_ps",
        parent="powershell", child="cipher", category="impact",
        tier="high", technique="T1485", impact=True,
        reason="PowerShell -> cipher - free space overwritten, which destroys deleted-file recovery",
        cmdline_any=[r"/w"],
        title="PowerShell wiped free space with cipher",
    ),
    # --- certutil: download/decode cradle vs certificate administration ---
    dict(
        id="procchain.c2.certutil_download_cradle",
        parent="cmd", child="certutil", category="command_and_control",
        tier="high", technique="T1105",
        reason="cmd -> certutil - certutil used as a download or payload-decode cradle rather than for certificate work",
        cmdline_any=[r"-urlcache", r"-decode", r"-encode", r"-verifyctl", r"-split"],
        title="cmd used certutil as a download or decode cradle",
    ),
    dict(
        id="procchain.c2.certutil_download_cradle_ps",
        parent="powershell", child="certutil", category="command_and_control",
        tier="high", technique="T1105",
        reason="PowerShell -> certutil - certutil used as a download or payload-decode cradle rather than for certificate work",
        cmdline_any=[r"-urlcache", r"-decode", r"-encode", r"-verifyctl", r"-split"],
        title="PowerShell used certutil as a download or decode cradle",
    ),
    # --- curl: download vs upload ---
    dict(
        id="procchain.download.curl_fetch",
        parent="cmd", child="curl", category="download",
        tier="low", technique="T1105",
        reason="cmd -> curl - remote content fetched",
        cmdline_none=[r"-T\b", r"--upload-file", r"-F\b", r"--data-binary", r"-X\s*(POST|PUT)"],
        title="cmd fetched remote content with curl",
    ),
    dict(
        id="procchain.download.curl_fetch_ps",
        parent="powershell", child="curl", category="download",
        tier="low", technique="T1105",
        reason="PowerShell -> curl - remote content fetched",
        cmdline_none=[r"-T\b", r"--upload-file", r"-F\b", r"--data-binary", r"-X\s*(POST|PUT)"],
        title="PowerShell fetched remote content with curl",
    ),
    dict(
        id="procchain.exfil.curl_upload",
        parent="cmd", child="curl", category="exfiltration",
        tier="high", technique="T1048",
        reason="cmd -> curl - local data uploaded over an alternative protocol",
        cmdline_any=[r"-T\b", r"--upload-file", r"-F\b", r"--data-binary", r"-X\s*(POST|PUT)"],
        title="cmd uploaded data with curl",
    ),
    dict(
        id="procchain.exfil.curl_upload_ps",
        parent="powershell", child="curl", category="exfiltration",
        tier="high", technique="T1048",
        reason="PowerShell -> curl - local data uploaded over an alternative protocol",
        cmdline_any=[r"-T\b", r"--upload-file", r"-F\b", r"--data-binary", r"-X\s*(POST|PUT)"],
        title="PowerShell uploaded data with curl",
    ),
    # --- archive staging: password-protected archives are the strong signal ---
    dict(
        id="procchain.collection.archive_password_protected",
        parent="cmd", child="7z", category="collection",
        tier="high", technique="T1560.001",
        reason="cmd -> 7z - password-protected archive created, the standard pre-exfiltration staging pattern",
        cmdline_any=[r"\s-h?p\S"],
        title="cmd created a password-protected archive",
    ),
    dict(
        id="procchain.collection.archive_password_protected_ps",
        parent="powershell", child="7z", category="collection",
        tier="high", technique="T1560.001",
        reason="PowerShell -> 7z - password-protected archive created, the standard pre-exfiltration staging pattern",
        cmdline_any=[r"\s-h?p\S"],
        title="PowerShell created a password-protected archive",
    ),
    dict(
        id="procchain.collection.archive_password_protected_rar",
        parent="cmd", child="rar", category="collection",
        tier="high", technique="T1560.001",
        reason="cmd -> rar - password-protected archive created, the standard pre-exfiltration staging pattern",
        cmdline_any=[r"\s-h?p\S"],
        title="cmd created a password-protected RAR archive",
    ),
    # --- taskkill: generic process kill vs security-tool termination ---
    dict(
        id="procchain.evasion.taskkill_security_tool",
        parent="cmd", child="taskkill", category="defense_evasion",
        tier="high", technique="T1562.001",
        reason="cmd -> taskkill - a named endpoint security or backup process was terminated",
        cmdline_any=[
            r"\b(msmpeng|mssense|sensecncproxy|windefend|cbdefense|cylancesvc|csfalcon|csagent|sentinelagent|sophos|savservice|mcshield|ekrn|avp|xagt|traps|cyserver|sqlwriter|veeam|backupexec)\b"
        ],
        title="cmd terminated a security or backup process",
    ),
]

# Pairs whose blanket form is replaced by the explicit variants above.
SUPPRESSED_PAIRS = {
    ("cmd", "vssadmin"), ("powershell", "vssadmin"),
    ("cmd", "wbadmin"), ("powershell", "wbadmin"),
    ("cmd", "bcdedit"), ("powershell", "bcdedit"),
    ("cmd", "wmic"), ("powershell", "wmic"),
    ("cmd", "reg"), ("powershell", "reg"),
    ("cmd", "sc"), ("powershell", "sc"),
    ("cmd", "net"), ("powershell", "net"),
    ("cmd", "psexec"), ("powershell", "psexec"),
    ("cmd", "wevtutil"), ("powershell", "wevtutil"),
    ("cmd", "fltmc"), ("powershell", "fltmc"),
    ("cmd", "cipher"), ("powershell", "cipher"),
    ("cmd", "certutil"), ("powershell", "certutil"),
    ("cmd", "curl"), ("powershell", "curl"),
    ("cmd", "7z"), ("powershell", "7z"),
    ("cmd", "rar"), ("powershell", "rar"),
    ("cmd", "taskkill"),
}

# --------------------------------------------------------------------------
# Scoring model
# --------------------------------------------------------------------------

TIER_BASE = {"informational": 0, "low": 20, "medium": 40, "high": 55, "critical": 80}
TIER_MAX = {"informational": 0, "low": 39, "medium": 49, "high": 79, "critical": 100}
SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]

# Source severity 0-3 is only the starting point; the tables below encode
# Telltale's own judgement about prevalence, specificity, and blast radius.
SEVERITY_TO_TIER = {0: "informational", 1: "low", 2: "medium", 3: "high"}

# Parents that should essentially never spawn an interpreter or LOLBin. A match
# here means the parent itself carries most of the confidence.
HIGH_CONFIDENCE_PARENTS = {
    "winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub",
    "acrord32", "foxitreader", "chrome", "msedge", "firefox", "iexplore",
    "w3wp", "tomcat", "httpd", "nginx", "sqlservr", "umworkerprocess",
    "msexchangemailboxreplication", "lsass", "csrss", "smss", "winlogon",
    "spoolsv", "sethc", "utilman", "osk", "narrator", "magnify",
    "displayswitch", "atbroker", "searchprotocolhost", "searchindexer",
}

# Parents that indicate a server-side code execution foothold.
SERVER_PARENTS = {
    "w3wp", "tomcat", "httpd", "nginx", "sqlservr", "umworkerprocess",
    "msexchangemailboxreplication",
}

# Parents that are legitimate products but are repeatedly abused as an
# attacker's remote-hands channel.
RMM_PARENTS = {
    "anydesk", "teamviewer", "teamviewer_service", "screenconnect_clientservice",
    "screenconnect_windowsclient", "ateraagent", "splashtop",
}

# Children that exist almost exclusively to do the offensive thing.
OFFENSIVE_CHILDREN = {
    "mimikatz", "sekurlsa", "rubeus", "lazagne", "procdump", "ntdsutil",
    "adfind", "sharphound", "bloodhound", "seatbelt", "ngrok", "chisel",
    "rclone", "megasync", "megacmd", "psexec", "psexesvc", "accesschk",
}

# Explicit tier promotions/demotions relative to SEVERITY_TO_TIER, keyed by
# (parent, child). These are the judgement calls the scoring model exists for.
TIER_OVERRIDES: dict[tuple[str, str], str] = {}

for _child in ("cmd", "powershell", "csc", "certutil", "whoami", "net", "bash"):
    for _parent in SERVER_PARENTS:
        TIER_OVERRIDES[(_parent, _child)] = "critical"
for _child in ("cmd", "powershell", "rundll32"):
    TIER_OVERRIDES[("lsass", _child)] = "critical"
    TIER_OVERRIDES[("csrss", _child)] = "critical"
    TIER_OVERRIDES[("smss", _child)] = "critical"
for _parent in ("sethc", "utilman", "osk", "narrator", "magnify", "displayswitch", "atbroker"):
    TIER_OVERRIDES[(_parent, "cmd")] = "critical"
TIER_OVERRIDES[("winlogon", "sethc")] = "critical"
for _parent in ("cmd", "powershell"):
    for _child in ("mimikatz", "sekurlsa", "rubeus", "lazagne", "ntdsutil",
                   "adfind", "sharphound", "bloodhound", "procdump",
                   "ngrok", "chisel", "rclone", "megasync", "megacmd"):
        TIER_OVERRIDES[(_parent, _child)] = "critical"

# Office, PDF, and browser parents spawning an interpreter or LOLBin: the
# single most reliable initial-access chain in the library.
for _parent in ("winword", "excel", "powerpnt", "onenote", "msaccess", "mspub",
                "outlook", "acrord32", "foxitreader", "chrome", "msedge",
                "firefox", "iexplore"):
    for _child in ("cmd", "powershell", "wscript", "cscript", "mshta",
                   "rundll32", "regsvr32", "msdt", "bash", "certutil",
                   "bitsadmin", "schtasks"):
        TIER_OVERRIDES.setdefault((_parent, _child), "high")

# Demotions: pairs that are genuinely routine on developer and admin hosts.
for _pair in [("powershell", "cmd"), ("cmd", "powershell"), ("powershell", "powershell")]:
    TIER_OVERRIDES[_pair] = "low"
TIER_OVERRIDES[("bash", "cmd")] = "informational"
TIER_OVERRIDES[("wsl", "cmd")] = "informational"
TIER_OVERRIDES[("wsl", "powershell")] = "informational"
TIER_OVERRIDES[("cmd", "xcopy")] = "informational"
TIER_OVERRIDES[("cmd", "copy")] = "informational"
TIER_OVERRIDES[("cmd", "gpupdate")] = "informational"
TIER_OVERRIDES[("powershell", "gpupdate")] = "informational"
TIER_OVERRIDES[("cmd", "klist")] = "informational"
TIER_OVERRIDES[("powershell", "klist")] = "informational"

CATEGORY_ID_SEGMENT = {
    "execution": "execution",
    "defense_evasion": "evasion",
    "command_and_control": "c2",
    "persistence": "persistence",
    "discovery": "discovery",
    "credential_access": "credaccess",
    "lateral_movement": "lateral",
    "impact": "impact",
    "collection": "collection",
    "exfiltration": "exfil",
    "download": "download",
}

SECTION_TO_CATEGORY = {
    "Execution": "execution",
    "Defense Evasion": "defense_evasion",
    "Command And Control": "command_and_control",
    "Persistence": "persistence",
    "Discovery": "discovery",
    "Credential Access": "credential_access",
    "Lateral Movement": "lateral_movement",
    "Collection": "collection",
    "Exfiltration": "exfiltration",
}


def normalize(name: str) -> str:
    name = name.strip().lower()
    name = re.sub(r"\.exe$", "", name)
    return name.replace(".", "_").replace("-", "_")


def score_for(tier: str, parent: str, child: str, impact: bool, has_cmdline: bool) -> int:
    score = TIER_BASE[tier]
    if tier == "informational":
        return 0
    if child in OFFENSIVE_CHILDREN:
        score += 5
    if parent in HIGH_CONFIDENCE_PARENTS or parent in RMM_PARENTS:
        score += 5
    if impact:
        score += 5
    if has_cmdline:
        score += 3
    return min(score, TIER_MAX[tier])


def confidence_for(tier: str, parent: str, child: str, has_cmdline: bool) -> str:
    if has_cmdline or child in OFFENSIVE_CHILDREN or parent in SERVER_PARENTS:
        return "high"
    if tier in ("medium", "high", "critical") or parent in HIGH_CONFIDENCE_PARENTS:
        return "medium"
    return "low"


def title_for(reason: str) -> str:
    head = reason.split(" - ", 1)[0]
    return head.replace("->", "spawned")


def quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def main() -> int:
    rules: list[dict] = []
    seen_ids: set[str] = set()

    section = None
    for raw in SOURCE.strip().splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            section = line.lstrip("# ").strip()
            continue
        parent_raw, child_raw, severity_raw, reason, technique = line.split("|")
        parent = normalize(parent_raw)
        child = normalize(child_raw)
        if (parent, child) in SUPPRESSED_PAIRS:
            continue
        category = SECTION_TO_CATEGORY[section]
        tier = TIER_OVERRIDES.get((parent, child), SEVERITY_TO_TIER[int(severity_raw)])
        rule_id = f"procchain.{CATEGORY_ID_SEGMENT[category]}.{parent}_{child}"
        if rule_id in seen_ids:
            continue
        seen_ids.add(rule_id)
        rules.append(
            dict(
                id=rule_id,
                title=title_for(reason),
                category=category,
                tier=tier,
                parent=parent,
                child=child,
                technique=technique,
                reason=reason,
                source_severity=int(severity_raw),
            )
        )

    for entry in EXPLICIT:
        entry = dict(entry)
        entry.setdefault("source_severity", None)
        entry["title"] = entry.get("title") or title_for(entry["reason"])
        if entry["id"] in seen_ids:
            raise SystemExit(f"duplicate explicit id {entry['id']}")
        seen_ids.add(entry["id"])
        rules.append(entry)

    rules.sort(key=lambda rule: rule["id"])

    lines: list[str] = []
    emit = lines.append
    emit("# Telltale process-chain detection pack.")
    emit("#")
    emit("# GENERATED FILE - edit scripts/dev/generate-process-chain-rules.py and re-run")
    emit("#   python3 scripts/dev/generate-process-chain-rules.py")
    emit("#")
    emit("# Behavioural reference: irflow-timeline process-tree rule library")
    emit("#   https://github.com/r3nzsec/irflow-timeline (src/detection-rules.js)")
    emit("# Scores are Telltale's own; see docs/process-chain-detections.md.")
    emit("version: 1")
    emit('description: "Parent/child process-chain and standalone process indicators."')
    emit("defaults:")
    emit("  enabled: true")
    emit("  risk_entity: host")
    emit("  suppression_window_seconds: 3600")
    emit("categories:")
    for category, meta in CATEGORY_METADATA.items():
        emit(f"  {category}:")
        emit(f"    detection_class: {meta['detection_class']}")
        emit(f"    analytic_intent: {meta['analytic_intent']}")
        emit("    investigation_fields:")
        for field in meta["investigation_fields"]:
            emit(f"      - {field}")
        emit("    falsepositives:")
        for note in meta["falsepositives"]:
            emit(f"      - {quote(note)}")
    emit("rules:")
    for rule in rules:
        has_cmdline = bool(rule.get("cmdline_any") or rule.get("cmdline_none"))
        impact = bool(rule.get("impact"))
        tier = rule["tier"]
        score = score_for(tier, rule["parent"], rule["child"], impact, has_cmdline)
        confidence = confidence_for(tier, rule["parent"], rule["child"], has_cmdline)
        emit(f"  - id: {rule['id']}")
        emit(f"    title: {quote(rule['title'])}")
        emit(f"    category: {rule['category']}")
        emit(f"    severity: {tier}")
        emit(f"    score: {score}")
        emit(f"    confidence: {confidence}")
        emit(f"    parent: {rule['parent']}")
        emit(f"    child: {rule['child']}")
        emit(f"    mitre: [{rule['technique']}]")
        emit(f"    reason: {quote(rule['reason'])}")
        if rule.get("cmdline_any"):
            emit("    child_command_line_any:")
            for pattern in rule["cmdline_any"]:
                emit(f"      - {quote(pattern)}")
        if rule.get("cmdline_none"):
            emit("    child_command_line_none:")
            for pattern in rule["cmdline_none"]:
                emit(f"      - {quote(pattern)}")
        if rule.get("source_severity") is not None:
            emit(f"    source_severity: {rule['source_severity']}")

    emit("standalone:")
    for rule in STANDALONE:
        emit(f"  - id: {rule['id']}")
        emit(f"    title: {quote(rule['title'])}")
        emit(f"    category: {rule['category']}")
        emit(f"    severity: {rule['tier']}")
        emit(f"    score: {STANDALONE_SCORES[rule['tier']]}")
        emit(f"    confidence: {rule['confidence']}")
        emit(f"    mitre: [{', '.join(rule['mitre'])}]")
        emit(f"    reason: {quote(rule['reason'])}")
        emit(f"    match: {rule['match']}")
        emit("    patterns:")
        for pattern in rule["patterns"]:
            emit(f"      - {quote(pattern)}")
        if rule.get("exclude"):
            emit("    exclude:")
            for pattern in rule["exclude"]:
                emit(f"      - {quote(pattern)}")

    emit("correlations:")
    for rule in CORRELATIONS:
        emit(f"  - id: {rule['id']}")
        emit(f"    title: {quote(rule['title'])}")
        emit(f"    category: {rule['category']}")
        emit(f"    severity: {rule['tier']}")
        emit(f"    score: {rule['score']}")
        emit(f"    confidence: {rule['confidence']}")
        emit(f"    mitre: [{', '.join(rule['mitre'])}]")
        emit(f"    reason: {quote(rule['reason'])}")
        emit(f"    window_seconds: {rule['window_seconds']}")
        emit(f"    entity: {rule['entity']}")
        emit("    sequence:")
        for step in rule["sequence"]:
            emit("      - any_category:")
            for category in step.get("any_category", []):
                emit(f"          - {category}")
            if step.get("any_rule_id"):
                emit("        any_rule_id:")
                for rule_id in step["any_rule_id"]:
                    emit(f"          - {rule_id}")
            if step.get("any_child"):
                emit("        any_child:")
                for child in step["any_child"]:
                    emit(f"          - {child}")
    lines.append("")

    OUT.write_text("\n".join(lines))
    print(f"wrote {OUT} ({len(rules)} chain rules)")
    tier_counts: dict[str, int] = {}
    for rule in rules:
        tier_counts[rule["tier"]] = tier_counts.get(rule["tier"], 0) + 1
    for tier in SEVERITY_ORDER:
        print(f"  {tier:<14} {tier_counts.get(tier, 0)}")
    return 0


CATEGORY_METADATA = {
    "execution": dict(
        detection_class="security_detection",
        analytic_intent="alert",
        investigation_fields=[
            "source_process_command_line",
            "target_process_command_line",
            "target_process_path",
            "user",
            "host",
        ],
        falsepositives=[
            "Software deployment and configuration-management agents legitimately spawn interpreters on managed endpoints.",
            "Developer tooling and build systems routinely chain shells and script hosts.",
        ],
    ),
    "defense_evasion": dict(
        detection_class="security_detection",
        analytic_intent="alert",
        investigation_fields=[
            "target_process_command_line",
            "target_process_path",
            "user",
            "host",
            "parent_process_name",
        ],
        falsepositives=[
            "Patching, imaging, and endpoint-agent maintenance windows can legitimately stop services or adjust security settings.",
            "LOLBins such as rundll32 and msiexec are used constantly by Windows itself and by installers.",
        ],
    ),
    "command_and_control": dict(
        detection_class="security_detection",
        analytic_intent="alert",
        investigation_fields=[
            "target_process_command_line",
            "target_process_path",
            "host",
            "user",
        ],
        falsepositives=[
            "Authorised RMM products spawn shells as part of normal remote support; scope by approved product and management server.",
            "Developers legitimately use ngrok-style tunnels for local webhook testing.",
        ],
    ),
    "persistence": dict(
        detection_class="security_detection",
        analytic_intent="alert",
        investigation_fields=[
            "target_process_command_line",
            "user",
            "host",
            "source_process_command_line",
        ],
        falsepositives=[
            "Installers, scheduled maintenance, and configuration management create tasks, services, and autorun keys routinely.",
        ],
    ),
    "discovery": dict(
        detection_class="threat_hunting",
        analytic_intent="hunt",
        investigation_fields=[
            "target_process_command_line",
            "user",
            "host",
        ],
        falsepositives=[
            "Discovery commands are the ordinary vocabulary of helpdesk and administration work; they are useful mainly in sequence.",
            "Inventory and monitoring agents run these commands on a schedule.",
        ],
    ),
    "credential_access": dict(
        detection_class="security_detection",
        analytic_intent="alert",
        investigation_fields=[
            "target_process_command_line",
            "target_process_path",
            "user",
            "host",
            "parent_process_name",
        ],
        falsepositives=[
            "Backup software and domain-controller maintenance legitimately touch shadow copies and the AD database.",
            "Support engineers use ProcDump for genuine crash analysis.",
        ],
    ),
    "lateral_movement": dict(
        detection_class="security_detection",
        analytic_intent="alert",
        investigation_fields=[
            "target_process_command_line",
            "user",
            "host",
            "source_process_name",
        ],
        falsepositives=[
            "Remote administration over WinRM, PsExec, and DCOM is normal for server operations teams.",
        ],
    ),
    "impact": dict(
        detection_class="security_detection",
        analytic_intent="alert",
        investigation_fields=[
            "target_process_command_line",
            "user",
            "host",
            "source_process_command_line",
        ],
        falsepositives=[
            "Backup and imaging products prune shadow copies and backup catalogues as part of retention policy; verify the invoking account and product.",
        ],
    ),
    "collection": dict(
        detection_class="security_detection",
        analytic_intent="alert",
        investigation_fields=[
            "target_process_command_line",
            "user",
            "host",
        ],
        falsepositives=[
            "Archiving is everyday packaging and backup work; only password-protected or unusually large staging archives are meaningful alone.",
        ],
    ),
    "exfiltration": dict(
        detection_class="security_detection",
        analytic_intent="alert",
        investigation_fields=[
            "target_process_command_line",
            "host",
            "user",
        ],
        falsepositives=[
            "Approved cloud-sync clients and CI artefact uploads use the same utilities; scope by destination and account.",
        ],
    ),
    "download": dict(
        detection_class="security_detection",
        analytic_intent="enrich",
        investigation_fields=[
            "target_process_command_line",
            "host",
            "user",
        ],
        falsepositives=[
            "Fetching packages, installers, and documentation is routine developer and administrator activity.",
        ],
    ),
}


# Standalone indicators: command-line, process-name, and path signatures that do
# not depend on a parent/child relationship. Scores use the same severity bands
# as the chain rules, with no parent-confidence bonus available.
STANDALONE_SCORES = {
    "informational": 0, "low": 25, "medium": 45, "high": 65, "critical": 85,
}

STANDALONE = [
    dict(
        id="procchain.execution.suspicious_execution_path",
        title="Process executed from a user-writable staging directory",
        category="execution", tier="medium", confidence="low",
        mitre=["T1036.005"],
        reason="Process image is located in a user-writable staging directory rather than a program directory",
        match="process_path",
        patterns=[r"\\temp\\", r"\\tmp\\", r"\\appdata\\", r"\\downloads\\", r"\\public\\", r"\\recycle", r"\\perflogs\\"],
        exclude=[
            r"^(mpcmdrun|msmpeng|dismhost|monagentcore|monagenthost|monagentmanager|monagentlauncher|metricsextension_native|cleanmgr|tiworker|wuauclt|setup|msiexec|drvinst|trustedinstaller|taskhostw|backgroundtaskhost|runtimebroker|searchprotocolhost|searchindexer|searchfilterhost|microsoftedgeupdate|googleupdate|onedrive|onedriveupdater|wermgr|werfault|compattelrunner)$"
        ],
    ),
    dict(
        id="procchain.execution.encoded_powershell",
        title="PowerShell invoked with an encoded command",
        category="execution", tier="high", confidence="high",
        mitre=["T1059.001", "T1027"],
        reason="PowerShell was invoked with a base64-encoded command, which hides the payload from command-line logging",
        match="command_line",
        patterns=[r"\s+-e(nc|ncodedcommand|c|n)?\s+[A-Za-z0-9+/=]{16,}"],
    ),
    dict(
        id="procchain.credaccess.credential_dump_command",
        title="Credential-dumping command line observed",
        category="credential_access", tier="critical", confidence="high",
        mitre=["T1003.001"],
        reason="Command line names a credential-dumping technique or tool",
        match="command_line",
        patterns=[r"comsvcs\.dll.*minidump", r"\bsekurlsa\b", r"\blsadump\b", r"procdump.*lsass", r"\bmimikatz\b", r"\bpypykatz\b", r"\bnanodump\b", r"\bdcsync\b", r"\bdrsuapi\b"],
    ),
    dict(
        id="procchain.credaccess.ntds_extraction",
        title="Active Directory database extraction observed",
        category="credential_access", tier="critical", confidence="high",
        mitre=["T1003.003"],
        reason="Command line targets the Active Directory database for offline credential extraction",
        match="command_line",
        patterns=[r"ntdsutil.*\bifm\b", r"wbadmin.*ntds", r"\bsecretsdump\b", r"ntds\.dit"],
    ),
    dict(
        id="procchain.credaccess.lsass_dump_tool",
        title="Known LSASS memory-dumping utility executed",
        category="credential_access", tier="high", confidence="medium",
        mitre=["T1003.001"],
        reason="A utility commonly used to dump LSASS memory was executed",
        match="process_name",
        patterns=[r"^(processhacker|procdump|procdump64|sqldumper|avdump|handlekatz|nanodump)$"],
    ),
    dict(
        id="procchain.persistence.account_manipulation",
        title="Local or domain account created or elevated",
        category="persistence", tier="high", confidence="high",
        mitre=["T1136.001", "T1098"],
        reason="An account was created or added to a group through net.exe",
        match="command_line",
        patterns=[r"net1?\s+(user|group|localgroup)\s+.*(/add|/domain\s+/add)"],
    ),
    dict(
        id="procchain.evasion.recovery_and_log_tampering",
        title="Recovery data or event logs destroyed",
        category="defense_evasion", tier="critical", confidence="high",
        mitre=["T1490", "T1070.001"],
        reason="Command line deletes shadow copies, clears event logs, or disables boot recovery",
        match="command_line",
        patterns=[r"vssadmin.*\bdelete\b", r"wevtutil\s+cl\b", r"bcdedit.*safeboot", r"bcdedit.*recoveryenabled"],
    ),
    dict(
        id="procchain.discovery.network_scanner",
        title="Network scanning utility executed",
        category="discovery", tier="medium", confidence="medium",
        mitre=["T1046"],
        reason="A network scanning utility commonly staged by intrusion operators was executed",
        match="process_name",
        patterns=[r"^(netscan|netscan64|advanced_ip_scanner|rustscan|masscan|angry_ip_scanner|nbtscan)$"],
    ),
    dict(
        id="procchain.discovery.ad_recon_tool",
        title="Active Directory attack-path tooling executed",
        category="discovery", tier="critical", confidence="high",
        mitre=["T1087.002", "T1018"],
        reason="Purpose-built Active Directory reconnaissance or abuse tooling was executed",
        match="process_name",
        patterns=[r"^(adfind|sharphound|bloodhound|sharpview|seatbelt|rubeus|certify|certipy)$"],
    ),
    dict(
        id="procchain.c2.rmm_tool_present",
        title="Remote monitoring and management agent executed",
        category="command_and_control", tier="low", confidence="low",
        mitre=["T1219"],
        reason="A remote monitoring and management agent ran on this host; benign when it is the sanctioned product",
        match="process_name",
        patterns=[r"^(anydesk|teamviewer|teamviewer_service|screenconnect_clientservice|screenconnect_windowsclient|ateraagent|splashtop|splashtopstreamer|connectwisecontrol|logmein|lmiignition|gotoassist|dwagent|rustdesk|supremo|ammyy)$"],
    ),
    dict(
        id="procchain.exfil.cloud_transfer_tool",
        title="Bulk cloud transfer utility executed",
        category="exfiltration", tier="high", confidence="medium",
        mitre=["T1567.002"],
        reason="A bulk cloud-transfer utility associated with data theft was executed",
        match="process_name",
        patterns=[r"^(rclone|megasync|megacmd|megaclient|filezilla|winscp|freefilesync)$"],
    ),
    dict(
        id="procchain.c2.tunnel_tool",
        title="Network tunnelling utility executed",
        category="command_and_control", tier="high", confidence="medium",
        mitre=["T1572"],
        reason="A reverse-tunnel or proxy utility used to expose internal services was executed",
        match="process_name",
        patterns=[r"^(ngrok|chisel|frpc|frps|plink|gost|iox|revsocks|cloudflared)$"],
    ),
    dict(
        id="procchain.collection.password_protected_archive",
        title="Password-protected archive created",
        category="collection", tier="high", confidence="high",
        mitre=["T1560.001"],
        reason="An archive utility was invoked with a password flag, the standard pre-exfiltration staging pattern",
        match="command_line",
        patterns=[r"\b(7z|7za|winrar|rar)\b.*\s-h?p\S"],
    ),
]

# Correlation rules. Each step matches an already-emitted process-chain
# detection; steps must occur in order, within the window, for the same entity.
CORRELATIONS = [
    dict(
        id="procchain.correlation.host_then_account_discovery",
        title="Host fingerprinting followed by account enumeration",
        category="discovery", tier="medium", score=45, confidence="medium",
        mitre=["T1082", "T1087.002"],
        reason="Host fingerprinting was followed by account enumeration on the same host, the standard opening of hands-on-keyboard reconnaissance",
        window_seconds=900, entity="host",
        sequence=[
            dict(any_category=["discovery"], any_child=["hostname", "systeminfo", "ipconfig", "arp", "route", "nbtstat", "netstat", "tasklist"]),
            dict(any_category=["discovery"], any_child=["whoami", "net", "net1", "dsquery", "dsget", "csvde", "ldifde", "nltest", "adfind", "sharphound", "bloodhound"]),
        ],
    ),
    dict(
        id="procchain.correlation.discovery_then_remote_exec",
        title="Account discovery followed by remote execution",
        category="lateral_movement", tier="high", score=55, confidence="medium",
        mitre=["T1087.002", "T1570"],
        reason="Account or trust enumeration was followed by remote execution tooling on the same host",
        window_seconds=1800, entity="host",
        sequence=[
            dict(any_category=["discovery"]),
            dict(any_category=["lateral_movement"]),
        ],
    ),
    dict(
        id="procchain.correlation.archive_then_cloud_transfer",
        title="Archive staging followed by bulk cloud transfer",
        category="exfiltration", tier="high", score=65, confidence="high",
        mitre=["T1560.001", "T1567.002"],
        reason="Data was archived and then a bulk cloud-transfer utility ran on the same host, the collection-to-exfiltration sequence",
        window_seconds=3600, entity="host",
        sequence=[
            dict(any_category=["collection"]),
            dict(any_category=["exfiltration"]),
        ],
    ),
    dict(
        id="procchain.correlation.office_script_then_download",
        title="Office application spawned a script host that then fetched remote content",
        category="execution", tier="high", score=70, confidence="high",
        mitre=["T1204.002", "T1105"],
        reason="An Office application spawned a script interpreter which then retrieved remote content, the classic maldoc staging chain",
        window_seconds=600, entity="host",
        sequence=[
            dict(any_category=["execution"], any_rule_id=[
                "procchain.execution.winword_powershell",
                "procchain.execution.winword_cmd",
                "procchain.execution.winword_wscript",
                "procchain.execution.winword_cscript",
                "procchain.execution.excel_powershell",
                "procchain.execution.excel_cmd",
                "procchain.execution.excel_wscript",
                "procchain.execution.excel_cscript",
                "procchain.execution.onenote_powershell",
                "procchain.execution.onenote_cmd",
                "procchain.execution.outlook_powershell",
                "procchain.execution.powerpnt_powershell",
                "procchain.execution.msaccess_powershell",
                "procchain.execution.mspub_powershell",
            ]),
            dict(any_category=["command_and_control", "download"]),
        ],
    ),
    dict(
        id="procchain.correlation.webshell_then_discovery",
        title="Web-server process spawned a shell that then ran discovery",
        category="execution", tier="critical", score=80, confidence="high",
        mitre=["T1190", "T1033"],
        reason="A web-server or database process spawned a shell and discovery commands followed, which is web-shell hands-on activity",
        window_seconds=900, entity="host",
        sequence=[
            dict(any_category=["execution"], any_rule_id=[
                "procchain.execution.w3wp_cmd",
                "procchain.execution.w3wp_powershell",
                "procchain.execution.w3wp_csc",
                "procchain.execution.tomcat_cmd",
                "procchain.execution.httpd_cmd",
                "procchain.execution.nginx_cmd",
                "procchain.execution.sqlservr_cmd",
                "procchain.execution.sqlservr_powershell",
                "procchain.execution.java_cmd",
                "procchain.execution.java_powershell",
                "procchain.execution.javaw_cmd",
                "procchain.execution.umworkerprocess_cmd",
                "procchain.execution.umworkerprocess_powershell",
                "procchain.execution.msexchangemailboxreplication_cmd",
            ]),
            dict(any_category=["discovery"]),
        ],
    ),
    dict(
        id="procchain.correlation.rmm_then_credential_or_evasion",
        title="RMM agent spawned PowerShell before credential access or defence tampering",
        category="command_and_control", tier="high", score=60, confidence="medium",
        mitre=["T1219", "T1003"],
        reason="A remote monitoring agent spawned an interpreter and credential-access or defence-evasion behaviour followed on the same host",
        window_seconds=1800, entity="host",
        sequence=[
            dict(any_category=["command_and_control"], any_rule_id=[
                "procchain.c2.anydesk_powershell",
                "procchain.c2.anydesk_cmd",
                "procchain.c2.teamviewer_powershell",
                "procchain.c2.teamviewer_cmd",
                "procchain.c2.teamviewer_service_powershell",
                "procchain.c2.teamviewer_service_cmd",
                "procchain.c2.screenconnect_clientservice_powershell",
                "procchain.c2.screenconnect_clientservice_cmd",
                "procchain.c2.screenconnect_windowsclient_powershell",
                "procchain.c2.screenconnect_windowsclient_cmd",
                "procchain.c2.ateraagent_powershell",
                "procchain.c2.ateraagent_cmd",
                "procchain.c2.splashtop_powershell",
                "procchain.c2.splashtop_cmd",
            ]),
            dict(any_category=["credential_access", "defense_evasion"]),
        ],
    ),
]


if __name__ == "__main__":
    sys.exit(main())
