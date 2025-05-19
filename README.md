# LaZagne Credential Dumping Detection Using LimaCharlie 
This project demonstrates how to use LimaCharlie EDR to detect LaZagne

## 🎯 Objective 
Detect the execution of LaZagne on an endpoint and respond with alerts using LimaCharlie and Tines.

## 🔧 Tools Used
- LimaCharlie EDR
- Windows Server VM
- Tines
- Slack
- MITRE ATT&CK (T1003 - OS Credential Dumping)
- LaZagne: https://github.com/AlessandroZ/LaZagne

## 🕵️‍♀️ Detection Rule Logic
Detection is based on:
- File path or name ('LaZagne.exe')
- Comand line usage
- Event type


LimaCharlie D&R Rule:

```
events:
  - NEW_PROCESS
  - EXISTING_PROCESS
op: and
rules:
  - op: is windows
  - op: or
    rules:
      - case sensitive: false
        op: ends with
        path: event/FILE_PATH
        value: lazagne.exe
      - case sensitive: false
        op: ends with
        path: event/COMMAND_LINE
        value: all
      - case sensitive: false
        op: contains
        path: event/COMMAND_LINE
        value: lazagne
      - case sensitive: false
        op: is
        path: event/HASH
        value: dc06d62ee95062e714f2566c95b8edaabfd387023b1bf98a09078b84007d5268

- action: report
  metadata:
    author: graciegue
    description: TEST - Detects Lazagne Usage
    falsepositives:
      - ToTheMoon
    level: medium
    tags:
      - attack.credential_access
  name: graciegue - HackTool - Lazagne(SOAR-EDR)

```

## 🧪 Sample Event 
Located in `/logs/event-sample.json`

View in Screenshots as well
