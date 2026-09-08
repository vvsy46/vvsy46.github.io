---
title: "Pwn2Own Automotive 2026 Results"
date: 2026-09-07 22:50:00 +0900
categories: [Pwn2Own]
tags: [Pwn2Own, Automotive]
---

## Target Overview
- Vendor: Phoenix Contact
- Model: CHARX SEC-3150
- Firmware Version: V1.8.0
- Local Modbus Version: pymodbus / 3.6.9
- Initial Privilege: Unauthenticated
- Impact: Remote Code Execution

## Brief
The vulnerability allows an unauthenticated attacker to achieve command injection, leading to remote code execution.

## Trigger Sequence
### 1. Unauthenticated Remote Shutdown of EV Charger via Modbus Register
Initially, the following ports are exposed to unauthenticated users:
```md
22: SSH
80/443: HTTP/HTTPS
502: Modbus
1883: MQTT
5353: mDNS
```
Among these services, we focused on the Modbus protocol.
![modbus_reboot](/assets/img/pwn2own/Auto_2026/modbus.png)  
According to the manual, writing to register 165 can restart the CHARX controller.  
This allows an unauthenticated user to remotely reboot the CHARX controller.


### 2. Configuration Injection During the EV Charger Shutdown Window
We then accidentally discovered a logic bug in the shutdown sequence.
![firewall](/assets/img/pwn2own/Auto_2026/firewall.png){: style="max-width: 80%; display: block; margin: 10px auto; margin-bottom: 25px;" }  
As shown above, the firewall shuts down before the `charx-system-config-manager` process.  
As a result, additional ports including port `5001` are temporarily exposed during the shutdown process.  
During this time window, we can add additional ports to the `incoming` field in `/data/charx-system-config-manager/system-user-configuration.ini`.
![firewall_bypass](/assets/img/pwn2own/Auto_2026/firewall_bypass.png){: style="max-width: 70%; display: block; margin: 10px auto; margin-bottom: 25px;" }  


### 3. Final-Stage Code Execution [REDACTED]
The final stage was not disclosed, so we did not receive credit for this vulnerability.    
Although we did not use it in our final exploit chain, we found a similar vulnerability. 
- OS Command Injection via CellularNetwork.idledisconnect

Special characters can be injected into the `/import` endpoint on port 5001, targeting the `CellularNetwork/idledisconnect` field in `configuration.ini`.  
Therefore, the following shows an example of the insertion and its result.  

![special_character_inject](/assets/img/pwn2own/Auto_2026/special_character_inject.png){: style="max-width: 80%; display: block; margin: 10px auto;" }

The `PPP` component allows a shell command to be specified through its `connect` option.
![ppp](assets/img/pwn2own/Auto_2026/ppp.png){: style="max-width: 70%; display: block; margin: 10px auto;" }

After the reboot, the reverse shell is triggered if `CellularNetwork` is enabled. If it is disabled, we can enable it while modifying the configuration through port `5001`.

## Exploit

<video controls autoplay loop muted playsinline width="100%" style="display: block; margin: 15px auto;">
  <source src="{{ '/assets/img/pwn2own/Auto_2026/exploit.mp4' | relative_url }}" type="video/mp4">
  브라우저가 비디오 태그를 지원하지 않습니다.
</video>