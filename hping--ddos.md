**DoS Attack Report Using HPING**

**1. Target Information**

- **IP Address/Domain Name:** 192.168.1.100
- **Type of Target:** Web Server (Apache)

**2. Attack Details**

- **HPING Command Used:bash**
    
    `hping3 -S -p 80 --flood -V 192.168.1.100`
    
- **Protocol Used:** TCP
- **Port Targeted:** 80 (HTTP)

**3. Attack Duration**

- The attack was conducted for a duration of 5 minutes.

**4. Observed Effects**

During the attack, the following effects were observed:

- **Increased Latency:** The response time for HTTP requests increased significantly, from an average of 50ms to over 500ms.
- **Unavailability:** Several HTTP requests resulted in timeouts, indicating that the server was unable to handle the increased load.
- **Error Messages:** Clients attempting to access the server received "503 Service Unavailable" errors.

**5. Tools and Environment**

- **Operating System:** Ubuntu 20.04 LTS
- **Network Configuration:**
    - Bandwidth: 100 Mbps
    - Latency to Target: Approximately 2ms

**6. Mitigation or Countermeasures**

- **Rate Limiting:** The target server implemented rate limiting, which helped to mitigate the effects of the attack somewhat, but it was still overwhelmed.
- **Firewall Rules:** Additional firewall rules were added to drop excessive SYN packets, but this only provided temporary relief.

**7. Conclusions and Observations**

The HPING-based DoS attack using a SYN flood was effective in degrading the performance of the target web server. The server experienced increased latency and unavailability, indicating that it was unable to handle the volume of SYN packets sent by HPING. The attack highlighted the vulnerability of the server to SYN flood attacks and the need for more robust defensive measures, such as improved rate limiting and SYN cookie protection.

Unexpectedly, the server's performance degradation was more severe than anticipated, suggesting that the server's current configuration and resources are insufficient to handle such attacks. This attack also demonstrated the effectiveness of HPING as a tool for network testing and DoS attacks.
