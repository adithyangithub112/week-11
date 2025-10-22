# What is a DOS Attack?

A DOS ([**Denial of Service**](https://www.geeksforgeeks.org/computer-networks/deniel-service-prevention/)) attack is a type of cyberattack where one internet-connected computer floods a different computer with traffic especially a server to instigate a crash. It always floods the server with requests which will cause it to either crash or be unavailable to users of the website in question. DOS attacks specifically appear when targeted at a website, making the site unavailable and causing a major disruption of online services.

### Key Characteristics of a DOS Attack:

- **Single Source:** It is started from one system only as explained above.
- **Traffic Volume:** The Turnover is high, however, it is a single point of call Turnover.
- **Traceability:** As the attack originates from a particular system it is traceable as compared to the case of the distributed one.
- **Blockability:** It is more easily blocked since ALL of the traffic comes from one source as opposed to a [**DDOS attack**](https://www.geeksforgeeks.org/computer-networks/what-is-ddosdistributed-denial-of-service/).

# What is a DDOS Attack?

A DDOS Which is a short form of Distributed Denial of Service attack works on similar lines as the DOS attack but is more complicated in that the attack is launched with the help of several systems located in different places. These systems, sometimes ge fringe computers or ‘bots,’ operate in parallel in the manner of amplifying the traffic volume to a level much more difficult for the target to counter. An inherent advantage of a distributed attack is that it is difficult to track the origin and, therefore, put a stop to it.

### Key Characteristics of a DDOS Attack

- **Multiple Sources:** The attack is initiated from the different systems; at times, originated from different environments.
- **Traffic Volume:** It has multiple sources and the volume of traffic is much higher and for this reason it is much more devastating.
- **Difficulty in Tracing:** This is because the attack is launched in several instances of computers at different locations, hence it is difficult to track its origin.
- **Complexity in Blocking:** It is even more challenging to block a DDOS attack because the attack originates from many different places.

# Difference Between DoS and DDoS Attacks

| **DOS** | **DDOS** |
| --- | --- |
| DOS Stands for Denial of service attack. | DDOS Stands for Distributed Denial of service attack. |
| In Dos attack single system targets the victim system. | In DDoS multiple systems attacks the victims system.. |
| Victim PC is loaded from the packet of data sent from a single location. | Victim PC is loaded from the packet of data sent from Multiple location. |
| Dos attack is slower as compared to DDoS. | DDoS attack is faster than Dos Attack. |
| Can be blocked easily as only one system is used. | It is difficult to block this attack as multiple devices are sending packets and attacking from multiple locations. |
| In DOS Attack only single device is used with DOS Attack tools. | In DDoS attack, The volumeBots are used to attack at the same time. |
| DOS Attacks are Easy to trace. | DDOS Attacks are Difficult to trace. |
| Volume of traffic in the Dos attack is less as compared to DDos. | DDoS attacks allow the attacker to send massive volumes of traffic to the victim network. |
| Types of DOS Attacks are: 1. Buffer overflow attacks 2. Ping of Death or ICMP flood 3. Teardrop Attack 4. Flooding Attack | Types of DDOS Attacks are: 1. Volumetric Attacks 2. Fragmentation Attacks 3. Application Layer Attacks 4. Protocol Attack. |

# Types of DoS and DDoS attacks
**Teardrop attack**

A teardrop attack is a DoS attack that sends countless Internet Protocol (IP) data fragments to a network. When the network tries to recompile the fragments into their original packets, it is unable to.

For example, the attacker may take very large data packets and break them down into multiple fragments for the targeted system to reassemble. However, the attacker changes how the packet is disassembled to confuse the targeted system, which is then unable to reassemble the fragments into the original packets.

**Flooding attack**

A flooding attack is a DoS attack that sends multiple connection requests to a server but then does not respond to complete the handshake.

For example, the attacker may send various requests to connect as a client, but when the server tries to communicate back to verify the connection, the attacker refuses to respond. After repeating the process countless times, the server becomes so inundated with pending requests that real clients cannot connect, and the server becomes “busy” or even crashes.

**IP fragmentation attack**

An IP fragmentation attack is a type of DoS attack that delivers altered network packets that the receiving network cannot reassemble. The network becomes bogged down with bulky unassembled packets, using up all its resources.

**Volumetric attack**

A volumetric attack is a type of DDoS attack used to target bandwidth resources. For example, the attacker uses a botnet to send a high volume of request packets to a network, overwhelming its bandwidth with [**Internet Control Message Protocol (ICMP)**](https://www.fortinet.com/resources/cyberglossary/internet-control-message-protocol-icmp) echo requests. This causes services to slow down or even cease entirely.

**Protocol attack**

A protocol attack is a type of DDoS attack that exploits weaknesses in Layers 3 and 4 of the [**OSI model**](https://www.fortinet.com/resources/cyberglossary/osi-model). For example, the attacker may exploit the [**TCP connection**](https://www.fortinet.com/resources/cyberglossary/tcp-ip) sequence, sending requests but either not answering as expected or responding with another request using a spoofed source IP address. Unanswered requests use up the resources of the network until it becomes unavailable.

**Application-based attack**

An application-based attack is a type of DDoS attack that targets Layer 7 of the OSI model. An example is a Slowloris attack, in which the attacker sends partial Hypertext Transfer Protocol (HTTP) requests but does not complete them. HTTP headers are periodically sent for each request, resulting in the network resources becoming tied up.

The attacker continues the onslaught until no new connections can be made by the server. This type of attack is very difficult to detect because rather than sending corrupted packets, it sends partial ones, and it uses little to no bandwidth.

# Conclusion

DOS and DDOS both are real threats to online services and systems. A DOS attack is when a single system will be attacked while a DDOS attack will have multiple systems attacking the victim hence making it difficult to defend against the attack. Differentiation between these two sociotechnical attacks is critical when preventing-security measures and risks of harm.
