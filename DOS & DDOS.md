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

# **What are some common types of DDoS attacks?**

Different types of DDoS attacks target varying components of a network connection. In order to understand how different DDoS attacks work, it is necessary to know how a network connection is made.

A network connection on the Internet is composed of many different components or “layers”. Like building a house from the ground up, each layer in the model has a different purpose.

The [OSI model](https://www.cloudflare.com/learning/ddos/glossary/open-systems-interconnection-model-osi/), shown below, is a conceptual framework used to describe network connectivity in 7 distinct layers.

![The OSI model 7 layers: application, presentation, session, transport, network, data link, physical](https://cf-assets.www.cloudflare.com/slt3lc6tev37/6ZH2Etm3LlFHTgmkjLmkxp/59ff240fb3ebdc7794ffaa6e1d69b7c2/osi_model_7_layers.png)

While nearly all DDoS attacks involve overwhelming a target device or network with traffic, attacks can be divided into three categories. An attacker may use one or more different attack vectors, or cycle attack vectors in response to counter measures taken by the target.

# **Application layer attacks**

Application layer (Layer 7) DDoS attacks are performed by overwhelming a web application's resources with a flood of seemingly legitimate requests, such as HTTP floods, by using a botnet. Attackers achieve this by targeting specific application functions like search bars, login pages, or APIs to consume server resources, exhaust database connections, or disrupt session management. [1, 2, 3, 4, 5]  
How the attack works 

• Building a botnet: Attackers use malware to infect a large number of devices (computers, IoT devices) to create a network of compromised machines called a botnet. [6]  
• Launching the attack: The attacker instructs the botnet to send a massive volume of requests to a specific target, like a website, application, or API. [6, 7]  
• Mimicking legitimate traffic: These requests are often crafted to look like normal user traffic, making them difficult to detect and distinguish from legitimate requests. [1, 2, 4]  
• Overwhelming the application: The sheer volume of requests exhausts the server's resources, such as CPU, memory, and database connections, leading to slower performance or a complete crash. [1, 3, 5]  

Common techniques used in the attack 

• HTTP floods: Sending a high volume of HTTP GET or POST requests to overwhelm the server. [4, 8]  
• Cache-busting attacks: Using unique query strings in requests to prevent a content delivery network (CDN) from serving cached content, forcing the origin server to process every request. [4, 9]  
• Authentication exhaustion: Repeatedly submitting login requests or other authentication challenges to overload the authentication system. [1]  
• API floods: Repeatedly calling an API to consume its resources and cause it to crash. [1, 3]  
• Slow-rate attacks: A more subtle "low and slow" method that keeps connections open by sending requests very slowly, which ties up server resources without triggering common detection thresholds. [10]  




# **Application layer attack example:**

![HTTP flood DDoS attack: multiple bot HTTP GET requests to victim](https://cf-assets.www.cloudflare.com/slt3lc6tev37/3jlyZeWRy9eBz3tyEk9mxA/96eab064524495e8f6b2647f1f7b9d60/application_layer_ddos_example.png)

# **HTTP flood**

This attack is similar to pressing refresh in a web browser over and over on many different computers at once – large numbers of HTTP requests flood the server, resulting in denial-of-service.

This type of attack ranges from simple to complex.

Simpler implementations may access one URL with the same range of attacking IP addresses, referrers and user agents. Complex versions may use a large number of attacking IP addresses, and target random urls using random referrers and user agents.

# **Protocol attacks**

# **The goal of the attack:**

Protocol attacks, also known as a state-exhaustion attacks, cause a service disruption by over-consuming server resources and/or the resources of network equipment like [firewalls](https://www.cloudflare.com/learning/security/what-is-a-firewall/) and load balancers.

Protocol attacks utilize weaknesses in layer 3 and layer 4 of the protocol stack to render the target inaccessible.

# **Protocol attack example:**

![Protocol DDoS attack example: SYN flood: spoofed SYN packets](https://cf-assets.www.cloudflare.com/slt3lc6tev37/38KdcqNuv0l0jF4ohUI7bj/44a3f60c5352984258f72a1e69e1bbdd/syn_flood_ddos_example.png)

# **SYN flood**

[A SYN Flood](https://www.cloudflare.com/learning/ddos/syn-flood-ddos-attack/) is analogous to a worker in a supply room receiving requests from the front of the store.

The worker receives a request, goes and gets the package, and waits for confirmation before bringing the package out front. The worker then gets many more package requests without confirmation until they can’t carry any more packages, become overwhelmed, and requests start going unanswered.

This attack exploits the [TCP handshake](https://www.cloudflare.com/learning/ddos/glossary/tcp-ip/) — the sequence of communications by which two computers initiate a network connection — by sending a target a large number of TCP “Initial Connection Request” SYN packets with [spoofed](https://www.cloudflare.com/learning/ddos/glossary/ip-spoofing/) source IP addresses.

The target machine responds to each connection request and then waits for the final step in the handshake, which never occurs, exhausting the target’s resources in the process.

# **Volumetric attacks**

# **The goal of the attack:**

This category of attacks attempts to create congestion by consuming all available bandwidth between the target and the larger Internet. Large amounts of data are sent to a target by using a form of amplification or another means of creating massive traffic, such as requests from a botnet.

# **Amplification example:**

![Amplification DDoS attack example: DNS amplification: spoofed DNS requests](https://cf-assets.www.cloudflare.com/slt3lc6tev37/1FIBEeoyzoa64lVGlWKaRV/3b878bb03df1729b48cd3f667cdfe3de/amplification_ddos_example.png)

# **DNS Amplification**

A [DNS amplification](https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/) is like if someone were to call a restaurant and say “I’ll have one of everything, please call me back and repeat my whole order,” where the callback number actually belongs to the victim. With very little effort, a long response is generated and sent to the victim.

By making a request to an open [DNS](https://www.cloudflare.com/learning/dns/what-is-dns/) server with a spoofed IP address (the IP address of the victim), the target IP address then receives a response from the server.

# **What is the process for mitigating a DDoS attack?**

The key concern in mitigating a DDoS attack is differentiating between attack traffic and normal traffic.

For example, if a product release has a company’s website swamped with eager customers, cutting off all traffic is a mistake. If that company suddenly has a surge in traffic from known attackers, efforts to alleviate an attack are probably necessary.

The difficulty lies in telling the real customers apart from the attack traffic.

In the modern Internet, DDoS traffic comes in many forms. The traffic can vary in design from un-spoofed single source attacks to complex and adaptive multi-vector attacks.

A multi-vector DDoS attack uses multiple attack pathways in order to overwhelm a target in different ways, potentially distracting mitigation efforts on any one trajectory.

An attack that targets multiple layers of the protocol stack at the same time, such as a DNS amplification (targeting layers 3/4) coupled with an [HTTP flood](https://www.cloudflare.com/learning/ddos/http-flood-ddos-attack/) (targeting layer 7) is an example of multi-vector DDoS.

Mitigating a multi-vector DDoS attack requires a variety of strategies in order to counter different trajectories.

Generally speaking, the more complex the attack, the more likely it is that the attack traffic will be difficult to separate from normal traffic - the goal of the attacker is to blend in as much as possible, making mitigation efforts as inefficient as possible.

Mitigation attempts that involve dropping or limiting traffic indiscriminately may throw good traffic out with the bad, and the attack may also modify and adapt to circumvent countermeasures. In order to overcome a complex attempt at disruption, a layered solution will give the greatest benefit.

# **Blackhole routing**

One solution available to virtually all network admins is to create a [blackhole](https://www.cloudflare.com/learning/ddos/glossary/ddos-blackhole-routing/) route and funnel traffic into that route. In its simplest form, when blackhole filtering is implemented without specific restriction criteria, both legitimate and malicious network traffic is routed to a null route, or blackhole, and dropped from the network.

If an Internet property is experiencing a DDoS attack, the property’s Internet service provider (ISP) may send all the site’s traffic into a blackhole as a defense. This is not an ideal solution, as it effectively gives the attacker their desired goal: it makes the network inaccessible.

# **Rate limiting**

Limiting the number of requests a server will accept over a certain time window is also a way of mitigating denial-of-service attacks.

While rate limiting is useful in slowing web scrapers from stealing content and for mitigating [brute force](https://www.cloudflare.com/learning/bots/brute-force-attack/) login attempts, it alone will likely be insufficient to handle a complex DDoS attack effectively.

Nevertheless, rate limiting is a useful component in an effective DDoS mitigation strategy. Learn about [Cloudflare's rate limiting](https://www.cloudflare.com/application-services/products/rate-limiting/)

# **Web application firewall**

A [Web Application Firewall (WAF)](https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/) is a tool that can assist in mitigating a layer 7 DDoS attack. By putting a WAF between the Internet and an origin server, the WAF may act as a [reverse proxy](https://www.cloudflare.com/learning/cdn/glossary/reverse-proxy/), protecting the targeted server from certain types of malicious traffic.

By filtering requests based on a series of rules used to identify DDoS tools, layer 7 attacks can be impeded. One key value of an effective WAF is the ability to [quickly implement custom rules](https://developers.cloudflare.com/firewall/) in response to an attack. Learn about [Cloudflare's WAF](https://www.cloudflare.com/application-services/products/waf/).

# **Anycast network diffusion**

This mitigation approach uses an Anycast network to scatter the attack traffic across a network of distributed servers to the point where the traffic is absorbed by the network.

Like channeling a rushing river down separate smaller channels, this approach spreads the impact of the distributed attack traffic to the point where it becomes manageable, diffusing any disruptive capability.

The reliability of an [Anycast network](https://www.cloudflare.com/learning/cdn/glossary/anycast-network/) to mitigate a DDoS attack is dependent on the size of the attack and the size and efficiency of the network. An important part of the DDoS mitigation implemented by Cloudflare is the use of an Anycast distributed network.

Cloudflare has a 405 Tbps network, which is an order of magnitude greater than the largest DDoS attack recorded.

If you are currently [under attack](https://www.cloudflare.com/under-attack-hotline/), there are steps you can take to get out from under the pressure. If you are on Cloudflare already, you can follow [these steps](https://support.cloudflare.com/hc/en-us/articles/200170196-I-am-under-DDoS-attack-what-do-I-do-) to mitigate your attack.

The DDoS protection that we implement at Cloudflare is multifaceted in order to mitigate the many possible attack vectors. Learn more about Cloudflare's [DDoS protection](https://www.cloudflare.com/ddos/) and how it works.
# Conclusion

DOS and DDOS both are real threats to online services and systems. A DOS attack is when a single system will be attacked while a DDOS attack will have multiple systems attacking the victim hence making it difficult to defend against the attack. Differentiation between these two sociotechnical attacks is critical when preventing-security measures and risks of harm.
