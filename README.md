# SanderTrap 🛡️

> Advanced honeypot with ReDoS protection, a tarpit engine, and JSONL logging.

![Java](https://img.shields.io/badge/Java-11+-orange)
![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20Windows-blue)
![License](https://img.shields.io/badge/License-GPL--3.0-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## Overview

SanderTrap is a next-generation honeypot designed to detect, trap, and log malicious activity in real time. It combines advanced payload detection with a smart blacklist and a tarpit mechanism to slow down attackers.

Built with zero external dependencies — just the Java Standard Library.

### Key Features
- Advanced payload detection: SQLi, XSS, and Command Injection (CMD).
- Anti-ReDoS: limits input size to 8 KB to prevent resource exhaustion.
- Tarpit engine: holds attackers in a slow loop for up to 2 minutes.
- Smart blacklist: IPs auto-expire after 1 hour (no permanent lockouts).
- Polyglot logging: outputs to CSV and JSON Lines (.jsonl) in real time.
- Dynamic banners: randomized SSH/FTP/MySQL banners to confuse scanners.

---

## Quick Start

### Prerequisites
- Java JDK 11+ installed.
- (Optional) Termux for Android users.

### Install & Run

```bash
# 1. Clone the repository
git clone https://github.com/aleksandergrambelik-png/SanderTrap.git
cd SanderTrap

# 2. Compile the source code
javac SanderTrap_v4.java

# 3. Run the honeypot
java SanderTrap_v4
```

By default, SanderTrap listens on ports: 2121, 2222, 3306, 8080, 33890.

⚠️ WARNING: This tool is intended for defensive purposes only. Run it only on networks you own or have explicit permission to test. Unauthorized use may be illegal.

---

## Proof of Concept (PoC)

Example screenshot of SanderTrap detecting a Command Injection and engaging the tarpit:

![SanderTrap POC](assets/poc.jpg)

Note: IP addresses in screenshots and examples are redacted for ethical disclosure (e.g., 192.168.1.xxx).

---

## Log Output

SanderTrap writes two log files to the working directory:

- sander_v4_behavior.csv (CSV)
- sander_v4_behavior.jsonl (JSON Lines)

Example CSV (sander_v4_behavior.csv):

```csv
timestamp,event,ip,port,details
2026-10-19 16:34:01,CMD_INJECTION,192.168.1.xxx,8080,"Command injection detected"
2026-10-19 16:34:01,TARPIT_ENGAGED,192.168.1.xxx,8080,"Slowing down attacker"
```

Example JSONL (sander_v4_behavior.jsonl):

```json
{"timestamp":"2026-10-19 16:34:01","event":"CMD_INJECTION","ip":"192.168.1.xxx","port":8080,"details":"Command injection detected"}
{"timestamp":"2026-10-19 16:34:01","event":"TARPIT_ENGAGED","ip":"192.168.1.xxx","port":8080,"details":"Slowing down attacker"}
```

All example IPs are redacted for privacy and ethical reasons.

---

## Configuration (Optional)

Ports and thresholds are currently hardcoded in SanderTrap_v4.java. To change default ports, edit the constant in the Java file (search for the PORTS array) or update the source accordingly.

Example in the Java source:
```java
private static final int[] PORTS = {2121, 2222, 3306, 8080, 33890};
```

A future release will add a config.json or CLI arguments for easier configuration.

---

## AI Collaboration & Tooling

This project was developed with human and AI collaboration. For debugging and documentation support we used multiple AI assistants.

Contributors:
- Idea & Architecture: Aleksander
- Core Logic & QA: Aleksander
- Debugging & Review: DeepSeek V4.1 Pro, Qwen 3.5plus
- Documentation & Editing: DeepSeek, Qwen 3.5plus, Copilot (GitHub Copilot), Aleksander

Notes:
- Qwen 3.5plus was used for debugging assistance and documentation drafting.
- Copilot (GitHub Copilot) assisted with wording, formatting, and repository updates.

---

## License

This project is licensed under the GNU General Public License v3.0. See LICENSE for details.

---

## Author

Aleksander (@aleksandergrambelik-png)

Built with ❤️ and too much coffee — sometimes even from a phone. 📱☕
