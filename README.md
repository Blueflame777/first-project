🛡️ Advanced Threat Analyzer

An enterprise-grade, client-side Lexical Analysis Engine designed to detect phishing URLs, typosquatting attacks, and malware payload vectors using zero-latency offline heuristics.

🚀 Overview

The Advanced Threat Analyzer is a cybersecurity tool that performs deep pattern recognition on suspicious URLs. Unlike traditional dynamic scanners that rely on external API blocklists, this engine uses mathematical algorithms to calculate the probability of a threat entirely within the browser's local memory.

This ensures zero data leakage, instant results, and the ability to catch zero-day phishing domains before they are ever reported to global threat databases.

✨ Key Features

Deep Lexical Heuristics: Detects IP obfuscation, URL shorteners, excessive subdomains, and suspicious Top-Level Domains (TLDs).

Typosquatting Detection: Uses the Levenshtein Distance algorithm to calculate character edit distances against a database of high-value target brands (e.g., catching paypa1.com).

Gibberish Detection: Calculates Shannon Entropy to identify machine-generated token strings often used in malware infrastructure.

Malware Payload Analysis: Scans URL paths for dangerous executable extensions (.exe, .apk, .bat).

Interactive UI Controls: Toggle "Strict Mode" for aggressive mathematical penalties or bypass "Deep Path Inspection".

Data Visualization: Generates real-time threat score doughnut charts using Chart.js.

Cyberpunk Aesthetic: Features a custom HTML5 <canvas> matrix rain background and glassmorphism UI overlays.

🧠 How the Engine Works

The core of the analyzer is the URLScanner Object-Oriented JavaScript class. It breaks down the target URL into its constituent parts (Protocol, Hostname, Path, Search Params) and runs them through a gauntlet of heuristic checks:

Shannon Entropy (Randomness Check):
The engine measures the predictability of characters in the URL path. A high entropy score ( > 4.0) indicates a highly randomized string, which is a strong indicator of malicious, dynamically generated infrastructure.

Levenshtein Matrix (Brand Spoofing):
The engine builds a mathematical matrix to compare the target domain against an array of known brands (Google, PayPal, Microsoft). If the mathematical "distance" (number of edits required to match) is 1 or 2, it flags the domain as a Typosquatting attack.

Punycode / Homograph Attacks:
Detects the xn-- prefix, catching attackers attempting to use Cyrillic or Greek alphabets to fake English domain names.

Social Engineering Vectors:
Scans for psychological trigger words (urgent, verify, invoice, wallet) embedded in sub-directories.

🛠️ Installation & Usage

Because this tool relies entirely on Client-Side JavaScript, no server setup or complex installation is required.

Clone the repository:

git clone [https://github.com/YOUR_USERNAME/advanced-threat-analyzer.git](https://github.com/YOUR_USERNAME/advanced-threat-analyzer.git)


Open the application:
Simply double-click index.html to open it in any modern web browser.

Run a Scan:
Paste a suspicious URL into the input field and click SCAN_TARGET, or use the "Load Test Vector" dropdown to test pre-configured malicious URLs.

📂 File Structure

index.html - The core application layout, UI controls, and Chart.js integration.

style.css - Custom CSS featuring a dark hacker theme, glassmorphism effects, and CSS animations.

script.js - The brains of the operation. Contains the URLScanner class, mathematical algorithms, dynamic UI toggles, and the Canvas Matrix animation loop.

⚠️ Disclaimer

This tool is designed for educational and heuristic analysis purposes only. Static lexical analysis is incredibly powerful for catching structural anomalies, but it cannot guarantee a website's safety. It does not actively ping servers or scan live page source code. Always exercise caution and use multiple layers of threat intelligence when investigating suspicious links.

Engineered by SYSTEM_ADMIN