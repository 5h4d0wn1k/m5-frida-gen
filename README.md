# MO5 — Frida Script Generator

Generate Frida instrumentation scripts for Android app security testing.

## Overview

This project generates ready-to-use Frida scripts for SSL pinning bypass, root detection bypass, class/method enumeration, and custom hook generation. It produces both JavaScript output and JSON configuration.

## Features

- **SSL Bypass Scripts**: OkHttp3, WebView, hostname verifier, trust manager, NetworkSecurityConfig
- **Root Detection Bypass**: File checks, process checks, package checks, binary checks
- **Class Enumeration**: Loaded classes, methods, fields, constructors, interfaces
- **Hook Generation**: Constructor hooks, return value hooks, argument hooks, modifying hooks
- **Script Builder**: Composite scripts combining multiple bypass techniques

## Installation

Standard library only — no dependencies required.

```bash
# Frida CLI must be installed separately
pip install frida-tools
```

## Usage

```bash
# Generate SSL bypass script
python3 frida_gen.py ssl-bypass

# Generate root detection bypass
python3 frina_gen.py root-bypass

# Generate class enumeration for a pattern
python3 frida_gen.py class-enum "com.target.app"

# Generate composite script (SSL + root bypass)
python3 frida_gen.py composite combined

# Generate hook for specific method
python3 frida_gen.py hook android.webkit.WebViewClient onReceivedSslError

# List saved scripts
python3 frida_gen.py list
```

## Example Output

```
Saved: ['frida_output/ssl_bypass.js', 'frida_output/ssl_bypass.json']

=== SSL Bypass Script (excerpt) ===
Java.perform(function() {
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function(...) {
        send("[SSL] Bypassing certificate verification for: " + host);
        return untrustedChain;
    };
});
```

## Architecture

- `FridaScript` — Script model with hooks, enumerations, and exports
- `SSLBypassGenerator` — SSL pinning bypass templates
- `RootDetectionBypassGenerator` — Root detection bypass templates
- `ClassEnumerator` — Class/method enumeration scripts
- `HookGenerator` — Custom hook generation
- `ScriptBuilder` — Composite script assembly
- `FridaGenerator` — Main orchestrator

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the app owner before using this tool
- Unauthorized modification of application behavior is illegal under federal and state laws
- This tool should ONLY be used on applications you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Digital Millennium Copyright Act (DMCA)**: Circumventing software protections may violate copyright law
- **State Laws**: Many states have additional computer crime statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own applications
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Bypassing security controls without authorization
- Extracting sensitive data from applications you do not own
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
