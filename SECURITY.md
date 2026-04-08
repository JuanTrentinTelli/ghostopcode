# Security Policy

## Authorized use

GhostOpcode is an offensive reconnaissance tool intended **only** for use in **authorized** environments.

**By using this software you accept all of the following:**

- You have **explicit written permission** from the owner of any target system **before** you run the tool
- You are **solely responsible** for how you use this software
- The authors **accept no liability** for misuse, illegal use, or unauthorized use **under any circumstances**
- Unauthorized use may be a criminal offense under Brazil’s **LGPD** (General Data Protection Law), **Law 12.737/2012** (computer-crime statute), and comparable laws in other jurisdictions

---

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.9.x | ✅ Current |
| 1.8.x | ✅ Critical fixes only |
| Pre-1.8 | ❌ Unsupported |

---

## Reporting vulnerabilities in GhostOpcode

If you find a **security vulnerability in GhostOpcode itself** (not in third-party targets), please follow **responsible disclosure**:

### What to report

- Issues that allow **arbitrary code execution**
- Flaws that **expose sensitive operator data**
- **Bypasses** of framework security controls
- **Critical CVEs** in bundled or documented dependencies

### How to report

1. **Do not** open a **public** issue with exploit details
2. Open an issue titled **`[SECURITY] short generic summary`** or contact the maintainer **privately**
3. Include: description, **steps to reproduce**, estimated impact, and **affected version(s)**

### What to expect

- Acknowledgement within **72 hours** (best effort)
- Triage and severity assessment
- A fix in a **future release** if the issue is confirmed
- **Credit in the changelog** if you want it

---

## Safe usage practices

```bash
# Always confirm authorization before running active modules.
# GhostOpcode requires explicit CONFIRM for invasive modules, e.g.:
# nuclei, port scan (vuln level), packet sniffer

# Restrict access to session output
chmod 700 output/

# Do not commit real target data from output/
echo "output/" >> .gitignore
```

---

## Contact

Maintainer: **GhostOpcode Project**  
Repository: `git@github.com:JuanTrentinTelli/ghostopcode.git`

---

*This project follows **ethical hacking** and **responsible disclosure** principles. Use it responsibly.*
