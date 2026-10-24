# Upstream sources and attribution

Sentinel uses open-source software and public upstream interfaces. Availability, completeness, quotas, redistribution rights, and data licenses remain controlled by the source. Preserve provenance when exporting intelligence. Optional provider credentials are free quota/authentication credentials, not paid integrations.

| Source | Primary project / documentation |
|---|---|
| CISA Known Exploited Vulnerabilities | https://www.cisa.gov/known-exploited-vulnerabilities-catalog · https://github.com/cisagov/kev-data |
| MITRE CWE REST API | https://github.com/CWE-CAPEC/REST-API-wg · https://cwe.mitre.org/about/termsofuse.html |
| OWASP Top 10:2025 | https://github.com/OWASP/Top10/tree/master/2025 · https://top10.owasp.org/2025/ |
| NVD CVE API | https://nvd.nist.gov/developers/vulnerabilities |
| Official CVE List V5 | https://github.com/CVEProject/cvelistV5 · CVE Program terms: https://www.cve.org/Legal/TermsOfUse |
| Debian Security Tracker | https://security-tracker.debian.org/tracker/ · JSON: https://security-tracker.debian.org/tracker/data/json |
| Ubuntu Security Notices | https://ubuntu.com/security/notices · JSON: https://ubuntu.com/security/notices.json |
| Trickest CVE index | https://github.com/trickest/cve · MIT-licensed index; referenced repositories retain their own licenses |
| FIRST EPSS | https://www.first.org/epss/api |
| MITRE ATT&CK STIX | https://github.com/mitre-attack/attack-stix-data |
| RansomLook | https://www.ransomlook.io/about · https://github.com/RansomLook/RansomLook |
| GitHub Advisory Database | https://docs.github.com/en/rest/security-advisories/global-advisories |
| OSV | https://google.github.io/osv.dev/api/ |
| CISA Vulnrichment | https://github.com/cisagov/vulnrichment |
| Apache HTTP Server advisories | https://httpd.apache.org/security/vulnerabilities_24.html |
| Apache Tomcat advisories | https://tomcat.apache.org/security-9.html · https://tomcat.apache.org/security-10.html · https://tomcat.apache.org/security-11.html |
| OpenSSL advisories | https://openssl-library.org/news/vulnerabilities/ |
| curl advisory feed | https://curl.se/docs/security.html · https://curl.se/docs/vuln.json |
| Microsoft Security Update Guide | https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API |
| Nuclei templates | https://github.com/projectdiscovery/nuclei-templates |
| Sigma rules | https://github.com/SigmaHQ/sigma |
| Emerging Threats Open rules | https://rules.emergingthreats.net/open/suricata/ |
| OpenVEX schema | https://github.com/openvex/spec |

RansomLook publishes its code under AGPLv3 and its data under CC BY 4.0 according to its About page. Imported rule references retain their upstream source URLs; Sentinel does not grant new licenses for rule contents. Use upstream license files when distributing rule bundles. Public access to an API is not itself an open-source license for every returned datum.

CWE definitions retain MITRE attribution and their upstream terms; the REST API specification license does not relicense CWE content. OWASP Top 10 content retains its upstream CC BY-SA 4.0 license and attribution. Sentinel imports category names and explicit mappings, not attack examples. NVD patch links are extracted only from references tagged `Patch`. Vendor adapters also retain explicitly supplied fix commit references; their target pages are not fetched or executed. A link is upstream remediation evidence, not independent confirmation that a fix works for a deployment.

Apache advisory text retains attribution to the Apache Software Foundation; OpenSSL advisory text retains OpenSSL attribution; curl advisory data retains project curl attribution. These adapters parse public publisher documents and retain document hashes and retrieval dates. Review each publisher’s terms when redistributing extracted content; Sentinel’s GPL license does not relicense it.
