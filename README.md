### Weak ephemeral Diffie-Hellman parameter detection for SSL/TLS services.

This script simulates SSL/TLS handshakes using ciphersuites that have ephemeral
Diffie-Hellman as the key exchange algorithm.

Diffie-Hellman MODP group parameters are extracted and analyzed for use of common
primes and vulnerability to LOGJAM precomputation attacks.

Opportunistic STARTTLS sessions are established on services that support them.

### Usage:

`nmap --script path/to/ssl-dh-params <target>`

### Sample output:

```
 | ssl-dh-params: 
 |   VULNERABLE:
 |   Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)
 |     State: VULNERABLE
 |     IDs:  CVE:CVE-2015-4000  OSVDB:122331
 |       The Transport Layer Security (TLS) protocol contains a flaw that is triggered
 |       when handling Diffie-Hellman key exchanges defined with the DHE_EXPORT cipher.
 |       This may allow a man-in-the-middle attacker to downgrade the security of a TLS
 |       session to 512-bit export-grade cryptography, which is significantly weaker,
 |       allowing the attacker to more easily break the encryption and monitor or tamper
 |       with the encrypted stream.
 |     Disclosure date: 2015-5-19
 |     Check results:
 |       EXPORT DH PRIME 1:
 |         Cipher: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
 |         Source: mod_ssl 2.2.x/Hardcoded 512-bit prime
 |         Length: 512
 |     References:
 |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000
 |       https://weakdh.org
 |       http://osvdb.org/122331
 |   
 |   Diffie-Hellman Key Exchange Discrete Logarithm Precomputation Vulnerability
 |     State: VULNERABLE
 |       Transport Layer Security (TLS) services that use one of a few commonly shared
 |       Diffie-Hellman groups of insufficient size may be susceptible to passive
 |       eavesdropping from an attacker with nation-state resources.
 |     Check results:
 |       COMMON DH PRIME 1:
 |         Cipher: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
 |         Source: mod_ssl 2.2.x/Hardcoded 512-bit prime
 |         Length: 512
 |       COMMON DH PRIME 2:
 |         Cipher: TLS_DHE_RSA_WITH_DES_CBC_SHA
 |         Source: mod_ssl 2.2.x/Hardcoded 1024-bit prime
 |         Length: 1024
 |     References:
 |_      https://weakdh.org
```

Depends on TLS library code currently available only in the development version
of Nmap, which can be obtained by cloning and compiling the Subversion repository
at https://svn.nmap.org/nmap.

