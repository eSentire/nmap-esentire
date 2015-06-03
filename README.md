## Discovery of ephemeral Diffie-Hellman parameters for SSL/TLS services.

This script simulates SSL/TLS handshakes using ciphersuites that have ephemeral
Diffie-Hellman as the key exchange algorithm.

Diffie-Hellman MODP group parameters are extracted and analyzed for use of common
primes and vulnerability to LOGJAM precomputation attacks.

Opportunistic STARTTLS sessions are established on services that support them.

### Usage:

nmap --script path/to/ssl-dh-params <target>

### Sample output:

| ssl-dh-params: 
|   LOGJAM: Vulnerable to DH precomputation attacks!
|   MODP PRIME #1: 
|     Source: mod_ssl 2.2.x/Hardcoded 512-bit prime
|     Length: 512 bits
|     Value: 
|       9fdb8b8a004544f0045f1737d0ba2e0b274cdf1a9f588218fb435316a16e3741
|       71fd19d8d8f37c39bf863fd60e3e300680a3030c6e4c3757d08f70e6aa871033
|   MODP PRIME #2: 
|     Source: mod_ssl 2.2.x/Hardcoded 1024-bit prime
|     Length: 1024 bits
|     Value: 
|       d67de440cbbbdc1936d693d34afd0ad50c84d239a45f520bb88174cb98bce951
|       849f912e639c72fb13b4b4d7177e16d55ac179ba420b2a29fe324a467a635e81
|       ff5901377beddcfd33168a461aad3b72dae8860078045b07a7dbca7874087d15
|       10ea9fcc9ddd330507dd62db88aeaa747de0f4d6e2bd68b0e7393e0f24218eb3


Depends on TLS library code currently available only in the development version
of Nmap, which can be obtained by cloning and compiling the Subversion repository
at https://svn.nmap.org/nmap.

