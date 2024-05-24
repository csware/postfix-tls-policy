# Usage

This project aims to provide a policy map file usable with postfix to prevent downgrades of connections supporting
TLS or even DANE.

The commandline help should be self-explanatory:

```
usage: update.py [-h] [--log {CRITICAL,ERROR,WARNING,INFO,DEBUG}]
                 [--min-security {may,dane,encrypt,fingerprint,secure,dane_only}]
                 [--ignore-lower-than-config]
                 [--mixed-lowest | --no-mixed-lowest] [--no-dnssec]
                 [--no-dane] [--force-dane-only] [--include-policy FILE]
                 [--include-from-log FILE [FILE ...]]
                 [[--] DOMAIN ...]

Postfix TLS policy generator

positional arguments:
  [--] DOMAIN           Use additional domains given on commandline. Use '--' to separate them from files listed for --include-from-log (if used).

optional arguments:
  -h, --help            show this help message and exit
  --log {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        Loglevel to log (default: INFO)
  --min-security {may,dane,encrypt,fingerprint,secure,dane_only}
                        Minimum TLS policy to use, use 'dane' for automatic 'encrypt' or 'may' if TLSA records are not usable or not present at all.
  --ignore-lower-than-config
                        Don't output policy rules that would configure a domain lower than without a policy file (using the current postfix setting 'smtp_tls_security_level').
  --mixed-lowest, --no-mixed-lowest
                        Use lowest/highest denominator for security level if the set of MX servers give different results. (default: True)
  --no-dnssec           Don't use dnssec to validate if MX delegation is save, even if available. Implies --no-dane.
  --no-dane             Don't use dane, even if available.
  --force-dane-only     Force dane using 'dane_only' security level if dane could be detected (will use only 'dane' security level otherwise).
  --include-policy FILE
                        Use domains listed given policy file (can be used multiple times).
  --include-from-log FILE [FILE ...]
                        Use domains logged as connected to in given policy file.
```

This project is based upon an abandoned project described over here: https://www.cs-ware.de/blog/archives/175

# Misc
I take pull requests to include more domains.

## License

CC0 1.0 Universal, see LICENSE file
