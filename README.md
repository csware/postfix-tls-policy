# Usage

This project aims to provide a policy map file usable with postfix to prevent downgrades of connections supporting
TLS or even DANE.

The commandline help should be self-explanatory:

```
$ ./update.py --help
usage: update.py [-h] [--log LOGLEVEL] [--min-security {none,may,dane,encrypt,verify,secure,dane_only}] [--no-dane] [--include-policy FILE] [--include-connected-to]
                 [domain ...]

Postfix TLS policy generator

positional arguments:
  domain                Use additional domains given on commandline.

options:
  -h, --help            show this help message and exit
  --log LOGLEVEL        Loglevel to log
  --min-security {none,may,dane,encrypt,verify,secure,dane_only}
                        Minimum TLS policy to use, use 'dane' for automatic 'encrypt' or 'may' if TLSA records are not usable or not present at all.
  --no-dane             Don't use dane, even if available.
  --include-policy [FILE]
                        Use domains listed given policy file (can be used multiple times).
  --include-connected-to
                        Use domains logged as connected to in /var/log/mail.log{.1}.
```

This project is based upon an abandoned project described over here: https://www.cs-ware.de/blog/archives/175

# Misc
I take pull requests to include more domains.

## License

CC0 1.0 Universal, see LICENSE file