#!/usr/bin/env python3
import sys
import os
import subprocess
import re
import argparse
import enum
import logging, logging.config

# see https://www.postfix.org/postconf.5.html#smtp_tls_policy_maps
class SecurityLevel(enum.IntEnum):
    none = enum.auto()
    may = enum.auto()
    dane = enum.auto()
    encrypt = enum.auto()
    verify = enum.auto()
    secure = enum.auto()
    dane_only = enum.auto()
    
    def __str__(self):
        return self.name

# parse commandline
parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description="Postfix TLS policy generator")
parser.add_argument("--log", metavar='LOGLEVEL', help="Loglevel to log", default="INFO")
parser.add_argument("--min-security", type=str, choices=[str(x) for x in list(SecurityLevel)], default="dane", help="Minimum TLS policy to use, use 'dane' for automatic 'encrypt' or 'may' if TLSA records are not usable or not present at all.")
parser.add_argument("--no-dane", default=False, action='store_true', help="Don't use dane, even if available.")
parser.add_argument("--force-dane", default=False, action='store_true', help="Force dane using 'dane_only' security level if dane could be detected (will use only 'dane' security level otherwise).")
parser.add_argument("--include-policy", metavar="FILE", action='append', help="Use domains listed given policy file (can be used multiple times).")
parser.add_argument("--include-connected-to", default=False, action='store_true', help="Use domains logged as connected to in /var/log/mail.log{.1}.")
parser.add_argument("domain", type=str, help="Use additional domains given on commandline.", nargs="*")
args = parser.parse_args()
args.min_security = SecurityLevel[args.min_security]

logging.config.dictConfig({
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "%(asctime)s [%(levelname)-7s] %(name)s {%(threadName)s} %(filename)s:%(lineno)d: %(message)s",
            "color": True
        }
    },
    "handlers": {
        "stderr": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "simple"
        },
    },
    "loggers": {
        "": {
            "level": args.log,
            "handlers": ["stderr"]
        }
    }
})
logger = logging.getLogger(__name__)
logger.info('Logger configured...')



used_domains = set()
if args.include_connected_to:
    policy_dir=os.path.dirname(sys.argv[0])
    for filename in ("/var/log/mail.log", "/var/log/mail.log.1"):
        logger.info(f"Extracting domains from '{filename}'...")
        proc = subprocess.Popen(["perl", f"{policy_dir}/extract-domains.pl", filename], stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            domain = line.decode("utf-8").split(":")[0]
            used_domains.add(domain)

policy_domains = set()
if args.include_policy:
    for filename in args.include_policy:
        if not os.path.exists(filename):
            logger.error(f"Could not find policy file at '{filename}', ignoring...")
            continue
        logger.info(f"Extracting domains from '{filename}'...")
        with open(filename) as fp:
            # ignore comments
            pattern = re.compile(r"^(\s?#.*)|((\.?)([^\s]+)\s*.*)$")
            while True:
                line = fp.readline()
                if not line:
                    break
                matches = re.match(pattern, line)
                if matches and matches.group(2):    # ignore comments
                    has_dot = True if len(matches.group(3)) else False
                    domain = matches.group(4)
                    policy_domains.add(domain)

all_domains = used_domains.union(policy_domains)
if args.domain:
    logger.info(f"Domains supplied on comandline: {set(args.domain)}")
if args.domain:
    all_domains = all_domains.union(set(args.domain))
logger.info(f"Extracted {len(used_domains)} domains from mail.log(.1), {len(policy_domains)} domains from policy files and added {len(args.domain)} domains from commandline ({len(all_domains)} domains in summary)...")

# see https://www.postfix.org/FORWARD_SECRECY_README.html#status
nonexistent_regex = re.compile(r"^posttls-finger: Destination address lookup failed:.*$")
dane_regex = re.compile(r"^posttls-finger: using DANE RR:.*$")
secure_regex = re.compile(r"^posttls-finger: Verified TLS connection established.*$")
unmatched_regex = re.compile(r"^posttls-finger: Trusted TLS connection established.*$")
starttls_regex = re.compile(r"^posttls-finger: > STARTTLS$")
for domain in all_domains:
    not_existing = False
    has_dane = False
    is_secure = False
    is_unmatched = False
    has_starttls = False
    logger.info(f"Testing {domain}...")
    proc = subprocess.Popen(["posttls-finger", "-l", "dane", "-P", "/etc/ssl/certs", "-otls_eecdh_auto_curves=X448,X25519,secp384r1,prime256v1", "-otls_high_cipherlist=ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA", domain], stdout=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        line = line.decode("utf-8")
        logger.debug(f"> {line.strip()}")
        if re.match(nonexistent_regex, line):
            not_existing = line
        if re.match(dane_regex, line):
            has_dane = True
        if re.match(secure_regex, line):
            is_secure = True
        if re.match(unmatched_regex, line):
            is_unmatched = True
        if re.match(starttls_regex, line):
            has_starttls = True
    
    if not_existing:
        logger.warning(f"Ignoring nonexistent domain '{domain}', {not_existing.strip()}")
        continue
    logger.info(f"--> {has_dane = }, {is_secure = }, {is_unmatched = }, {has_starttls = }")
    level = SecurityLevel.none
    if has_dane and not args.no_dane:
        level = SecurityLevel.dane_only if args.force_dane else SecurityLevel.dane
    elif is_secure:
        level = SecurityLevel.secure
    elif is_unmatched:
        level = SecurityLevel.encrypt
    elif has_starttls:
        level = SecurityLevel.encrypt
    else:
        level = SecurityLevel.none
    
    comment = []
    if level < args.min_security:
        logger.warning(f"Increasing security level from '{level}' to minimum allowed '{args.min_security}' for domain: {domain}")
        comment.append(f"increased security level from '{level}' to minimum allowed '{args.min_security}'")
        level = args.min_security
    comment = " ; ".join(comment)
    if len(comment):
        comment = f"\t# {comment}"
    
    levelstring = "dane-only" if level==SecurityLevel.dane_only else str(level)
    print(f"{domain}\t\t{levelstring}{comment}")
