#!/usr/bin/env python3
import sys
import os
import subprocess
import re
import argparse
import enum
import datetime
import collections
import glob
import itertools
import gzip
import logging, logging.config

import dns.resolver, dns.flags
import publicsuffix2


# see https://www.postfix.org/postconf.5.html#smtp_tls_policy_maps
class SecurityLevel(enum.IntEnum):
    may = enum.auto()
    dane = enum.auto()
    encrypt = enum.auto()
    fingerprint = enum.auto()
    secure = enum.auto()
    dane_only = enum.auto()
    
    def __str__(self):
        return self.name

def merge_all_mxs(to_filter, default_value, value_name, comments=[], no_fallback=None):
    retval = [mx for mx, value in to_filter.items() if value != default_value]
    if len(retval) == 0:
        return default_value
    elif len(retval) == len(to_filter):
        return not default_value
    if len(retval) != len(to_filter):
        if isinstance(no_fallback, set):
            logger.warning(f"Mixed results: MXs {retval} {value_name}, ignoring these!")
            comments.append(f"WARNING: Mixed results: MXs {retval} {value_name}, ignoring these!")
            no_fallback.update(set([mx for mx, value in to_filter.items() if value == default_value]))
            return default_value
        logger.warning(f"Mixed results: MXs {retval} {value_name}, dropping support!")
        comments.append(f"WARNING: Mixed results: MXs {retval} {value_name}, dropped support!")
        return not default_value

def resolve_mx(domain):
    resolver = dns.resolver.Resolver(configure=True)
    resolver.ednsflags |= dns.flags.EDNSFlag.DO
    try:
        result = resolver.resolve(domain, "MX")
        if result.response.flags & dns.flags.Flag.AD:
            return True, [(str(rdata.exchange)[:-1] if str(rdata.exchange)[-1] == "." else str(rdata.exchange)) for rdata in result]
        else:
            return False, [(str(rdata.exchange)[:-1] if str(rdata.exchange)[-1] == "." else str(rdata.exchange)) for rdata in result]
    except:
        return None, []

# see https://stackoverflow.com/a/33214423/3528174
def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False
    labels = hostname.split(".")
    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False
    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)

def group_by_sld(names):
    data = [(publicsuffix2.PublicSuffixList(idna=is_valid_hostname(name)).get_sld(name), name) for name in names]
    mapping = collections.defaultdict(list)
    for k, v in data:
        mapping[k].append(v)
    return [v for k, v in mapping.items()]

def common_dns_suffixes(names):
    if len(names) == 0:
        return []
    longest = max([len(n.split(".")) for n in names])
    def return_it(prefix):
        joined = ".".join(prefix[::-1])
        retval = set()
        if joined in names:
            retval.add(joined)
        retval.add(f".{joined}" if len(prefix)<longest else joined)
        return list(retval)
    namelist = [[p for p in n.split(".")[::-1] if p != "*"] for n in names]     #split domain, reverse it and remove wildcards
    prefix = []
    for index in range(len(namelist[0])):
        for name in namelist:
            if index >= len(prefix):
                prefix.append(name[index])
            if index >= len(name) or ".".join(prefix) != ".".join(name[:index+1]):
                return return_it(prefix[:-1])
    return return_it(prefix)

def generate_suffix_matchlist(names):
    retval = []
    for namelist in group_by_sld(names):
        retval += common_dns_suffixes(namelist)
    return retval

def postconf(setting):
    proc = subprocess.Popen(["postconf", "-h", "-p", setting], stdout=subprocess.PIPE)
    line = proc.stdout.readline()
    if not line:
        logger.error(f"Could not read postconf arg '{setting}'!")
        return None
    return re.sub(r"[ ,:]+", ":", line.decode("utf-8").strip())

def start_finger(*args):
    args = [entry for inner in args for entry in inner];
    logger.debug(f"Calling: {' '.join(args)}")
    return subprocess.Popen(args, stdout=subprocess.PIPE)

# see https://stackoverflow.com/a/47080739
def is_gzip_file(filename):
    with open(filename, "rb") as fp:
        return fp.read(2) == b'\x1f\x8b'


# initialize logging as early as possible
logger_config = {
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
            "level": "INFO",
            "handlers": ["stderr"]
        }
    }
}
logging.config.dictConfig(logger_config)
logger = logging.getLogger(__name__)
logger.info('Logger configured...')

# parse commandline
security_levels_list = [str(x) for x in list(SecurityLevel)]
parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description="Postfix TLS policy generator")
parser.add_argument("--log", help="Loglevel to log (default: INFO)", choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"], default="INFO")
parser.add_argument("--min-security", type=str, choices=security_levels_list, default="dane", help="Minimum TLS policy to use, use 'dane' for automatic 'encrypt' or 'may' if TLSA records are not usable or not present at all.")
parser.add_argument("--ignore-lower-than-config", default=False, action='store_true', help="Don't output policy rules that would configure a domain lower than without a policy file (using the current postfix setting 'smtp_tls_security_level').")
parser.add_argument("--mixed-lowest", default=True, action=argparse.BooleanOptionalAction, help="Use lowest/highest denominator for security level if the set of MX servers give different results.")
parser.add_argument("--no-dnssec", default=False, action='store_true', help="Don't use dnssec to validate if MX delegation is save, even if available. Implies --no-dane.")
parser.add_argument("--no-dane", default=False, action='store_true', help="Don't use dane, even if available.")
parser.add_argument("--force-dane-only", default=False, action='store_true', help="Force dane using 'dane_only' security level if dane could be detected (will use only 'dane' security level otherwise).")
parser.add_argument("--include-policy", metavar="FILE", action='append', help="Use domains listed given policy file (can be used multiple times).")
parser.add_argument("--include-from-log", metavar="FILE", action="append", nargs="+", help="Use domains logged as connected to in given policy file.")
parser.add_argument("domain", metavar="[--] DOMAIN", type=str, help="Use additional domains given on commandline. Use '--' to separate them from files listed for --include-from-log (if used).", nargs="*")
args = parser.parse_args()

# check arguments
if args.min_security in (SecurityLevel.dane, SecurityLevel.dane_only) and args.no_dane:
    logger.error("--no-dane and {--min-security dane, --min-security dane_only} are mutually exclusive, aborting!")
    sys.exit(2)

# initialize/convert some values
logger_config["loggers"][""]["level"] = args.log
logging.config.dictConfig(logger_config)
args.min_security = SecurityLevel[args.min_security]
config_trust_level = postconf("smtp_tls_security_level")

if args.ignore_lower_than_config and config_trust_level not in security_levels_list:
    logger.error("--ignore-lower-than-config used but unknown trust level '{config_trust_level}' found in config, use one of: {', '.join(security_levels_list)}")
    sys.exit(2)

# load domains from logfiles
used_domains = set()
if args.include_from_log:
    #May 24 08:20:55 srv1 postfix/smtp[26806]: 49C05220A5C: to=<test@md-textil.de>, relay=mx.md-textil.de[1.2.3.4]:25, delay=3.2, delays=2.8/0.02/0.24/0.08, dsn=2.0.0, status=sent (250 2.0.0 Message accepted.)
    pattern = re.compile(r"^\S+ \d+ \d+:\d+:\d+ \S+ .*/smtp\[\d+\]: [^:]+: to=<[^@]+@([^>]+)>, .*, status=sent")
    files = list(itertools.chain.from_iterable([glob.glob(x) for x in itertools.chain.from_iterable(args.include_from_log)]))
    for filename in files:
        logger.info(f"Extracting domains from '{filename}'...")
        with gzip.open(filename, "rb") if is_gzip_file(filename) else open(filename, "rb") as fp:
            while True:
                line = fp.readline()
                if not line:
                    break
                matches = re.match(pattern, line.decode("utf-8"))
                if matches:
                    used_domains.add(matches.group(1).lower()) 

# load domains from policy files
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
                    policy_domains.add(domain.lower())

# merge all loaded domains
all_domains = used_domains.union(policy_domains)
if args.domain:
    logger.info(f"Domains supplied on comandline: {set(args.domain)}")
if args.domain:
    all_domains = all_domains.union(set(args.domain))
logger.info(f"Extracted {len(used_domains)} domain(s) from logfile(s), {len(policy_domains)} domain(s) from policy file(s) and added {len(args.domain)} domain(s) from commandline ({len(all_domains)} domain(s) in summary)...")
if not len(all_domains):
    logger.error(f"No domains to check, terminating...")
    sys.exit(2)

# print policy header to stdout
print(f"# Generated at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by https://github/tmolitor-stud-tu/postfix-tls-policy generator")
print(f"# Used commandline arguments: {os.path.realpath(sys.argv[0])} --min-security {args.min_security}{' --ignore-lower-than-config' if args.ignore_lower_than_config else ''} {'--mixed-lowest' if args.mixed_lowest else '--no-mixed-lowest'}{' --no-dnssec' if args.no_dnssec else ''}{' --no-dane' if args.no_dane else ''}{' --force-dane-only' if args.force_dane_only else ''} [domains...]")
print(f"")

# load additional posttls-finger arguments from postconf
common_finger_args = {
    "smtp_tls_mandatory_protocols": "-p",
    "smtp_tls_fingerprint_digest": "-d",
    "smtp_tls_mandatory_ciphers": "-g",
    #"tls_eecdh_auto_curves": None,
    "tls_high_cipherlist": None,
    "tls_medium_cipherlist": None,
    "tls_null_cipherlist": None,
}
configured_finger_args = []
for name, translation in common_finger_args.items():
    value = postconf(name)
    if value != None:
        if translation != None:
            configured_finger_args += [translation, value]
        else:
            configured_finger_args += ["-o", f"{name}={value}"];

# iterate over all domains and print calculated policy to stdout
# (make sure this is always sorted to give stable diff output)
all_domains = list(all_domains)
all_domains.sort()
# see https://www.postfix.org/FORWARD_SECRECY_README.html#status for the meaning of "Verified" and "Trusted"
dane_regex = re.compile(r"^posttls-finger: using DANE RR:.*$")
verified_regex = re.compile(r"^posttls-finger: Verified TLS connection established.*$")
unmatched_regex = re.compile(r"^posttls-finger: Trusted TLS connection established.*$")
starttls_regex = re.compile(r"^posttls-finger: > STARTTLS$")
nonexistent_regex = re.compile(r"^posttls-finger: Destination address lookup failed:.*$")
altname_regex = re.compile(r"^posttls-finger: .*subjectAltName: ([a-zA-F0-9._*-]+)$")
fingerprint_regex = re.compile(r"posttls-finger: .*fingerprint=([0-9A-Fa-f:]+),.*$")
for domain in all_domains:
    logger.info(f"Testing {domain}...")
    is_dnssec, mxlist = resolve_mx(domain)
    if args.no_dnssec:
        is_dnssec = False
    if not len(mxlist):
        logger.warning(f"Ignoring domain with nonexisting MX record: {domain}")
        continue
    logger.info(f"--> {is_dnssec = }, {mxlist = }")
    
    mx_not_existing = {}
    mx_has_dane = {}
    mx_is_verified = {}
    mx_is_unmatched = {}
    mx_has_starttls = {}
    mx_cert_names = {}
    mx_fingerprints = {}
    for mx in mxlist:
        mx_not_existing[mx] = False
        mx_has_dane[mx] = False
        mx_is_verified[mx] = False
        mx_is_unmatched[mx] = False
        mx_has_starttls[mx] = False
        mx_cert_names[mx] = set()
        mx_fingerprints[mx] = set()
        
        # connect to mx host and use a match of explicit nexthop, dot-nexthop
        proc = start_finger(["posttls-finger", "-l", "secure", "-P", "/etc/ssl/certs"], configured_finger_args, [f"[{mx}]", f"{domain}", f".{domain}"], ["hostname"] if is_dnssec else [])
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.decode("utf-8")
            logger.debug(f"> {line.strip()}")
            altname_match = re.match(altname_regex, line)
            if altname_match:
                mx_cert_names[mx].add(altname_match.group(1))
            fingerprint_match = re.match(fingerprint_regex, line)
            if fingerprint_match:
                mx_fingerprints[mx].add(fingerprint_match.group(1))
            if re.match(nonexistent_regex, line):
                mx_not_existing[mx] = line
            if re.match(verified_regex, line):
                mx_is_verified[mx] = True
            if re.match(unmatched_regex, line):
                mx_is_unmatched[mx] = True
            if re.match(starttls_regex, line):
                mx_has_starttls[mx] = True
        
        # this separation is needed because posttls-finger will incorrectly overwrite smtp_tls_secure_cert_match to always use hostname,nexthop
        # which is not very useful if we want to know if we need a match= attribute listing the detected cert names
        # --> only use dane security level if domain is dnssec signed
        # --> (the "hostname", "nexthop" will be automatically set by the security level, but are specified nontheless for completeness)
        if mx_has_starttls[mx] and is_dnssec and not args.no_dane:
            proc = start_finger(["posttls-finger", "-c", "-l", "dane", "-P", "/etc/ssl/certs"], configured_finger_args, [mx, "hostname", "nexthop"])
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.decode("utf-8")
                logger.debug(f"> {line.strip()}")
                if re.match(dane_regex, line):
                    mx_has_dane[mx] = True
    
    # merge all results to get the lowest/highest denominator
    comments = []
    extra_kwargs = {
        "comments": comments,
    }
    if not args.mixed_lowest:
        extra_kwargs["no_fallback"] = set()
    has_dane = merge_all_mxs(mx_has_dane, True, "do not support DANE", **extra_kwargs)
    is_verified = merge_all_mxs(mx_is_verified, True, "do not serve a verifiable certificate", **extra_kwargs)
    is_unmatched = merge_all_mxs(mx_is_unmatched, False, "do not have matching hostnames in certificate", **extra_kwargs)
    has_starttls = merge_all_mxs(mx_has_starttls, True, "do not provide TLS at all", **extra_kwargs)
    cert_names = set()
    fingerprints = set()
    for mx in mxlist:
        if not args.mixed_lowest or ("no_fallback" in extra_kwargs and mx in extra_kwargs["no_fallback"]):
            cert_names.update(mx_cert_names[mx])
            fingerprints.update(mx_fingerprints[mx])
    common_cert_suffixes = generate_suffix_matchlist(list(cert_names))
    common_cert_suffixes.sort()
    fingerprints = list(fingerprints)
    fingerprints.sort()
    
    # log raw results
    logger.info(f"--> {is_dnssec = }, {has_dane = }, {is_verified = }, {is_unmatched = }, {has_starttls = }, {common_cert_suffixes = }, {cert_names = }, {fingerprints = }")
    
    # translate raw results into postfix security level (including arguments needed for that security level)
    level = SecurityLevel.may
    levelargs = ""
    if has_dane and not args.no_dane:
        level = SecurityLevel.dane_only if args.force_dane_only else SecurityLevel.dane
    elif is_verified:
        level = SecurityLevel.secure
        if is_dnssec:
            comments.append("MX records could be resolved using DNSSEC, we can trust the hostname from DNS for cert validation")
        comments.append("Matched cert names for nexthop, dot-nexthop" + (", hostname" if is_dnssec else ""))
        levelargs = "match=nexthop:dot-nexthop" + (":hostname" if is_dnssec else "")
    elif is_unmatched:
        level = SecurityLevel.secure
        comments.append("Unmatched cert names, fixing using explictly listed names")
        levelargs = "match=" + ":".join(common_cert_suffixes)
    elif has_starttls:
        if len(fingerprints):
            level = SecurityLevel.fingerprint
            comments.append("Unmatched cert names and untrusted CA, fixing using explict listed fingerprints")
            levelargs = "match=" + "|".join(fingerprints)
        else:
            level = SecurityLevel.encrypt
            comments.append("Unmatched cert names and untrusted CA, using just plain encryption without verification")
    
    # force minimal security level if requested
    if level < args.min_security:
        logger.warning(f"Increasing security level from '{level}' to minimum allowed '{args.min_security}' for domain: {domain}")
        comments.append(f"WARNING: Increased security level from '{level}' to minimum allowed '{args.min_security}'")
        
        # overwrites needed
        if args.min_security == SecurityLevel.dane:
            level = args.min_security
            levelargs = ""
        elif args.min_security == SecurityLevel.encrypt:
            level = args.min_security
            levelargs = ""
        elif args.min_security == SecurityLevel.fingerprint:
            level = args.min_security
            if len(fingerprints):
                levelargs = "match=" + "|".join(fingerprints)
            else:
                logger.warning(f"Increasing security level will likely make domain unusable and/or config-line invalid!")
                comments.append(f"WARNING: Increased security level will likely make domain unusable and/or config-line invalid!")
        elif args.min_security == SecurityLevel.secure:
            # using a common_cert_suffixes match probably won't work
            level = SecurityLevel.secure
            levelargs = "match=" + ":".join(common_cert_suffixes)
            logger.warning(f"Increasing security level will likely make domain unusable and/or config-line invalid!")
            comments.append(f"WARNING: Increased security level will likely make domain unusable and/or config-line invalid!")
        elif args.min_security == SecurityLevel.dane_only:
            level = args.min_security
            levelargs = ""
            logger.warning(f"Increasing security level will likely make domain unusable and/or config-line invalid!")
            comments.append(f"WARNING: Increased security level will likely make domain unusable and/or config-line invalid!")
    
    # output postfix policy map line(s) to stdout
    if args.ignore_lower_than_config and level <= SecurityLevel[config_trust_level]:
        logger.warning(f"Ignoring domain '{domain}' having a lower or equal security level than the globally configured '{config_trust_level}': {level}")
        continue
    if len(comments):
        comments = [f"# {line}\n" for line in comments]
    comments = "".join(comments)
    levelstring = "dane-only" if level==SecurityLevel.dane_only else str(level)
    if len(levelargs):
        levelargs = " " + levelargs
    print(f"{comments}{domain}\t\t{levelstring}{levelargs}")
    print(f"")
