#!/usr/bin/env python3
import os
import re
import sys
import collections

from publicsuffix2 import get_sld

domains = collections.defaultdict(list)

filename=sys.argv[1]
with open(filename, 'r') as fp:
    # ignore comments
    pattern = re.compile(r"^(\s?#.*)|((\.?)([^\s]+)\s*.*)$")
    while True:
        line = fp.readline()
        if not line:
            break
        matches = re.match(pattern, line)
        if matches and matches.group(2):    # ignore comments
            domains[get_sld(matches.group(4))].append(matches.group(4).lower())

with open(filename, 'w') as fp:
     for k, domains in sorted(domains.items()):
        fp.write(k)
        fp.write("\n")
        for domain in sorted([x for x in domains if x != k]):
            fp.write(domain)
            fp.write("\n")
