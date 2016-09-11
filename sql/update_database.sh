#!/bin/sh
if [ -z "$1" ]; then
    echo "Usage: $(basename "$0") POLICY_FILE" >&2
    exit 1
fi
if [ -z "$TEMPLATE" ]; then
    TEMPLATE="DELETE FROM tls_policy WHERE domain = '{domain}';"
    TEMPLATE="$TEMPLATE INSERT INTO tls_policy (domain, policy, params) VALUES ('{domain}', '{policy}', '{params}');"
fi

DATABASE="$1"
[ "$DATABASE" = "-" ] && DATABASE="/dev/stdin"

EXIT_CODE=0
while read -r LINE || [ -n "$LINE" ]; do
    [ -n "$LINE" ] || continue
    [ "$(echo "$LINE" | cut -c 1)" = "#" ] && continue

    DATA="$(echo "$LINE" | sed -e 's/\s\+/ /')"
    DOMAIN="$(echo "$DATA" | cut -s -d ' ' -f 1)"
    POLICY="$(echo "$DATA" | cut -s -d ' ' -f 2)"
    PARAMS="$(echo "$DATA" | cut -s -d ' ' -f 3-)"

    if [ -z "$(echo "$DOMAIN" | sed -ne '/^[a-zA-Z0-9._-]\{1,255\}$/p')" ] \
        || ( case "$POLICY" in none|may|encrypt|dane|dane-only|fingerprint|verify|secure) false ;; esac ) \
        || ( case "$POLICY" in fingerprint|verify|secure) false ;; esac && [ -n "$PARAMS" ] ) \
        || ( [ "$POLICY" = "fingerprint" ] && [ -z "$(echo "$PARAMS" | sed -ne '/^match=[a-fA-F0-9:|]\+$/p')" ] ) \
        || ( ! case "$POLICY" in verify|secure) false ;; esac && [ -z "$(echo "$PARAMS" | sed -ne '/^match=[a-zA-Z0-9:._-]\+$/p')" ] )
    then
        echo "Invalid row: $LINE" >&2
        EXIT_CODE=1
        continue
    fi

    echo "$TEMPLATE" | sed \
        -e "s/{domain}/$(echo "$DOMAIN" | sed -e 's/[\/&]/\\&/g')/g" \
        -e "s/{policy}/$(echo "$POLICY" | sed -e 's/[\/&]/\\&/g')/g" \
        -e "s/{params}/$(echo "$PARAMS" | sed -e 's/[\/&]/\\&/g')/g"
done < "$DATABASE"

exit $EXIT_CODE

