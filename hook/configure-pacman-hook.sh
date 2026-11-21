#!/bin/bash

hook=${1:-/usr/share/libalpm/hooks/traur.hook}
libalpm=${2:-/usr/lib/libalpm.so}

# CachyOS's parser contains this option name. Stock libalpm rejects unknown keys.
if LC_ALL=C grep -aFzqx NetworkAccess "$libalpm"; then
    from='# NetworkAccess = allowed'
    to='NetworkAccess = allowed'
else
    from='NetworkAccess = allowed'
    to='# NetworkAccess = allowed'
fi

if grep -Fxq "$from" "$hook"; then
    sed -i "s/^$from$/$to/" "$hook"
fi
