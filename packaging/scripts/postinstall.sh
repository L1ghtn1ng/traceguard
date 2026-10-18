#!/bin/sh
# Package managers keep an administrator-edited config file on upgrade with
# the mode it already had, so tighten it in place. It can hold Authorization
# header values, so it must not be readable by other users.
set -e

env_file=/etc/traceguard/traceguard.env

if [ -f "$env_file" ] && [ ! -L "$env_file" ]; then
	chown root:root "$env_file"
	chmod 0600 "$env_file"
fi
