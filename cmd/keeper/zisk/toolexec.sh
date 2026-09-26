#!/bin/sh
# go build -toolexec wrapper that makes the final link external, going through
# extld.sh. The go command itself refuses -linkmode=external without cgo, but
# cmd/link supports it and is all we need: runtime/cgo is not linked in.
#
# Usage: GOOS=openbsd GOARCH=riscv64 CGO_ENABLED=0 go build -tags zisk \
#            -toolexec "$PWD/cmd/keeper/zisk/toolexec.sh" ./cmd/keeper
set -eu

here=$(cd "$(dirname "$0")" && pwd)
tool=$1
shift

if [ "$(basename "$tool")" != link ]; then
	exec "$tool" "$@"
fi
for arg; do
	if [ "$arg" = -V=full ]; then
		# The go command identifies the linker by this output when deciding
		# whether a binary is up to date. Mix in the shim so that changing
		# it causes a relink.
		shim=$(cat "$here/crt0.S" "$here/switch.S" "$here/libc.c" "$here/zisk.ld" "$here/extld.sh" | cksum)
		echo "$("$tool" "$@") zisk-shim=${shim%% *}"
		exit
	fi
done

# Flags must precede the package archive, which is the last argument, and come
# after the go command's own -extld so that they take precedence.
orig=$#
n=$#
for arg; do
	n=$((n - 1))
	if [ $n -eq 0 ]; then
		set -- "$@" -linkmode=external -extld="$here/extld.sh"
	fi
	set -- "$@" "$arg"
done
shift "$orig"
exec "$tool" "$@"
