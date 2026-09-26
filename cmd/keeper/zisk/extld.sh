#!/bin/sh
# External linker invoked by cmd/link (see toolexec.sh). Instead of linking
# against OpenBSD's libc, it builds the libc shim and startup code in this
# directory and statically links them with the Go object, using the ZisK
# memory layout.
#
# The C compiler and linker are zig's (clang and lld), which cross-compile
# without a dedicated toolchain. ZIG selects the zig binary (default: zig).
set -eu

# Keep the object files in the positional parameters, dropping the flags meant
# for a regular C linker.
out=
n=$#
while [ "$n" -gt 0 ]; do
	arg=$1
	shift
	n=$((n - 1))
	case $arg in
	-o)
		out=$1
		shift
		n=$((n - 1))
		;;
	*.o) set -- "$@" "$arg" ;;
	# cmd/link probes the compiler for supported flags by building a
	# trivial C file; report every such flag as unsupported.
	*.c) exit 1 ;;
	esac
done
if [ -z "$out" ] || [ $# -eq 0 ]; then
	echo "extld.sh: unexpected invocation" >&2
	exit 1
fi

here=$(cd "$(dirname "$0")" && pwd)
zig=${ZIG:-zig}
objdir=$(mktemp -d)
trap 'rm -rf "$objdir"' EXIT

# Keep zig's caches out of $HOME, which may not be writable (e.g. in package
# build sandboxes).
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$objdir/zig-cache}"
export ZIG_LOCAL_CACHE_DIR="${ZIG_LOCAL_CACHE_DIR:-$objdir/zig-cache}"

cflags="-target riscv64-freestanding-none -mcpu=generic_rv64+m+a+f+d -mabi=lp64d
	-mcmodel=medany -O2 -Wall -Werror -ffreestanding -fno-builtin
	-fno-stack-protector -fno-pic -fno-asynchronous-unwind-tables -fno-unwind-tables
	-nostdlib"
for src in crt0.S switch.S libc.c; do
	"$zig" cc $cflags -c "$here/$src" -o "$objdir/${src%.*}.o"
done

"$zig" ld.lld -static --no-relax -T "$here/zisk.ld" -o "$out" \
	"$objdir/crt0.o" "$@" "$objdir/switch.o" "$objdir/libc.o"
