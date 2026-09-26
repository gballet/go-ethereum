# Keeper on the ZisK zkVM

[ZisK](https://github.com/0xPolygonHermez/zisk) runs RISC-V (RV64GC) programs with no operating system. Keeper targets it by compiling for `GOOS=openbsd GOARCH=riscv64`: on OpenBSD, the Go runtime and the `syscall` package never issue system calls themselves and call libc instead. The files in this directory replace libc with an implementation for the zkvm, so the resulting program makes no system calls.

## Building

[zig](https://ziglang.org) is required as the C compiler and linker (tested with 0.16.0). It cross-compiles to bare-metal RISC-V without a dedicated toolchain. Set `ZIG` to use a zig binary that isn't on the `PATH`. The scripts only need a POSIX shell.

From `cmd/keeper`, with Go 1.26 or later:

```bash
GOOS=openbsd GOARCH=riscv64 CGO_ENABLED=0 go build -tags zisk \
    -gcflags=all=-d=compressinstructions=0 -asmflags=all=-d=compressinstructions=0 \
    -toolexec "$PWD/zisk/toolexec.sh" -o keeper-zisk.elf .
```

The ELF contains no compressed (RVC) instructions. `extld.sh` builds the shim for RV64IMAFD, and the flags above stop the Go compiler and assembler from emitting RVC, which they do by default since Go 1.26. This works around a ZisK bug: it decodes `c.fldsp` with `ft0` as its destination as a reserved instruction and halts. The spec only reserves a zero destination for the integer `c.ldsp`/`c.lwsp` (`transpilers/riscv/src/riscv_interpreter.rs`). Go 1.25 never emits compressed instructions and doesn't accept the flags, so drop them there.

Replace `-tags zisk` with `-tags example` to embed the example Hoodi block instead of reading the input. The release build is `go run build/ci.go keeper`, which produces `build/bin/keeper-zisk`. It downloads the zig version pinned in `build/checksums.txt` into `build/cache` and verifies it, so there's nothing to install.

The linker prints `loadinternal: cannot find runtime/cgo`; this is expected.

## How it works

- `toolexec.sh`: the go command refuses `-linkmode=external` without cgo, but cmd/link supports it. This wrapper adds it to the final link, with `extld.sh` as the external linker.
- `extld.sh`: compiles the files below with `zig cc` (clang) and links them statically with the Go object using `zig ld.lld` and `zisk.ld`. zig's caches go to a temporary directory unless `ZIG_GLOBAL_CACHE_DIR`/`ZIG_LOCAL_CACHE_DIR` are set, so the build doesn't write to `$HOME`.
- `zisk.ld`: the ZisK memory layout. Code and read-only data go to ROM at `0x80000000`, the initial stack at `0xa0000000`, data after the ZisK system and output areas, and the heap fills the rest of RAM up to the float library area at `0xbfff0000`.
- `crt0.S`: sets up the stack as the OpenBSD kernel would (argc, argv, `GOGC=off` in envp, auxv) and enters the Go runtime.
- `libc.c`: the libc functions referenced by the runtime, `syscall` and `os`:
  - memory: `mmap` is a bump allocator, and nothing is freed. Go heap arenas are placed 64MB-aligned, and everything else goes around them. The runtime reserves tables of up to 512MB indexed by address over a 48-bit address space. Without an MMU they can't be backed lazily, but no address above `0xc0000000` exists, so only their first few KB are ever touched. Only that part is allocated.
  - threads: cooperative, on the single hart. The runtime needs a few OS threads even with GOMAXPROCS=1. One is `sysmon`. Another is needed during package initialization, when the main goroutine is locked to the initial thread: when it blocks, the runtime hands its work to a new thread. A thread only gives up the hart when it blocks or yields, and the next one is picked round-robin, so execution is deterministic.
  - time: a virtual clock. It only advances when all threads sleep, jumping to the earliest deadline.
  - I/O: fd 1 and 2 go to the ZisK UART. There is no filesystem.
  - randomness: `arc4random_buf` is a fixed-seed generator. It is not a source of secrets.
- `switch.S`: the thread context switch.

With a single CPU, geth also skips its own goroutines on the keeper path: the receipt pipeline, the per-account storage root updates in `StateDB.IntermediateRoot` and the parallel trie hasher all run inline when `GOMAXPROCS` is 1. The runtime still creates its own goroutines (sweeper, scavenger, forced GC helper, finalizers). They are scheduled cooperatively.

## Running

The input is the RLP-encoded payload, mapped by ZisK at `0x40000008` (8-byte length, then the data). Pass it as a legacy input file, which adds the length prefix:

```bash
ziskemu -e keeper-zisk.elf --legacy-inputs payload.rlp
```

Keeper prints nothing on success. On failure it prints the reason to the UART. ZisK ignores the exit code, and keeper doesn't commit public outputs yet.

### Floating point

The Go compiler emits RISC-V F and D instructions, in the runtime as well as in regular code, and `-gcflags=all=-d=softfloat` does not work on riscv64. ZisK executes them through its float library, but only when built with the `float` feature, which is off by default. `ziskemu` doesn't expose the feature itself, so enable it through the transpiler:

```bash
cargo build --release -p ziskemu --features zisk-transpiler-riscv/float
```

The transpiler (`riscv2zisk`, built as `zisk-transpiler-riscv`) checks whether an ELF can be translated:

```bash
cargo build --release -p zisk-transpiler-riscv --features float
zisk-transpiler-riscv keeper-zisk.elf out.asm --gen=0
```

Without `float`, it stops at the first `fmv.d.x`. The release ELF contains about 2,200 instructions that need it, across 44 mnemonics. The most frequent are `fld`/`fsd` (register spills), `fcvt.d.l`, `flw`, `fmv.d.x`/`fmv.x.d`, `feq.d` and `fmul.d`/`fdiv.d`. Translation succeeding is not enough on its own: a compressed build hits the `c.fldsp` issue above, which translates fine and only halts when executed.

### Example run

`ziskemu` built with `float`, running the release build (`go run build/ci.go keeper` with Go 1.27.1) on the example Hoodi block (`1192c3_block.rlp`, `1192c3_witness.rlp`):

| Input | Result | Steps |
|---|---|---|
| valid payload | exit 0 | 139,283,791 |
| header state root replaced | `stateless self-validation root mismatch`, exit 11 | 139,290,338 |

The run uses 3 threads: the initial one, `sysmon`, and one created during initialization. There are 5 thread switches, all during runtime initialization, and only the main goroutine is left at the end. With Go 1.25, the same block takes 145,979,654 steps; it reserves 128MB for the Go heap and about 5MB for runtime metadata.
