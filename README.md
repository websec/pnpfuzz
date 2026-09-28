<p align="center">
  <img src="assets/pnpfuzz-logo.png" alt="pnpfuzz logo" width="220">
</p>

# pnpfuzz

A hardware-free USB and PCI driver-acquisition fuzzer for Windows. It sweeps a
vendor's entire ID space and asks Windows, both the local DriverStore and Windows
Update, which driver it would install for each identity, without plugging in a
single device.

Author: Joel Aviad Ossi, WebSec B.V.

Special Thanks:

- Alejandro Hernando **0xedh**
- Borja Martinez **borjmz**

You can find their awsome research here https://plugandpwn.com/

## Use and legal terms

pnpfuzz is research material. we wrote and published
it to study how the Windows Plug and Play manager and Windows Update decide which
driver to install for a given device identity, and to let defenders and
researchers test that behaviour on systems they are responsible for.

In its default mode the tool only asks Windows what it would do. It installs
nothing, downloads nothing, and runs no third-party code. It carries no exploit,
no payload, and no method for gaining access to any system it is not invited
onto. What it produces is information: which driver Windows would offer for which
identity, written to a log you can read.

Run it only against hardware, virtual machines, and Windows installations that
you own or that you have explicit written permission to test. Before you run it,
make sure your use is lawful where you are and is allowed by any contract or
policy that covers the systems in scope. That responsibility is yours alone.

The authors do not support or assist misuse and take no responsibility for it.
Pointing this tool at a machine you do not control, interfering with someone
else's system, or using it to cause harm is outside its purpose and is very
likely a crime. If you do that, the act is yours, not the authors'.

The work is derived from security research presented publicly at DEF CON 34
(2026), and it is shared in that same spirit: to document a real behaviour of
Windows so it can be understood, tested, and defended against. If your testing
uncovers something that affects other people's systems, report it to the
affected vendor through coordinated disclosure before you publish.

The software is provided as is, with no warranty of any kind. The authors are
not liable for any loss or damage arising from its use, and nothing here is
legal advice.

## Highlights

- It needs no hardware. A synthetic `ROOT\PNPFUZZ` device node makes Windows
  react as if the device were plugged in. That primitive comes from the DEF CON
  34 (2026) *Plug and Pwn* research; pnpfuzz turns the single-device trick into a
  batched, resumable sweep over the identity space.
- It covers USB and PCI/PCIe from one engine. `--bus usb` uses VID/PID and
  `--bus pci` uses VEN/DEV, and each renders the ID shapes Windows expects
  (`USB\VID_xxxx&PID_yyyy`, `PCI\VEN_xxxx&DEV_yyyy`, with REV, MI, SUBSYS and
  class-code axes).
- It runs one Windows Update search per batch. A single node advertises thousands
  of candidate IDs, and one search covers all of them. `--auto-batch` measures the
  widest batch the host answers without dropping IDs and rides it, with a canary
  that flags any silent truncation.
- It visits every combination once. A mixed-radix odometer walks the whole space
  with no gaps, and durable per-search-space checkpoints resume the run after a
  crash, a Ctrl+C, or a stalled Windows Update.
- It tells you whether a vendor is worth sweeping. Before the sweep it resolves
  the vendor ID to a company (a built-in USB-IF list of 13,756 vendors, then
  DeviceHunt), checks the Microsoft partner hardware directory, and lists that
  publisher's certified driver submissions.
- It logs everything. Events go to JSONL with raw and decoded error codes, and
  matches go to a CSV you can diff across Windows builds.

## Quick start

```bat
:: build (Visual Studio Build Tools + Windows SDK; static /MT, single exe)
build.bat

:: sweep every PID of a USB vendor, query-only, self-tuning  (Razer = 1532)
pnpfuzz --vid 1532

:: sweep every device ID of a PCI/PCIe vendor  (Intel = 8086)
pnpfuzz --bus pci --ven 8086

:: triage a vendor without sweeping: who owns the ID, do they ship WU drivers?
pnpfuzz --vid 046D --recon-only
```

Query mode is the default. It downloads and installs nothing and is safe to run
across all 65,536 PIDs. `--install` and `--install-all` run vendor code as
SYSTEM; see [Modes](#modes).

## Contents

- [What the Windows Update query actually is](#what-the-windows-update-query-actually-is)
- [Where the speed comes from](#where-the-speed-comes-from)
- [Build](#build)
- [Windows version matters more than the hardware ID](#windows-version-matters-more-than-the-hardware-id)
- [Usage](#usage): [target axes](#target-axes), [PCI / PCIe](#pci--pcie), [vendor recon](#vendor-recon), [modes](#modes), [throughput](#throughput), [scope and resume](#scope-and-resume)
- [Verifying the batch](#verifying-the-batch)
- [Output](#output)
- [Examples](#examples)
- [Suggested workflow](#suggested-workflow)
- [Known limitations](#known-limitations)

## What the Windows Update query actually is

For each candidate the tool registers a synthetic `ROOT\PNPFUZZ` device node
whose hardware ID is `USB\VID_xxxx&PID_yyyy`. That puts the ID into the machine's
PnP device inventory as a present device with no driver. The Windows Update
search it issues is `IsInstalled=0 AND Type='Driver'`, and the VID/PID is not
part of that query. What scopes the search is the injected node: the Windows
Update agent uploads the current device inventory, now carrying your ID, and the
service works out server-side which driver package it would offer for that
device. It is the same path Windows follows when you physically plug the
hardware in.

This is not a walk of the Microsoft Update Catalogue, and not a local search over
a downloaded copy of one. Windows Update only returns drivers that apply to
devices present on the machine, which is why an unassigned vendor ID comes back
empty (the property the `--verify-batch` decoys rely on). The client-side
`DriverHardwareID` filtering the tool does afterwards is attribution: it sorts
the returned set back onto individual target IDs. Run with `--dump-raw-wu` to log
the full unfiltered set per search and watch the device-scoped behaviour
yourself.

## Where the speed comes from

`SPDRP_HARDWAREID` is a `REG_MULTI_SZ`. Windows matches a device against every
entry in that list, and both the SetupAPI driver detail and the Windows Update
result name the specific ID that matched. So one synthetic node can advertise 64,
128 or 512 candidate hardware IDs at once, and a single Windows Update search
covers all of them while keeping attribution.

The Windows Update search is the slow part of the loop, a full online sync of
roughly 20 to 90 seconds, and it costs the same whether the node carries one
hardware ID or two hundred. The speed comes from spreading that fixed cost across
a whole batch.

Confirm this on your own hosts before trusting a long sweep. See
[Verifying the batch](#verifying-the-batch) below.

## Build

```
build.bat
```

Locates the toolchain itself if `cl.exe` is not on `PATH`. Needs Visual Studio
Build Tools with the C++ workload and the Windows SDK. Links statically
(`/MT`), so `pnpfuzz.exe` drops onto a bare VM with no redistributable.

`build.bat clean` removes the artifacts.

### Tests

`tests/run.sh` compiles the real `hwid.c` and the real `id_related()` against a
small shim and runs them anywhere gcc or clang does, no Windows needed. It
covers the spec parser, the mixed-radix odometer, hardware/compatible ID
synthesis, the axis dependency rules, the search-space overflow guard, and the
component-boundary ID matcher. Two properties it asserts are load-bearing for
the batching design:

- every index maps to a distinct combination and the union covers the whole
  Cartesian product exactly once, so a sweep cannot silently skip part of its
  search space;
- consecutive indices within a batch never change a slow axis, so one probe
  node per batch is always valid.

It runs clean under ASan and UBSan.

## Windows version matters more than the hardware ID

A driver package on Windows Update is published for specific OS versions and a
specific architecture. An exact VID/PID match can still return nothing if the
vendor never certified that package for the build you are testing on.

pnpfuzz prints a suitability verdict at startup and records the full OS tuple in
every run log, so a result always ties back to a specific build.

Highest-yield targets, in the order worth building VMs for:

| Build | Release | Why |
|---|---|---|
| 10.0.10240 | Windows 10 1507 x64 (TH1) | Very large legacy driver catalogue still offered, permissive matching |
| 10.0.10586 | Windows 10 1511 x64 (TH2) | Same catalogue behaviour as 1507 |
| 10.0.14393 | Windows Server 2016 x64 | LTSC line, long-tail vendor packages still published |
| 10.0.26100 | Windows 11 24H2 | Current servicing branch, largest live catalogue |
| 10.0.26200 | Windows 11 25H2 | Current servicing branch, largest live catalogue |

Two notes on the list. The first Windows 10 release is 1507, not 1506 (build
10240; 1511 is build 10586). And Windows Server 2016 RTM is build 14393
(Redstone 1) rather than a Threshold build; the Threshold-era Server 2016
releases were technical previews, and the table above recognises both.

Sweeping the same ID range across 1507 and 24H2 gives different answers, and
those differences are the result you are after. Run the same range on several
builds and diff the `hits-*.csv` files.

### Why a sweep returns zero

The preflight checks the environmental reasons before you waste hours:

- `wuauserv` and the Device Install Service not running
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching\SearchOrderConfig = 0`
  (Windows will never take a driver from Windows Update on this host)
- Policy `DontSearchWindowsUpdate`
- Policy `ExcludeWUDriversInQualityUpdate = 1`
- A configured WSUS server. This is the most common silent cause on a corporate
  image. pnpfuzz forces `ServerSelection = ssWindowsUpdate` so the *query* still
  reaches Microsoft Update, but an actual `--install` still follows machine
  policy and will go to WSUS.
- A metered network connection (Windows suppresses driver downloads)
- Device installation restriction policies
- Not running as x64 (most vendor packages are x64 only)

If any hard blocker is present, the summary says so explicitly rather than
letting you read a zero as a negative result.

## Usage

```
pnpfuzz --vid 1532
```

That is the whole command for the common case. It sweeps every PID of that
vendor (`--pid` defaults to `0000-FFFF`), calibrates its own batch width against
Windows Update, discovers its own canary from the first hit it finds, re-runs
anything that was swept before the width was proven, and resumes automatically
if interrupted. You do not pick a width, supply a reference, or run a separate
verification step.

```
pnpfuzz --vid <spec> [options]
```

A `<spec>` is always hexadecimal: comma-separated values and `A-B` ranges, or
`*` for the whole range.

```
046D        0x046D        0000-FFFF        1,2,10-1F        *
```

(Values are always hexadecimal, so `10` means `0x10` and `0x0000` is a valid
product ID.)

### Target axes

| Option | Effect |
|---|---|
| `--vid` | vendor ID (required) |
| `--pid` | product ID (defaults to `0000-FFFF`) |
| `--rev` | adds `&REV_xxxx` to the hardware ID |
| `--mi` | adds `&MI_xx` (composite interface) |
| `--class` | emits `USB\Class_xx` as a compatible ID |
| `--subclass` | `USB\Class_xx&SubClass_yy`, requires `--class` |
| `--protocol` | `USB\Class_xx&SubClass_yy&Prot_zz`, requires `--subclass` |
| `--with-plain` | also present the bare `USB\VID&PID` alongside the REV/MI form, the way a real hub reports both |

By default only `USB\VID_xxxx&PID_yyyy` is presented. Most Windows Update driver
INFs match on the non-REV form because vendors want to cover all revisions, so
the plain form is the right default and keeps the search space small. Add `--rev`
only when chasing a REV-specific INF.

### PCI / PCIe

The PnP primitive is bus-agnostic. A hardware ID is just a string the PnP manager
matches against INF models sections, so the same synthetic-node trick works on
PCI. PCI names its identifiers VEN (vendor, assigned by PCI-SIG) and DEV (device)
rather than VID/PID, but they are the same two 16-bit fields, and everything else
in the tool is unchanged.

```
pnpfuzz --bus pci --ven 10DE
```

| USB | PCI |
|---|---|
| `USB\VID_046D&PID_C52B` | `PCI\VEN_10DE&DEV_2482` |
| `&REV_xxxx` (bcdDevice, 4 hex) | `&REV_xx` (2 hex) |
| `&MI_xx` (composite interface) | `&SUBSYS_ssssssss` (subsystem pair, 32-bit) |
| `USB\Class_xx&SubClass_yy&Prot_zz` | `PCI\VEN_xxxx&CC_ccsspp`, `PCI\CC_ccsspp` |

`--ven`/`--dev` and `--vid`/`--pid` are accepted as synonyms on either bus.
`--class`/`--subclass`/`--protocol` map onto the PCI class code's class, subclass
and prog-IF bytes, which is exactly what `CC_ccsspp` encodes.

Two PCI-specific notes. `--subsys` is a 32-bit field, so its space is not
sweepable end to end. Pin a value when you need it; most third-party INFs match
the bare `VEN&DEV` form regardless. And on real hardware Windows reports
`PCI\VEN&DEV` only as a *compatible* ID, with `VEN&DEV&SUBSYS&REV` as the
hardware ID. Driver matching consults both lists, so the bare form is emitted as
a hardware ID here, which is what makes a DEV sweep match anything at all.

Query mode is as safe on PCI as on USB. Install mode is not. PCI covers storage
controllers, GPUs and chipset devices, and binding a real driver for one to a
synthetic root-enumerated node can destabilise a machine in ways a USB
peripheral driver will not. Sweep PCI in the default query mode unless you have a
disposable VM.

### Vendor recon

Before each sweep (unless `--no-recon`), three public read-only lookups answer
whether the vendor is worth sweeping and how to read a zero-hit result:

1. The built-in USB-IF list (13,756 vendors) is checked first. For USB this is
   the authoritative registry, it is instant, and it works with no network.
2. devicehunt.com resolves the vendor ID to a company name when the local list
   cannot: always for PCI (those IDs come from PCI-SIG, a different registry),
   and for USB vendors registered since the table was generated.
3. The Microsoft partner hardware directory is searched for that name. If the
   full name misses, progressively shorter prefixes are tried, because corporate
   suffixes rarely match the directory's own spelling.
4. That publisher's certified submissions are enumerated. The product search
   matches any substring, so querying each letter `a` to `z` and unioning the
   results lists the catalogue without knowing a single product name. Every
   letter is queried even after the first hit, since different letters surface
   different products.

```
pnpfuzz --bus pci --ven 416C --recon-only
```

```
Vendor recon for PCI\VID_416C
  DeviceHunt   : Aladdin Knowledge Systems
  Partner CPL  : Aladdin Knowledge Systems LTD.  (account 52944960)
  Certified    : 7 distinct submission(s) from 26 letter queries
      - Sample Device Package [25H2] [universal] [declarative]
      ...
  Outlook      : STRONG - active publisher with certified drivers, so Windows
                 Update packages for this vendor are plausible.
```

Reading the verdict:

| Result | Meaning |
|---|---|
| Resolves + publisher + certified drivers | Strong. A WU package is plausible; a zero-hit sweep is worth a second look. |
| Resolves + publisher, no certified drivers | Mixed. The publisher exists but nothing certified surfaced. |
| Resolves, no publisher | Weak. Either a dormant or legacy ID, or a silicon vendor that reserves IDs for its customers, in which case drivers ship under *their* name rather than the ID holder's. DeviceHunt may then name the silicon vendor for an ID while a partner directory lists the OEM that actually ships the hardware. |
| Nothing resolves | Unknown. DeviceHunt may simply not have indexed the ID; that is not evidence the ID is invalid. |

A vendor name often matches more than one partner account. `raytheon` returns
Raytheon Company, Raytheon Anschuetz GmbH and Raytheon Technologies, which are
separate accounts with separate driver catalogues, so the drivers you are after
may sit under any of them. The tool lists every match, marks the closest name
match, and asks which to enumerate:

```
  Partner CPL  : 3 publishers matched "Raytheon"
      1) Raytheon Company                        (30896210)  <- closest name match
      2) Raytheon Anschuetz GmbH                 (76778810)
      3) Raytheon Technologies                   (78476470)
  Enter a number, or 'a' for all [default 1]:
```

`--cpl-all` enumerates every match without asking, and `--cpl-account <id>` picks
one in advance. The prompt is not suppressed by `--yes`: that flag is consent to
install mode running vendor code as SYSTEM, and has nothing to do with which
publisher to read. Only a redirected stdin rules out asking, in which case the
tool takes the closest name match and says so rather than blocking. Results are
grouped per publisher so two companies' catalogues never blur together, and every
matched account is written to the JSONL whether it was enumerated or not, so the
log shows exactly what was considered and what was skipped.

`--recon-only` prints this and exits, a cheap way to triage a vendor before
committing to a sweep. `--no-recon` skips the lookups for offline hosts or where
third-party traffic is not acceptable. Only the first vendor of a multi-vendor
run is profiled. Requests are spaced to stay polite, so the pass takes about ten
seconds.

### Updating the vendor list

The USB-IF list is compiled into the exe rather than read at runtime, so the
binary stays self-contained (no side file to lose on a bare VM) and a lookup is a
binary search rather than a database open. `data/vendors.db` is kept as the
source of truth: a small SQLite database with a single `vendors` table of
(Company, VendorID). When USB-IF publishes a new list, update that table (or
point the generator at an equivalent `.sql` dump) and regenerate the header:

```
python3 tools/gen_vendordb.py data/vendors.db src/vendordb.h
build.bat
```

`src/vendordb.h` is generated. Do not edit it by hand.

### Sweeping several vendors in one run

Because every axis takes the same comma/range spec, `--vid` accepts a list of
vendors:

```
pnpfuzz --vid 1EF9,046D,1532 --pid 0000-FFFF --auto-batch
```

VID is the outermost axis and PID the innermost, so the sweep walks the entire
PID range of the first VID, then advances to the next VID automatically, in the
order you listed them. There is no need to launch a run per vendor. Each vendor
prints a header as it begins:

```
==== VID 1/3: USB\VID_1EF9 - sweeping its PID range ====
...
==== VID 2/3: USB\VID_046D - sweeping its PID range ====
```

A batch never straddles a VID boundary, and resume, coverage accounting and the
`hits-*.csv` table all span the whole multi-VID space as a single search, so an
interrupted multi-vendor run continues exactly where it stopped. The header is
also emitted to the JSONL as a `vid_begin` event.

### Modes

```
(default)        query only. Nothing is downloaded, nothing is installed,
                 no vendor code runs. Safe to sweep 65 536 PIDs.

--install        query first, then install only the IDs that matched, each on
                 its own single-ID node so attribution stays exact.

--install-all    fire CM_Setup_DevNode on every batch regardless of the query
                 result. The Device Install Service resolves server side and is
                 not the same code path as the COM query, so this occasionally
                 finds what the query misses. Much slower, much more invasive.
```

Install modes prompt for confirmation unless `--yes` is passed.

> What install actually does. `CM_Setup_DevNode(CM_SETUP_DEVNODE_READY)` is what
> the kernel calls after a bus driver enumerates a real PDO. It hands the node to
> the Device Install Service, which runs as `NT AUTHORITY\SYSTEM` and downloads
> and installs the matched package, co-installers and all, with no UAC prompt.
> That is the whole point of the DEF CON research, and it means removing the
> device node afterwards undoes nothing: DriverStore packages, installed files,
> services and registry changes all persist. pnpfuzz logs every `oemNN.inf` that
> appears so you know what landed, but it will not try to unwind it. Use a VM
> with a snapshot.

### Throughput

One Windows Update search per batch is the entire cost of a sweep (the search is
a 20 to 90 second online sync; everything local is sub-second). Wall time is
roughly `(total IDs / batch width) x search time`, so batch width is the dial
that matters, and `--auto-batch` finds the best value for you.

| Option | Default | Notes |
|---|---|---|
| `--batch N` | 64 | Fixed candidate hardware IDs per node (max 8192). Also sets the starting width for `--auto-batch` when there is no reference yet. |
| `--auto-batch` | off | Calibrate and ride the largest lossless batch width on this host, cached per host+build. See below. |
| `--auto-batch-max N` | 4096 | Ceiling the calibration probes to (max 8192). |
| `--ref-id <hwid>` | none | A hardware ID you know WU answers for, used as the calibration reference and canary. Optional. |
| `--wu-timeout N` | 300 | Seconds per Windows Update search |
| `--install-timeout N` | 300 | Seconds to wait for a driver to bind |
| `--settle N` | 750 | Milliseconds to let PnP settle after node creation |

#### Auto-tuning batch width (`--auto-batch`)

Threading the Windows Update search does not help. The WU agent serialises
searches internally, so running them concurrently just contends on one service
and risks wedging it. The tool keeps one WU search in flight at a time. The way
to go faster is to do fewer searches by putting more candidate IDs on each node,
which is what auto-tuning maximises, with no new threads and no new race surface.

How it works:

- Calibration. With `--ref-id`, the tool finds the largest width at which that
  reference still surfaces from WU when buried among decoys (it tests the ceiling,
  then binary-searches). The reference is placed last in the list, because if WU
  honours only the first N entries then the tail is the first casualty. A
  reference in the middle would survive whenever N is more than width/2 and report
  a ceiling about twice the truth.
- The canary. Once it has a reference, that ID rides along in every batch,
  appended last. After each search the tool checks it came back. If it ever goes
  missing, WU silently truncated the ID list, so the batch's other IDs were not
  all considered. The tool warns, halves the width, and re-runs that exact range,
  so coverage is never over-claimed.
- Per-host cache. A calibrated width is a property of the machine and its Windows
  build, not of the search space, so it is cached under `%LOCALAPPDATA%\pnpfuzz\`.
  Later sweeps on the same VM skip calibration. A canary-triggered downgrade is
  written back too, so the correction carries forward.

> A canary needs a reference, and the reference must be one Windows Update
> answers for. With neither `--ref-id` nor a cached value there is nothing to
> inject, so the run is unverified until it discovers its own WU hit. It starts
> at width 512 (override with `--batch`) and says so loudly. A small width is no
> safer here: without a reference it is not verified either, only slow. A
> DriverStore match cannot serve as the reference, because such an ID never comes
> back from a WU search, so every batch would look truncated and the width would
> collapse to 1.

Auto-tuning needs Windows Update, so it is ignored under `--no-wu`. A single
canary-guarded run is the fast path; `--verify-batch` remains available for a
one-shot manual check.

### Scope and resume

| Option | Notes |
|---|---|
| `--start N` | Begin at combination N (decimal). An explicit `--start` overrides auto-resume. |
| `--limit N` | Stop after N combinations |
| `--restart` / `--fresh` | Ignore any saved checkpoint and start this space over |
| `--resume` | Accepted but no longer needed. Resume is the default. |
| `--stop-on-first` | Stop at the first confirmed hit |
| `--no-exclude` | Also probe IDs that already exist on this host |

Resume is automatic. Progress is checkpointed to the log directory after every
batch, so if a run is interrupted by Ctrl+C, a crash, a killed process, or a
wedged Windows Update, you re-run the same command and it continues from the last
completed batch. An interrupted batch (the long part is the WU search) is redone
in full on resume, so nothing is ever skipped.

Three things make this reliable:

- Durable writes. Each checkpoint is written to a temp file, flushed to disk
  (`_commit`), then atomically renamed over the old one. A kill or power loss
  mid-write leaves either the previous checkpoint or the new one intact, never a
  torn half-written file.
- Per-search-space naming. The checkpoint file is `checkpoint-<hash>.txt`, keyed
  to the exact search space, so several different sweeps can share one log
  directory without clobbering each other's progress. Re-running a given command
  finds precisely its own checkpoint.
- Auto-batch state is preserved. A resumed auto-tuned run restores the batch
  width it had already calibrated instead of re-calibrating, and the canary keeps
  guarding every batch as before.

If the sweep had already finished, re-running says so and does nothing; use
`--restart` to run it again. The resume state lives in `--logdir`, so use the
same log directory to resume (the default `.\pnpfuzz-logs` is stable per working
directory).

By default any hardware ID already present on the machine is skipped, so a real
device on a swept VID is never touched.

### Housekeeping

| Option | Notes |
|---|---|
| `--cleanup` | Remove leftover `ROOT\PNPFUZZ\*` nodes and exit |
| `--cleanup-dry-run` | List them without removing anything |
| `--keep` | Leave probe nodes registered (debugging) |
| `--verify-batch <id>` | Prove batching is lossless on this host |
| `--dump-raw-wu` | Log every driver update WU returns per search, matched or not (proves the query is device-scoped, not a catalogue dump) |
| `--setupapi` | Save the `setupapi.dev.log` slice for each hit |
| `--watch-all` | Record PnP events for every device, not just ours |
| `--logdir PATH` | Default `.\pnpfuzz-logs` |

Cleanup is an exact prefix test on `ROOT\PNPFUZZ\`, so it cannot match a real
device. It runs automatically at the end of every sweep, including after Ctrl+C,
and covers non-present (ghost) nodes as well as live ones.

## Verifying the batch

Batching is the reason this tool is fast, and it rests on an assumption: that a
hardware ID buried among many others on one node is still reported by Windows
Update. Prove it on the host rather than assume it.

```
pnpfuzz --verify-batch "USB\VID_06CB&PID_0089" --batch 128
```

Give it a hardware ID you already know Windows Update answers for. It runs two
searches: one control with that ID alone, one with the same ID hidden among 127
decoys under the unassigned vendor ID `FFFF`. If both find it, batching is
lossless at that width on that host and you can sweep with `--batch 128`.

If the batched pass loses it, halve `--batch` and verify again. `--batch 1`
reproduces the published PoC's behaviour exactly: correct, and slow.

Do this once per Windows build you test on.

## Output

Everything lands in `--logdir` (default `.\pnpfuzz-logs`).

`run-<timestamp>.jsonl` holds one JSON object per event, flushed immediately so a
run that dies at hour nine still has its tail. Every record carries an ISO-8601
timestamp, a monotonic offset in milliseconds, a level, and the event name.
Failures always carry both the raw Win32/HRESULT/CONFIGRET code and the decoded
message.

Events: `run_start` (with the full OS tuple and policy state), `run_config`,
`autobatch_probe`, `autobatch_calibrated`, `batch_start`, `devnode_created`,
`devnode_create_failed`, `driverstore_probe`, `driverstore_match`,
`wu_search_start`, `wu_search_result`, `wu_search_timeout`, `wu_raw_update`
(with `--dump-raw-wu`), `windows_update_match`, `batch_truncated_retry`,
`install_start`, `pnp_install_queued`, `pnp_install_result`,
`driverstore_package_added`, `install_end`, `pnp_event`, `devnode_removed`,
`batch_end`, `cleanup_*`, `run_end`.

```
jq -r 'select(.event=="windows_update_match") | [.ts,.matched_target,.title] | @tsv' run-*.jsonl
jq -r 'select(.level=="error") | [.ts,.event,.error_text] | @tsv' run-*.jsonl
```

`hits-<timestamp>.csv` holds one row per match, for triage and diffing between
Windows builds. Columns: timestamp, hardware ID, source
(`driverstore` / `windowsupdate` / `installed`), match kind
(`hardware` / `compatible`), provider, description, class, version, INF, extra.

`checkpoint-<hash>.txt` holds per-search-space resume state: signature, last
completed index, and (for auto-batch runs) the calibrated width and canary
reference. Written durably after every batch. Re-run the same command to resume
from it; `--restart` ignores it.

`setupapi-*.log`, with `--setupapi`, holds the exact slice of
`%windir%\INF\setupapi.dev.log` appended during a hit, so you get the PnP
manager's own account of the match without hunting through a multi-megabyte log.

Set `PNPFUZZ_DEBUG=1` to also print debug-level events to the console. They are
always in the JSONL regardless.

## Examples

```bat
:: Full PID sweep of one vendor, query only, auto-tuned for speed
pnpfuzz --vid 046D --pid 0000-FFFF --auto-batch

:: Auto-tune from a known-good reference (fastest start, fully certified)
pnpfuzz --vid 06CB --pid * --auto-batch --ref-id "USB\VID_06CB&PID_0089"

:: Several vendors. If interrupted, the SAME line resumes automatically
pnpfuzz --vid 06CB,1199,056A --pid * --auto-batch

:: Query, then install what matched, unattended
pnpfuzz --vid 06CB --pid 0080-00A0 --install --yes

:: HID-class compatible IDs alongside the VID/PID sweep
pnpfuzz --vid 046D --pid 0000-0FFF --class 03 --subclass 01 --protocol 01

:: Prove the WU query is device-scoped, not a catalogue dump
pnpfuzz --verify-batch "USB\VID_06CB&PID_0089" --batch 128 --dump-raw-wu

:: Local DriverStore only, no network
pnpfuzz --vid 046D --pid * --no-wu

:: See what a previous run left behind
pnpfuzz --cleanup-dry-run
```

## Suggested workflow

1. Build a VM per target Windows build from the table above. Snapshot it clean.
2. Sweep query-only with `--auto-batch`: it calibrates the largest lossless
   width for that host, then rides it with a canary that catches any silent WU
   truncation. (Or `--verify-batch <known-good-id>` for a one-shot manual check.)
3. Let it run; it checkpoints continuously. If it stops for any reason, re-run
   the same command and it picks up where it left off.
4. Diff `hits-*.csv` across builds. The differences are what you came for.
5. Revert to snapshot, then re-run only the confirmed hits with `--install` to
   see what actually lands and what runs as SYSTEM.
6. Revert again. Never install on a machine you intend to keep.

## Known limitations

- The batching speedup is a design assumption about how Windows Update reports
  applicable driver updates for a multi-hardware-ID node. `--verify-batch` exists
  so you confirm it rather than trust it. It has not been validated across the
  full build matrix.
- A compatible-ID match (from `--class`/`--subclass`/`--protocol`) is attributed
  to the batch, not to an individual PID, because compatible IDs live on the node
  rather than on individual hardware IDs. Such matches are labelled `compatible`
  in the CSV. They usually mean a generic class driver matched, which is rarely
  the interesting result.
- `--install-all` installs whatever the batch resolves to, which may be any one
  of the IDs in it. Use `--install` when you need per-ID attribution.
- The Windows Update COM query and the Device Install Service's server-side
  resolve are related but not identical paths. A query miss is not proof that
  `--install-all` would also miss.
- Nothing here undoes an install. That is deliberate; a tool that half-removes
  vendor services is worse than one that clearly does not try.
