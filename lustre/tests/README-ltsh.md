# Lustre Test Shell Files

Subtests can live in their own files instead of in the large suite
script.  This keeps suites readable and reduces merge conflicts.

## Layout

    lustre/tests/sanity.sh                  the suite
    lustre/tests/sanity.d/test_27I.ltsh     subtest 27I
    lustre/tests/sanity.d/test_230i.ltsh    subtests 230i and 230j
    lustre/tests/conf-sanity.d/test_151.ltsh  subtests 151a and 151b

- Add subtest fragment files in `$TESTSUITE.d/`, they do not need to be
  added to `Makefile.am`.
- Name a file after its first subtest (`test_230i.ltsh` holds 230i
  and 230j, while 230a-230h stay in the suite), or `test_NNN.ltsh` if
  it holds all of a small NNN group (151a, 151b).
- A file holds one or more `test_NNN()` functions, plus helpers only
  they use.  Group only a handful of strongly-related subtests in one
  file, e.g. ones that use the same helper functions or were added by
  one patch.  Split large groups like sanity.sh test_27* or test_56*
  over several files: every subtest in a changed file is run again by
  the subtest-change test sessions.
- File subtests can use helpers that stay in the suite script.
- Do not call `run_test`.  The framework does it.
- No `#!` line and no SPDX line.  `prepare-commit-msg` runs shellcheck
  with `--shell=bash`.
- The suite script needs no changes.

## Run order

- Subtests run in number order, then by suffix: 27 < 27a < 27aa < 27b
  < 27z < 27A < 28.
- File subtests run between the suite's own subtests.  27I runs after
  27H and before 27J.
- File subtests sorting after the last subtest of the suite run before
  the suite's cleanup.
- If the suite runs subtests out of this order (e.g. 43A before 43a),
  moving only some of them changes their order.  Move those together,
  or check that the new order works.
- `ONLY`, `EXCEPT`, `START_AT`, `STOP_AT`, `always_except` and
  `EXCEPT_SLOW` work the same for file subtests.

## Writing the file

- The file is sourced in the suite's shell just before its first
  subtest runs.
- Keep top-level code to function definitions.
- Use `local` in functions as usual.  Top-level code runs inside a
  function, so top-level `local` or `declare` variables are gone after
  the file is sourced.  Use `declare -g` for globals the subtests
  need.  A plain assignment sets a local of the same name in a calling
  function instead, such as `repeat` or `rc` in `run_one_logged()`.
- Name helpers so they do not clash with other files or the suite.  A
  helper that replaces an existing function is logged.
- Every `test_*()` in the file is a subtest.  Helpers must not be named
  `test_*`; rename them when moving, e.g. `test_51d_sub()` to
  `sub_test_51d()`, which `grep test_51d` still finds.  In a file with
  `subtests:`, a `test_NNN()` not listed there fails.

## Header

The first comment block holds YAML between `---` and `...`.

For a file with one subtest, put the keys at the top level:

    # ---
    # summary: check that root dir striping does not break parent dir one
    # commit:
    #   - 'd8b08f467de9 ("LU-12055 lod: ignore root layout if parent''s one includes pool")'
    # keywords: [lod, pool]
    # requires:
    #   ostcount: 2
    #   mds1_version: v2_12_52-112-gd8b08f467de9
    #   reason: root layout ignored if parent has a pool
    # ...

    test_27I() {
    ...

For several subtests, list them under `subtests:`.  Keys outside
`subtests:` are defaults for every subtest in the file.  Keys under a
subtest override them.

    # ---
    # keywords: [lmv, dne]
    # requires:
    #   mdtcount: 2
    # subtests:
    #   33h:
    #     summary: temp file is located on the same MDT as target (crush)
    #     jira: LU-11025
    #   33hh:
    #     summary: temp file is located on the same MDT as target (crush2)
    #     jira: LU-15720
    #     requires:
    #       mds1_version: v2_15_50-185-g1ac4b9598ad6
    #       reason: crush2 hash type
    # ...

Under `subtests:`, subtests with only a summary take one line each:

    # subtests:
    #   0a: touch; rm
    #   0b: chmod 0755 the mount point

Supported YAML: block mappings, `- item` or `[a, b]` lists, plain or
quoted values, `|` and `>` text blocks, `#` comments.  Quote values
that start with one of `` <>[{`*&!%@| `` or a quote, or contain `: ` or
` #`.  In single quotes, write a `'` as `''`.  Headers are valid YAML,
so other tools can read them with a YAML library.

## Fields

| Field | Meaning |
|---|---|
| `summary` | Short description for `run_test`.  Required.  No `` ` `` or `$`: it is passed through `bash -c` on each node by `banner()`. |
| `jira` | Ticket or URL, added to the banner after the summary.  Default: the ticket of the first `commit:` entry, so it is needed only for a new subtest, whose own commit is not known yet, or a different ticket. |
| `commit` | List of the commits that added or substantially changed the subtest, since moving it to a file loses its `git log` history.  Each is in `Fixes:` format, `<12-char hash> ("<summary>")` with any double quotes in the summary changed to single quotes, in single quotes since the summary has a `: `, e.g. `- '1ac4b9598ad6 ("LU-15720 dne: add crush2 hash type")'`. |
| `description` | Longer text for someone reading the file, e.g. after a failure.  Not printed. |
| `keywords` | Free-form list of what the subtest exercises: modules, as in commit summaries (e.g. `lmv`, `osd-ldiskfs`), and features or areas (e.g. `dne`, `pool`, `recovery`, `dio`, `aio`, `migrate`, `llapi`, `many_files`, `mballoc`).  For finding subtests to run for a change.  The keywords of the whole file are added to those of each subtest, so subtests that share few keywords belong in different files. |
| `duration` | Typical run time in seconds, e.g. the mean in CI.  Not used yet; for timeouts and finding slow-downs later. |
| `requires` | Skip the subtest unless all of these hold (below). |
| `start` | Filesystem state needed at the start (below).  Default: `mounted`. |
| `end` | Filesystem state the subtest leaves (below).  Default: same as `start:`. |
| `expect` | `pass` (default), `must_fail` or `should_fail`: run with `run_test_must_fail()` or `run_test_should_fail()`, for a subtest added before its fix.  A header, setup or `fsck` error is also an expected failure. |
| `slow` | `true` to skip with `SLOW=no`. |
| `always_except` | `LU-NNNNN`: known failure, always skipped. |
| `fsck` | `each` or `last`: stop the filesystem and check the ldiskfs MDTs and OSTs with `run_e2fsck -n` after each subtest, or after the last subtest of the file, if that subtest passed.  Any problem found fails the subtest.  Not after `end: formatted`.  Leaves `stopped`. |
| `modifies` | List of shared state the subtest changes (below).  `[]` if none. |
| `observes` | List of shared state the subtest reads, and so fails if another subtest changes it at the same time (below).  `[]` if none. |

### requires

| Field | Meaning |
|---|---|
| `mdtcount`, `ostcount`, `clientcount` | At least this many MDTs, OSTs, client nodes.  `mdtcount` is checked against `MDSCOUNT`, which counts MDTs. |
| `mdsnodes`, `ossnodes` | At least this many distinct MDS or OSS hosts, e.g. for failover or to stop one server. |
| `mds1_version`, `ost1_version`, `mgs_version`, `client_version` | `[OP] VERSION`.  OP is `<`, `<=`, `==`, `!=`, `>=` (default), `>`.  Quote it if OP is given. |
| `fstype` | Allowed OSD types for mds1 and ost1, e.g. `[ldiskfs, zfs]`. |
| `mds1_fstype`, `ost1_fstype` | The same for one facet. |
| `mgs` | `separate` or `combined`. |
| `tools` | Commands that must be installed (`skip_env`). |
| `free_space`, `free_inodes` | Free KiB or inodes in the filesystem.  K/M/G/T suffix allowed. |
| `mdt_free_space`, `mdt_free_inodes`, `ost_free_space`, `ost_free_inodes` | The same for the least free MDT or OST. |
| `reason` | Why: added to the skip message, e.g. `crush2 hash type`. |

- For versions, use `git describe --match 'v[0-9]*' --exclude '*_0'
  --abbrev=12` of the commit that added the feature, e.g.
  `v2_15_50-185-g1ac4b9598ad6`.  The skip message shows it as
  `2.15.50.185`.  Without `--exclude`, older commits get the `_0` form
  of the tag, e.g. `v2_11_55_0-8-g169738e30a7e`.
- For a new patch, use its own dotted version, as in the suite scripts.
- Prefer a version check to a check for the feature.  A feature that
  disappears by mistake in a later release then fails the subtest
  instead of skipping it.  If a feature is removed on purpose, skip the
  subtest for the old versions in `except/` (see Exceptions).  Checks
  that are not about versions or the configuration stay in `test_NNN()`.
- Counts, versions and types use `skip`, not `skip_env`: they depend on
  the test configuration, and with `FAIL_ON_SKIP_ENV` set, `skip_env`
  would fail every subtest that a configuration cannot run, such as
  zfs-only subtests on ldiskfs.  `tools` uses `skip_env`.  Space and
  inodes are checked when the subtest starts, with the filesystem
  mounted.
- Without a count, a subtest needs one MDT, OST, client and server
  node of each kind.

### modifies and observes

These lists say whether a subtest can run at the same time as others.
List what the subtest itself does, including in its helpers; not the
files it makes in its own `$tdir`.

| `modifies` | The subtest changes |
|---|---|
| `fail_loc` | `fail_loc` or `fail_val` on any node |
| `tunables` | a `set_param` or module parameter on any node |
| `config` | the MGS configuration: `conf_param`, `set_param -P`, config llogs |
| `mount` | mounts or unmounts a client or target |
| `format` | reformats targets |
| `pools` | OST pools |
| `layout` | the default layout of `$MOUNT` or another shared directory |
| `quota` | quota limits or enforcement |
| `changelog` | changelog users or records cleared |
| `hsm` | the HSM coordinator or copytools |
| `nodemap` | nodemaps |
| `lnet` | LNet networks, routes or peers |
| `debug` | the debug mask or debug buffer size |

| `observes` | The subtest fails if another subtest changes |
|---|---|
| `stats` | `*stats` counters |
| `grant` | client grant or dirty limits |
| `free_space`, `free_inodes` | free space or inodes of a target |
| `changelog` | the changelog records |
| `debug_log` | messages in the debug log |
| `console` | messages on the console or in dmesg |
| `locks` | DLM lock counts or LRU size |

- A list left out means not known.  `[]` means none.
- `start:` or `end:` other than `mounted` add `mount`, and `formatted`
  adds `format`.
- With `PARALLEL=yes`, a subtest runs only if both lists are given and
  empty.
- A name not in these tables fails the subtest.  Add new names to them
  and to `LTSH_MODIFIES` or `LTSH_OBSERVES` in `ltsh.sh`.

## Filesystem state: start and end

`start:` and `end:` take one of:

| State | Meaning |
|---|---|
| `mounted` | Servers and client up. |
| `unmounted` | Servers up, client unmounted. |
| `stopped` | Servers and client down. |
| `formatted` | Freshly reformatted, servers and client down. |

- `start:` brings the filesystem into that state before the subtest, only
  doing what is needed.  The default is `mounted`.
- `end:` is the state the subtest leaves.  The default is the `start:`
  state, or `stopped` after `start: formatted`.
- `end:` is trusted, not checked, so the next subtest does no extra
  work.  A wrong `end:` makes the next subtest fail.  After a subtest
  that fails, or one in the suite script, the state is unknown and only
  the local client mount is checked.
- Most subtests need neither key.  Subtests that remount or reformat,
  like most of conf-sanity, must declare them when moved to a file.
- `start: formatted` reformats before the subtest, unless the previous
  subtest ended `formatted`.  To run on a fresh filesystem that is
  mounted, mount it in `test_NNN()`.
- `end: formatted` reformats after the subtest, also when it fails.  Use
  it instead of a reformat at the end of `test_NNN()`.  It is run with
  `stack_trap`, so subtests must use `stack_trap`, not `trap`, for EXIT
  handlers.
- Setup runs inside the subtest.  If it fails, only that subtest fails.
- Before a subtest of the suite script, the client is mounted again if a
  file subtest left the filesystem `unmounted`, `stopped` or
  `formatted`, or failed.  After a file subtest that reformatted with
  the default `formatall`, the setup that `check_and_setup_lustre()` did
  at the start of the suite is redone, such as the root layout from
  `*_STRIPEPARAMS` and the `FS_POOL` pools.
- Declare `start:` and `end:` accurately, if not `mounted`.  This lets the
  framework skip needless reformats and remounts, and later reorder
  subtests to avoid them.
- A suite can set its own functions.  `conf-sanity-framework.sh` does:

      LTSH_FORMAT=reformat_and_config    # default formatall
      LTSH_SETUP=setup                   # to mounted, default setupall
      LTSH_SERVERS=start_servers         # to unmounted, default
                                         #   setupall server_only
      LTSH_CLEANUP=stop_servers          # to stopped, keeping a separate
                                         #   MGS, default stopall
      LTSH_RESTORE_MOUNT=false           # do not remount after
      # also LTSH_MOUNT and LTSH_UMOUNT (clients only, default
      # zconf_mount_clients/zconf_umount_clients $CLIENTS $MOUNT)

## Exceptions

- `slow:` and `always_except:` apply in every configuration.  Keep
  exceptions for some configurations only (e.g. zfs) in the suite
  script.  They apply to file subtests by `NNN` or `NNNx` name, as
  for subtests in the suite.
- A server change that breaks a subtest for older clients still goes in
  `except/$TESTSUITE.ex` or `except/$TESTSUITE.NNN.ex` (see
  `except/README`): older clients read it from the servers and never
  see this header.

## Errors

Header errors do not stop the suite:

- A bad key or value fails that subtest.
- A YAML error fails every subtest in the file.
- A `test_NNN()` missing from `subtests:`, or a listed subtest with no
  function, fails as its own subtest.
- Several `test_NNN()` without `subtests:` fail.
- A helper named `test_*` fails every subtest in the file.
- The same subtest in two files, or in a file and the suite, fails.

## Code and testing

- The framework is `ltsh.sh`, sourced by `test-framework.sh`.  The
  header parser is `ltsh.awk`.
- `LTSH_DIR=/some/dir` uses another directory instead of `$TESTSUITE.d`.
- `sanity-ltsh.sh` tests the framework with the files in
  `sanity-ltsh.d/`.  Run it after changing `ltsh.sh` or `ltsh.awk`.  It
  is not in any test group.
