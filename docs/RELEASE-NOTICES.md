# Windows 2.0 Attribution and Toolchain Record

This historical record covers the `2.0.0-rc.1` Rust CLI candidate and the
`2.0.0` desktop release for `x86_64-pc-windows-msvc`. The counted inventories
below belong to those builds. The `2.1.0` inventory is regenerated at release.
This record documents the files retained and the explicit packaging review decisions. It does not relicense third-party code or replace the terms shipped with each dependency.

## Compiler and standard-library provenance

The local release toolchain reports Cargo 1.99.1 and rustc 1.99.1, commit `58cf8f9c35b355199727627d07ae34a4e2846d67`, LLVM 23.1.1.

The [official 1.99.1 channel manifest](https://static.rust-lang.org/dist/channel-rust-1.99.1.toml) identifies the [Windows compiler archive dated 2026-10-15](https://static.rust-lang.org/dist/2026-10-15/rustc-1.99.1-x86_64-pc-windows-msvc.tar.xz). The downloaded archive matched the manifest's SHA-256. The local `rustc.exe` then matched the compiler extracted from that archive byte for byte.

| Item | SHA-256 |
| --- | --- |
| Official compiler archive | `7da83c2af1f209606b0160f25174d2867c7c7b73667c32c9e5fbcef4f5f45348` |
| Local and official `rustc.exe` | `ba03e3ba03a73d9fef19ab3659140f94b43615ec1d587fe9befc9aed3bd5aa72` |
| Official and locally supplied `COPYRIGHT-library.html` | `5647be074c8edf7339fd863055923a8fc80bc5610a8d4661ec3b767b9d392c27` |

The standard-library document is 1,499,465 bytes. Its exact archive member is `rustc-1.99.1-x86_64-pc-windows-msvc/rustc/share/doc/rust/COPYRIGHT-library.html`.

The installed minimal sysroot omits that document, so packaging uses the existing explicit `--rust-stdlib-notice` file. The packaging index correctly labels its resolution `operator_supplied`; the independent comparison above establishes that its bytes match the official compiler archive. The packager's source-label behavior has not been changed.

## Dependency notice inventory

The locked, offline Windows CLI metadata closure for `2.0.0-rc.1` contains 192 packages, including 179 third-party packages. The corrected collector retains **343 notice files**, and the packaging verifier checked all 343 file hashes. It reports zero automatic blocking anomalies and the 12 explicit review items below.

The inventory includes the normal and build dependency closure. It is not a claim that every package contributes executable bytes to the final binary.

## Explicit review items

Each value below is passed individually as `--ack-review <value>` only after checking the corresponding indexed files. Unknown, stale or unacknowledged review values still cause refusal.

| Exact review value | Recorded review |
| --- | --- |
| `license_exception_present:ambient-authority@0.0.2` | Complete declared license and LLVM exception texts retained |
| `license_exception_present:cap-fs-ext@4.0.3` | Complete declared license and LLVM exception texts retained |
| `license_exception_present:cap-primitives@4.0.3` | Complete declared license and LLVM exception texts retained |
| `license_exception_present:cap-std@4.0.3` | Complete declared license and LLVM exception texts retained |
| `license_exception_present:fs-set-times@0.20.3` | Complete declared license and LLVM exception texts retained |
| `license_exception_present:io-extras@0.19.0` | Complete declared license and LLVM exception texts retained |
| `license_exception_present:io-lifetimes@2.0.4` | Complete declared license and LLVM exception texts retained |
| `license_exception_present:io-lifetimes@3.0.1` | Complete declared license and LLVM exception texts retained |
| `license_exception_present:winx@0.36.4` | Declared Apache-2.0 WITH LLVM-exception text retained |
| `sqlite_native_check:libsqlite3-sys@0.35.0` | Bundled SQLite and MIT binding notices distinguished and retained |
| `sqlite_native_check:rusqlite@0.37.0` | Rust wrapper remains MIT; SQLite's status does not relicense the wrapper |
| `native_links_check:ring@0.17.14` | Five root/vendored notice documents retained, including both referenced once_cell licenses |

### LLVM exceptions

The nine complete LLVM-exception documents have SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`. The relevant alternate license and copyright documents are preserved alongside them. Recording the exception does not remove or rewrite it.

### SQLite

The selected bundled amalgamation identifies SQLite 3.50.2. The effective features include `bundled` and do not include SQLCipher. The project's root [NOTICE](../NOTICE) distinguishes the SQLite engine's public-domain statement from the licenses of its Rust wrappers.

Both binding/wrapper MIT license files remain intact, with SHA-256 `c10c1f27337546471e5f7e4e97fdd398b35b9d4e126115dcd22de8d8e65abf6f`.

### ring and vendored once_cell

The `ring@0.17.14` package declares `Apache-2.0 AND ISC` and the native link name `ring_core_0_17_14_`. Its root license refers to vendored once_cell notices used by the x86_64 CPU-detection code. The previous collector omitted those nested files; this candidate adds the two known required paths without scanning arbitrary source trees or interpreting executable instructions from license text.

The five retained files are:

- `LICENSE`
- `LICENSE-BoringSSL`
- `LICENSE-other-bits`
- `src/polyfill/once_cell/LICENSE-APACHE`
- `src/polyfill/once_cell/LICENSE-MIT`

| Previously omitted file | SHA-256 |
| --- | --- |
| `src/polyfill/once_cell/LICENSE-APACHE` | `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2` |
| `src/polyfill/once_cell/LICENSE-MIT` | `6ee2ed6c77710de911761acd5fc1ad1da00f476beb1a7ef27e78c2d1858deafc` |

## Collector checks

The collector validates lexical path components before opening required nested or explicitly declared notices. It refuses symlinks, reparse points, non-regular files and an opened identity that differs from the qualified file. External license paths are excluded and remain marked external in the index. Each file is read through the verified descriptor with a 512 KiB + 1 byte limit; an oversized file remains a blocking anomaly. The recorded SHA-256 covers the bytes actually copied.

Regression evidence:

- Initial collection failed to include the two referenced once_cell licenses; the positive fixture passed after correction.
- A declared `license_file` through a symlink/junction was initially accepted; the lexical-path correction rejects it.
- Windows: 8 tests passed, with 3 symbolic-link fixtures skipped because the account lacks that creation privilege. Both real Windows junction fixtures ran.
- Linux: 10 tests passed; only the Windows-specific junction fixture was skipped.
- The real dependency closure and all 343 collected hashes were checked again after the final correction.

The source archive includes the collector and its regression tests. CI runs both the comment-ratchet tests and the notice-collection tests. Binary archives remain unsigned candidates until the separate release/signing gates in [RELEASE-v2.0.0.md](RELEASE-v2.0.0.md) are satisfied.


## Windows desktop dependency notices

The `2.0.0` desktop workspace was resolved with locked, offline Cargo metadata
for `x86_64-pc-windows-msvc`. Its reviewed inventory contains 366 packages and
685 notice records. The inventory is a normal/build dependency closure, not a
claim that every dependency contributes bytes to the executable.

Six exact crates omit their required license files from their registry archives:
`alloc-stdlib@0.3.0`, `selectors@0.38.0`, `tauri-plugin@2.7.4`,
`webview2-com@0.39.1`, `webview2-com-macros@0.8.1`, and
`webview2-com-sys@0.39.1`. The original legal notices and their provenance are
retained in [licenses/rust-fallbacks](../licenses/rust-fallbacks/).
The collector checks the reviewed manifest digest, exact registry package,
locked crate checksum, upstream revision and each notice digest before copying.
A different package version cannot inherit an acknowledgment or license pin.
Missing or altered notices remain a packaging failure; Cargo's cache is unchanged.

The WebView2 loader is a separate Microsoft SDK component, not covered by the
Rust bindings' MIT license. The SDK package `Microsoft.Web.WebView2 1.0.3800.47`
has SHA-256
`56c9f26bdd07916a2d1949fb58a5c7e434dfa1173577dca879206050c4e718db`.
All nine loader files for x86, x64 and arm64 in the cached bindings crate
match the corresponding SDK package members. The SDK's original LICENSE.txt
and NOTICE.txt, including third-party attribution and source-availability
information, accompany the Rust binding license. The collector checks the
nine file digests and emits a separate native-link review item.

The MPL-2.0 source-availability notices identify the exact unchanged registry
archives and Cargo.lock SHA-256 for each of the five MPL packages in this
closure: cssparser 0.37.0, cssparser-macros 0.7.1, dtoa-short 0.3.5,
option-ext 0.2.0 and selectors 0.38.0. A companion source archive also retains
the five original crate archives, the official MPL license and a checksum
inventory. Verify the companion against Cargo.lock and distribute it alongside
the binary release. Agent Bridge's own Apache-2.0 license does not replace
these terms.

### Explicit desktop review items

The nine LLVM exception texts match the previously reviewed hash
`268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`.
The two SQLite entries and ring retain the previously reviewed exact versions
and notices; SQLCipher is not selected. The four Tauri native-link declarations
are associated with build metadata and the retained Apache/MIT notices;
the corresponding crates contain no prebuilt executable or library members.
The WebView2 binding additionally requires the verified SDK notices described above.

The packager must acknowledge only the exact reviewed keys emitted by the
collector. The reviewed Windows desktop inventory has 17 such keys:
the twelve original CLI review keys, the four Tauri and plugin native-link
keys (`tauri@2.12.7`, `tauri-plugin-dialog@2.8.4`,
`tauri-plugin-fs@2.7.1`, `tauri-plugin-opener@2.7.3`), and
`native_links_check:webview2-com-sys@0.39.1`. This is a scoped dependency
notice review, not installer or application qualification.

The source archive includes the reviewed license pins and all sealed native
build inputs, including the additional WinApp patches, fixtures, build package
pins and provenance. The application build must still verify the exact resource
manifests, compiler identity, archive checksums, signatures and runtime behavior.
