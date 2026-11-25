#!/usr/bin/env python3
"""Build the pinned WinApp 0.5.0 Agent Bridge derivative using offline inputs.

The stable profile applies the three reviewed capture, post-message and UIA focus
patches (0.5.0-agentbridge.2). The experimental exact-passive profile also applies
the exact-passive window patch (0.5.0-agentbridge.3); it is not release-qualified.
Contract harnesses compile the real upstream services before and after each fix.
Native debug symbols are disabled so no PDB reference to the private build
directory is linked into the distributed executable.
No installed toolchain, NuGet cache, application, or runtime is modified.
"""
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
import argparse, base64, hashlib, json, os, re, shutil, stat, subprocess, zipfile
from xml.sax.saxutils import escape

COMMIT = "fd7cb6f235fa54dd2c6e26386e65e967a2c8797a"
ARCHIVE_SHA256 = "4c044ab048551fabb774b8962ad8a94c7cfe5dfa4c30eeecf350fa5740e6c1ff"
SDK = "10.0.402"
RUNTIME = "10.0.13"
PROFILES = {
    "stable": {"version": "0.5.0-agentbridge.2", "exact_passive": False},
    "exact-passive": {"version": "0.5.0-agentbridge.3", "exact_passive": True},
}
STABLE_PATCHES = ("0001-passive-screenshot.patch", "0002-background-post-message.patch", "0003-background-uia-autofocus.patch")
EXACT_PASSIVE_PATCH = "0004-exact-passive-window.patch"
# NativeAOT links with /DEBUG by default, embedding the absolute PDB path of the
# private work directory. Disabling native symbols removes /DEBUG only; Release
# keeps explicit /OPT:REF and /OPT:ICF, so code generation is unchanged.
PRIVACY_FLAGS = ("-p:NativeDebugSymbols=false",)
SKIA_SHA256 = "9a0d95e8caaa852c70d085af6a40a744242172ad9ea3fd6bc7599875a8a1dbcd"
TARGET = "src/winapp-CLI/WinApp.Cli/Services/UiAutomationService.Screenshot.cs"
MESSAGE_TARGET = "src/winapp-CLI/WinApp.Cli/Commands/UiSendKeysCommand.cs"
MESSAGE_SOURCES = (MESSAGE_TARGET, "src/winapp-CLI/WinApp.Cli/Services/UiAutomationService.cs", "src/winapp-CLI/WinApp.Cli/Services/IUiAutomationService.cs")
AUTOFOCUS_SOURCES = tuple("src/winapp-CLI/WinApp.Cli/" + path for path in (
    "NativeMethods.txt", "Commands/SharedUiOptions.cs", "Commands/UiInvokeCommand.cs", "Commands/UiSetValueCommand.cs",
    "Commands/UiScrollCommand.cs", "Services/UiAutomationService.cs", "Services/IUiAutomationService.cs"))
EXACT_PASSIVE_SOURCES = ("src/winapp-CLI/WinApp.Cli/Commands/UiScreenshotCommand.cs", TARGET)
PACK_PINS = {
    "microsoft.dotnet.ilcompiler.10.0.13.nupkg": "0d1a1d76813e3d99e880b379cc7f49259bb01c9cd8eacdcb209a12243e7c7a2c",
    "runtime.win-x64.microsoft.dotnet.ilcompiler.10.0.13.nupkg": "f17052c61a0959ca4416bbc510bb2ee7369770257ec93412ff97a1dcb446b7ad",
    "microsoft.netcore.app.runtime.win-x64.10.0.13.nupkg": "c66885d464697be75676b4d1fbca38b8806f3af01d65d27205b3f06add094444",
}

def digest(path, algorithm="sha256"):
    with path.open("rb") as source: return hashlib.file_digest(source, algorithm).digest()

def file_record(path):
    return {"sha256": digest(path).hex(), "size": path.stat().st_size}

def plain(path):
    if not path.is_file() or path.is_symlink() or getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400:
        raise ValueError("expected a regular non-reparse input: " + str(path))
    return path

def safe_argument(value):
    value = str(value)
    if any(character in value for character in '\r\n"%&|<>!^'):
        raise ValueError("unsupported metacharacter in build path or argument")
    return value

def extract_source(archive, destination):
    prefix = "winappCli-" + COMMIT
    with zipfile.ZipFile(archive) as source:
        total = 0
        for entry in source.infolist():
            path = PurePosixPath(entry.filename)
            if not path.parts or path.parts[0] != prefix or path.is_absolute() or any(part in ("..", ".") or ":" in part for part in path.parts):
                raise ValueError("unsafe source archive member")
            if stat.S_ISLNK(entry.external_attr >> 16): raise ValueError("source archive symlink")
            total += entry.file_size
            if total > 256 * 1024 * 1024: raise ValueError("source archive exceeds extraction bound")
            target = destination.joinpath(*path.parts[1:])
            if entry.is_dir(): target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output, source.open(entry) as input_file: shutil.copyfileobj(input_file, output)

def apply_patch(source, patch, target=TARGET):
    lines = patch.read_text(encoding="utf-8").splitlines(keepends=True)
    apply_lines(source, lines, target)

def apply_patch_set(source, patch, targets=MESSAGE_SOURCES):
    lines = patch.read_text(encoding="utf-8").splitlines(keepends=True)
    starts = [index for index,line in enumerate(lines) if line.startswith("--- a/")]
    if len(starts) != len(targets): raise ValueError("unexpected reviewed patch file count")
    starts.append(len(lines)); changes = {}
    for index, target in enumerate(targets):
        file = source / target
        before = file_record(file)
        apply_lines(file, lines[starts[index]:starts[index+1]], target)
        changes[target] = {"before":before, "after":file_record(file)}
    return changes

def apply_lines(source, lines, target):
    if target not in (TARGET, *MESSAGE_SOURCES, *AUTOFOCUS_SOURCES, *EXACT_PASSIVE_SOURCES) or lines[:2] != ["--- a/" + target + "\n", "+++ b/" + target + "\n"]:
        raise ValueError("only the reviewed upstream source paths may be patched")
    original = source.read_text(encoding="utf-8").splitlines(keepends=True)
    output, cursor, index = [], 0, 2
    while index < len(lines):
        match = re.fullmatch(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@\n", lines[index])
        if not match: raise ValueError("unexpected patch hunk")
        start, old_count, _, new_count = map(int, match.groups())
        if start - 1 < cursor: raise ValueError("overlapping patch")
        output.extend(original[cursor:start-1]); cursor = start - 1; index += 1
        old_seen = new_seen = 0
        while index < len(lines) and not lines[index].startswith("@@"):
            mark, text = lines[index][0], lines[index][1:]
            if mark in (" ", "-"):
                if cursor >= len(original) or original[cursor] != text: raise ValueError("patch context mismatch")
                cursor += 1; old_seen += 1
            if mark in (" ", "+"): output.append(text); new_seen += 1
            if mark not in (" ", "-", "+"): raise ValueError("invalid patch marker")
            index += 1
        if (old_seen, new_seen) != (old_count, new_count): raise ValueError("patch count mismatch")
    output.extend(original[cursor:])
    source.write_text("".join(output), encoding="utf-8", newline="\n")

def contract_project_xml(project):
    return (
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>'
        '<TargetFramework>net10.0-windows10.0.19041.0</TargetFramework><AssemblyName>WinApp.Cli.Tests</AssemblyName>'
        '<ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable><UseWindowsForms>true</UseWindowsForms><UseWPF>true</UseWPF><ValidateExecutableReferencesMatchSelfContained>false</ValidateExecutableReferencesMatchSelfContained>'
        '</PropertyGroup><ItemGroup><ProjectReference Include="' + escape(str(project.absolute()), {'"':'&quot;'}) + '"/></ItemGroup></Project>'
    )

def prepare_contract_projects(work, root, project):
    contract = work / "contract"; contract.mkdir()
    shutil.copyfile(plain(root / "native/winapp-patches/tests/PassiveCaptureContract.cs"), contract / "Program.cs")
    shutil.copyfile(plain(root / "native/winapp-patches/tests/BackgroundMessageContract.cs"), contract / "BackgroundMessageContract.cs")
    shutil.copyfile(plain(root / "native/winapp-patches/tests/BackgroundUiaContract.cs"), contract / "BackgroundUiaContract.cs")
    contract_project = contract / "PassiveCaptureContract.csproj"
    contract_project.write_text(contract_project_xml(project), encoding="utf-8")
    exact_contract = work / "exact-passive-contract"; exact_contract.mkdir()
    shutil.copyfile(plain(root / "native/winapp-patches/tests/ExactPassiveContract.cs"), exact_contract / "ExactPassiveContract.cs")
    exact_project = exact_contract / "ExactPassiveContract.csproj"
    exact_project.write_text(contract_project_xml(project), encoding="utf-8")
    return {"main": contract_project, "exact_passive": exact_project}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-archive", "dotnet", "vcvars", "work", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--cache", type=Path, action="append", required=True)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="stable")
    args = parser.parse_args()
    profile = PROFILES[args.profile]
    derivative_version, exact_passive = profile["version"], profile["exact_passive"]
    if os.name != "nt": raise ValueError("the qualified build requires Windows x64")
    for item in (args.source_archive, args.dotnet, args.vcvars): plain(item)
    for item in (args.dotnet, args.vcvars, args.work, args.output): safe_argument(item.absolute())
    if digest(args.source_archive).hex() != ARCHIVE_SHA256: raise ValueError("upstream source archive pin mismatch")
    if args.work.exists() or args.output.exists(): raise ValueError("work and output must be new directories")
    args.work.mkdir(parents=True)
    root = Path(__file__).resolve().parents[2]
    inputs = args.work / "inputs"; inputs.mkdir()
    patch_names = STABLE_PATCHES + ((EXACT_PASSIVE_PATCH,) if exact_passive else ())
    for name in patch_names:
        shutil.copyfile(plain(root / "native/winapp-patches" / name), inputs / name)
    patch = inputs / "0001-passive-screenshot.patch"
    message_patch = inputs / "0002-background-post-message.patch"
    autofocus_patch = inputs / "0003-background-uia-autofocus.patch"
    exact_passive_patch = inputs / EXACT_PASSIVE_PATCH
    script_record = file_record(Path(__file__))
    pin_source = plain(root / "native/winapp-patches/build-package-pins.json")
    shutil.copyfile(pin_source, inputs / pin_source.name)
    pinned_inputs = json.loads((inputs / pin_source.name).read_text())
    if (pinned_inputs.get("schema"), pinned_inputs.get("upstream_commit"), pinned_inputs.get("sdk_version"), pinned_inputs.get("runtime_version")) != (1, COMMIT, SDK, RUNTIME):
        raise ValueError("build dependency inventory does not match this source/toolchain")
    input_packages = pinned_inputs["files"]
    source = args.work / "source"; extract_source(args.source_archive, source)
    env = os.environ.copy()
    env.update(DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1",
        DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE="true", NUGET_CERT_REVOCATION_MODE="offline",
        MSBUILDDISABLENODEREUSE="1", NUGET_PACKAGES=str(args.work / "packages"),
        DOTNET_CLI_HOME=str(args.work / "dotnet-cli"))
    steps = []
    def run(name, command, cwd=source, expected=0):
        command = [str(item) for item in command]
        log = args.work / (name + ".log")
        started = datetime.now(timezone.utc).isoformat()
        with log.open("x", encoding="utf-8") as output:
            process = subprocess.run(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW)
        step = {"name": name, "exit_code": process.returncode, "started_utc": started,
            "finished_utc": datetime.now(timezone.utc).isoformat(), "log": file_record(log)}
        steps.append(step)
        (args.work / "steps.json").write_text(json.dumps(steps, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"step": name, "exit_code": process.returncode, "log": str(log)}), flush=True)
        if process.returncode != expected: raise RuntimeError("build step failed: " + name)
        return log.read_text(encoding="utf-8-sig")
    if run("sdk-version", [args.dotnet, "--version"]).strip() != SDK: raise ValueError("SDK version mismatch")
    # Restore exclusively from verified archive copies; no global-cache extracted
    # files or online feeds are used by the isolated build.
    feed = args.work / "feed"; feed.mkdir()
    packages = {}
    for cache in args.cache:
        for archive in sorted(cache.glob("*/*/*.nupkg")):
            name = archive.name.lower()
            if name not in input_packages: continue
            plain(archive)
            pin = plain(Path(str(archive) + ".sha512"))
            sha512 = base64.b64encode(digest(archive, "sha512")).decode()
            if pin.read_text().strip() != sha512: raise ValueError("cached nupkg SHA512 mismatch: " + archive.name)
            record = {**file_record(archive), "sha512": sha512}
            if record != input_packages[name]: raise ValueError("build input package pin mismatch: " + name)
            if name in packages:
                if packages[name] != record: raise ValueError("ambiguous cached package: " + name)
                continue
            packages[name] = record
            shutil.copyfile(archive, feed / name)
    if packages.keys() != input_packages.keys(): raise ValueError("a pinned build dependency is absent from the selected caches")
    for name, sha in PACK_PINS.items():
        if packages.get(name, {}).get("sha256") != sha: raise ValueError("qualified AOT/runtime pack unavailable: " + name)
    config = args.work / "NuGet.Config"
    config.write_text('<configuration><packageSources><clear/><add key="offline" value="' + escape(str(feed.absolute()), {'"':'&quot;'}) +
        '"/></packageSources><fallbackPackageFolders><clear/></fallbackPackageFolders><packageSourceMapping><clear/></packageSourceMapping></configuration>', encoding="utf-8")
    project = source / "src/winapp-CLI/WinApp.Cli/WinApp.Cli.csproj"
    projects = prepare_contract_projects(args.work, root, project)
    contract_project, exact_project = projects["main"], projects["exact_passive"]
    contract, exact_contract = contract_project.parent, exact_project.parent
    common = ["-c", "Release", "--nologo", "--disable-build-servers", "-p:UseSharedCompilation=false", "-p:NuGetAudit=false", "-p:PlatformTarget=x64"]
    test_flags = common + ["-p:PublishAot=false", "-p:SelfContained=false", "-p:UseAppHost=false",
        "-p:RestoreConfigFile=" + str(config), "-o", str(args.work / "contract-run")]
    exact_flags = common + ["-p:PublishAot=false", "-p:SelfContained=false", "-p:UseAppHost=false",
        "-p:RestoreConfigFile=" + str(config), "-o", str(args.work / "exact-passive-run")]
    run("contract-build-red", [args.dotnet, "build", contract_project, *test_flags])
    harness_dll = args.work / "contract-run/WinApp.Cli.Tests.dll"
    exact_dll = args.work / "exact-passive-run/WinApp.Cli.Tests.dll"
    red = run("contract-red", [args.dotnet, harness_dll], expected=1)
    if "RESULT failures=3" not in red: raise ValueError("expected exactly the three passive-capture regressions")
    before = file_record(source / TARGET)
    apply_patch(source / TARGET, patch)
    after = file_record(source / TARGET)
    run("contract-build-green", [args.dotnet, "build", contract_project, *test_flags])
    run("contract-green", [args.dotnet, harness_dll])
    background_red = run("background-red", [args.dotnet, harness_dll, "--background"], expected=1)
    if "RESULT failures=1" not in background_red: raise ValueError("expected the missing no-focus background transport")
    message_changes = apply_patch_set(source, message_patch)
    run("background-build-green", [args.dotnet, "build", contract_project, *test_flags])
    run("background-green", [args.dotnet, harness_dll, "--background"])
    autofocus_red = run("autofocus-red", [args.dotnet, harness_dll, "--uia-background"], expected=1)
    if "RESULT failures=3" not in autofocus_red: raise ValueError("expected three unavailable no-focus semantic commands")
    autofocus_changes = apply_patch_set(source, autofocus_patch, AUTOFOCUS_SOURCES)
    run("autofocus-build-green", [args.dotnet, "build", contract_project, *test_flags])
    run("autofocus-green", [args.dotnet, harness_dll, "--uia-background"])
    exact_passive_changes = {}
    if exact_passive:
        run("exact-passive-build-red", [args.dotnet, "build", exact_project, *exact_flags])
        exact_passive_red = run("exact-passive-red", [args.dotnet, exact_dll], expected=1)
        if "RESULT failures=2" not in exact_passive_red: raise ValueError("expected two unavailable exact-passive checks")
        exact_passive_changes = apply_patch_set(source, exact_passive_patch, EXACT_PASSIVE_SOURCES)
        run("exact-passive-build-green", [args.dotnet, "build", exact_project, *exact_flags])
        run("exact-passive-green", [args.dotnet, exact_dll])
    run("final-contract-build-green", [args.dotnet, "build", contract_project, *test_flags])
    run("autofocus-final-green", [args.dotnet, harness_dll, "--uia-background"])
    run("background-final-green", [args.dotnet, harness_dll, "--background"])
    run("passive-final-green", [args.dotnet, harness_dll])
    publish = args.work / "publish"
    runtime_pin = args.work / "pin-core-runtime.targets"
    runtime_pin.write_text('<Project><Target Name="AgentBridgePinCoreRuntime" BeforeTargets="ProcessFrameworkReferences">'
        '<ItemGroup><FrameworkReference Update="Microsoft.NETCore.App" RuntimeFrameworkVersion="' + RUNTIME + '"/></ItemGroup>'
        '</Target></Project>', encoding="utf-8")
    publish_flags = common + ["-r", "win-x64", "--self-contained", "true", "-p:CustomBeforeMicrosoftCommonTargets=" + str(runtime_pin),
        "-p:Version=" + derivative_version, "-p:InformationalVersion=" + derivative_version + "+" + COMMIT, *PRIVACY_FLAGS,
        "-p:Deterministic=true", "-p:ContinuousIntegrationBuild=true", "-p:RestoreConfigFile=" + str(config), "-o", str(publish)]
    command = [str(args.dotnet), "publish", str(project), *publish_flags]
    for argument in command: safe_argument(argument)
    batch = args.work / "publish-hidden.cmd"
    batch.write_text('@echo off\ncall "' + safe_argument(args.vcvars.absolute()) + '" >nul\nif errorlevel 1 exit /b %errorlevel%\n' +
        subprocess.list2cmdline(command) + '\nexit /b %errorlevel%\n', encoding="utf-8", newline="\r\n")
    run("native-aot-publish", [os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"), "/d", "/s", "/c", str(batch)])
    if digest(publish / "libSkiaSharp.dll").hex() != SKIA_SHA256: raise ValueError("Skia changed during upstream build")
    assets = json.loads((project.parent / "obj/project.assets.json").read_text())
    used = {}
    def restored_record(package, version):
        name = package + "." + version + ".nupkg"
        archive = plain(args.work / "packages" / package / version / name)
        actual = {**file_record(archive), "sha512": base64.b64encode(digest(archive, "sha512")).decode()}
        if actual != packages[name]: raise ValueError("restored archive differs from the verified package: " + name)
        return actual
    for key, value in assets["libraries"].items():
        if value["type"] != "package": continue
        package, version = key.lower().split("/")
        # NuGet's signed-package content hash differs from the SHA512 of the
        # archive containing the signature. Keep both and verify actual bytes.
        used[key.lower()] = {**restored_record(package, version), "nuget_content_sha512": value["sha512"], "kind":"package"}
    for framework in assets["project"]["frameworks"].values():
        for item in framework.get("downloadDependencies", []):
            match = re.fullmatch(r"\[([^,]+), \1\]", item["version"])
            if not match: raise ValueError("unbounded SDK runtime download in restored assets")
            package, version = item["name"].lower(), match[1]
            key = package + "/" + version
            if key not in used: used[key] = {**restored_record(package, version), "kind":"sdk-download"}
    for name in PACK_PINS:
        key = name[:-6].removesuffix("." + RUNTIME) + "/" + RUNTIME
        if key not in used: raise ValueError("effective AOT/runtime pack was not the pinned version")
    args.output.mkdir(parents=True)
    for name in ("winapp.exe", "libSkiaSharp.dll"): shutil.copyfile(plain(publish / name), args.output / name)
    shutil.copyfile(source / "LICENSE", args.output / "LICENSE.txt")
    notice_files = {}
    for key in used:
        package, version = key.split("/")
        if not (package.startswith("microsoft.netcore.app.runtime") or package in ("microsoft.dotnet.ilcompiler", "runtime.win-x64.microsoft.dotnet.ilcompiler")): continue
        name = package + "." + version + ".nupkg"
        with zipfile.ZipFile(feed / name) as archive:
            for member in archive.namelist():
                if PurePosixPath(member).name.upper() in ("LICENSE", "LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"):
                    notice = "DOTNET-" + package + "-" + PurePosixPath(member).name
                    (args.output / notice).write_bytes(archive.read(member))
                    notice_files[notice] = file_record(args.output / notice)
    patched_sources = {TARGET:{"before":before,"after":after}}
    for changes in (message_changes, autofocus_changes, exact_passive_changes):
        for path, record in changes.items():
            if path in patched_sources: patched_sources[path]["after"] = record["after"]
            else: patched_sources[path] = dict(record)
    provenance = {"schema":1, "product":"WinApp 0.5.0 + Agent Bridge passive capture, background message, UIA auto-focus" + (" and exact-passive window" if exact_passive else "") + " fixes", "upstream_commit":COMMIT,
        "upstream_source_archive":file_record(args.source_archive), "build_script":script_record,
        "build_package_inventory":file_record(inputs / pin_source.name),
        "patches":{name:file_record(inputs / name) for name in patch_names},
        "patched_sources":patched_sources,
        "patch_source_changes":{patch.name:{TARGET:{"before":before,"after":after}},message_patch.name:message_changes,autofocus_patch.name:autofocus_changes,**({exact_passive_patch.name:exact_passive_changes} if exact_passive else {})},
        "sdk_version":SDK, "dotnet_host":file_record(args.dotnet),
        "runtime_version":RUNTIME, "native_aot":True, "build_flags":publish_flags,
        "derivative_version":derivative_version, "build_profile":args.profile,
        "packages":used, "notices":notice_files, "tests":{"passive_red_failures":3,"background_red_failures":1,"autofocus_red_failures":3,**({"exact_passive_red_failures":2} if exact_passive else {}),"green_failures":0},
        "contract_sources":{**{name:file_record(contract/name) for name in ("Program.cs","BackgroundMessageContract.cs","BackgroundUiaContract.cs")}, **({"ExactPassiveContract.cs":file_record(exact_contract/"ExactPassiveContract.cs")} if exact_passive else {})},
        "files":{name:file_record(args.output/name) for name in ("winapp.exe","libSkiaSharp.dll","LICENSE.txt")}}
    # Local paths are recorded in private logs, not the distributable provenance.
    provenance["build_flags"] = [str(flag).replace(str(config), "<offline-config>").replace(str(publish), "<publish>").replace(str(runtime_pin), "<runtime-pin-targets>") for flag in publish_flags]
    provenance["runtime_pin_targets"] = file_record(runtime_pin)
    (args.output / "WINAPP-BUILD-PROVENANCE.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"output":str(args.output), "files":provenance["files"], "steps":len(steps)}), flush=True)

if __name__ == "__main__": main()
