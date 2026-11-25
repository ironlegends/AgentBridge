#!/usr/bin/env python3
"""Package separately pinned native resources; never consult a live DeskMCP app."""
from pathlib import Path
import argparse, hashlib, json, os, shutil, tempfile

PINS = {
    "winapp": ("winapp/winapp.exe", "2251c7a7a476b6cc527982bc5846e2433f524ff88796b6e9d16362918bdc3cc3"),
    "skia": ("winapp/libSkiaSharp.dll", "9a0d95e8caaa852c70d085af6a40a744242172ad9ea3fd6bc7599875a8a1dbcd"),
    "vda": ("VirtualDesktopAccessor.dll", "716c4ed3a38eaf3f318ae670949799f74d8030c7f79a117e903bcb73b14354b4"),
}
VDA_COMMIT = "8172097993b1194e3d5e2ff38421ebb06f867b6c"
WINAPP_VERSION = "0.5.0-agentbridge.2"
WINAPP_PROVENANCE_SHA256 = "13408bcc2d802b5b3f1fc91ff969a1918ba975340b230b9bc6f5f9494548fa76"

def digest(path):
    with path.open("rb") as file: return hashlib.file_digest(file, "sha256").hexdigest()

def plain_file(path):
    if not path.is_file() or path.is_symlink(): raise ValueError("input must be a regular file: " + str(path))
    if os.name == "nt" and path.stat(follow_symlinks=False).st_file_attributes & 0x400:
        raise ValueError("reparse input is not allowed: " + str(path))
    return path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper-publish", type=Path, required=True)
    parser.add_argument("--winapp-dir", type=Path, required=True)
    parser.add_argument("--vda-dir", type=Path, required=True)
    parser.add_argument("--dotnet-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    destination = args.output.absolute()
    if destination.exists(): raise ValueError("output must not already exist")
    inputs = {
        "native": plain_file(args.helper_publish / "agent-bridge-native.exe"),
        "winapp": plain_file(args.winapp_dir / "winapp.exe"),
        "skia": plain_file(args.winapp_dir / "libSkiaSharp.dll"),
        "vda": plain_file(args.vda_dir / "VirtualDesktopAccessor.dll"),
    }
    if (args.vda_dir / "SOURCE_COMMIT.txt").read_text().strip() != VDA_COMMIT:
        raise ValueError("VDA source commit mismatch")
    for key, (_, expected) in PINS.items():
        if digest(inputs[key]) != expected: raise ValueError(key + " pin mismatch")
    provenance_path = plain_file(args.winapp_dir / "WINAPP-BUILD-PROVENANCE.json")
    if digest(provenance_path) != WINAPP_PROVENANCE_SHA256: raise ValueError("qualified WinApp derivative provenance mismatch")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    root = Path(__file__).resolve().parents[2]
    notices = {
        "WINAPP-LICENSE.txt": plain_file(args.winapp_dir / "LICENSE.txt"),
        "VDA-LICENSE.txt": plain_file(args.vda_dir / "LICENSE.txt"),
        "VDA-SOURCE-COMMIT.txt": plain_file(args.vda_dir / "SOURCE_COMMIT.txt"),
        "DOTNET-LICENSE.txt": plain_file(args.dotnet_dir / "LICENSE.txt"),
        "DOTNET-THIRD-PARTY-NOTICES.txt": plain_file(args.dotnet_dir / "ThirdPartyNotices.txt"),
        "DESKMCP-APACHE-2.0.txt": plain_file(root / "native/agent-bridge-native/notices/DESKMCP-APACHE-2.0.txt"),
        "NATIVE-PROVENANCE.md": plain_file(root / "native/agent-bridge-native/THIRD-PARTY-NOTICES.md"),
        "WINAPP-THIRD-PARTY-NOTICES.txt": plain_file(root / "native/agent-bridge-native/notices/WINAPP-THIRD-PARTY-NOTICES.txt"),
        "WINAPP-DEPENDENCIES.json": plain_file(root / "native/agent-bridge-native/notices/WINAPP-DEPENDENCIES.json"),
        "WINAPP-BUILD-PROVENANCE.json": provenance_path,
    }
    for name, record in provenance["notices"].items():
        if Path(name).name != name or "/" in name or "\\" in name or name in notices: raise ValueError("invalid derivative notice name")
        source = plain_file(args.winapp_dir / name)
        if source.stat().st_size != record["size"] or digest(source) != record["sha256"]: raise ValueError("derivative runtime notice mismatch")
        notices[name] = source
    for name, expected in {
        "WINAPP-THIRD-PARTY-NOTICES.txt": "a98bd7554d4080faaa5688439d438e131ebfe4140c2bb4ed863c4fe99043b7d6",
        "WINAPP-DEPENDENCIES.json": "8efaf9095916417abb6da9be23c0699ce2d70d38bb5f5bf9cd00cc5ca1989c24",
    }.items():
        if digest(notices[name]) != expected: raise ValueError("qualified dependency notice changed: " + name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".native-bundle-", dir=destination.parent))
    try:
        files = {}
        for key, source in inputs.items():
            relative = "agent-bridge-native.exe" if key == "native" else PINS[key][0]
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            sha = digest(target)
            if key in PINS and sha != PINS[key][1]: raise ValueError("input changed during copy")
            files[key] = {"path": relative, "sha256": sha, "size": target.stat().st_size}
        notice_records = {}
        for name, source in notices.items():
            target = temporary / "notices" / name
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(source, target)
            notice_records[name] = {"path": "notices/" + name, "sha256": digest(target), "size": target.stat().st_size}
        manifest = {"schema": 1, "platform": "windows-x64", "protocol": 1,
                    "winapp_version": WINAPP_VERSION, "vda_commit": VDA_COMMIT,
                    "files": files, "notices": notice_records}
        manifest_path = temporary / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        sha = digest(manifest_path)
        temporary.rename(destination)
        print(json.dumps({"bundle_root": str(destination), "manifest_sha256": sha,
                          "files": {key: value["sha256"] for key, value in files.items()}}, indent=2))
    finally:
        if temporary.exists(): shutil.rmtree(temporary)

if __name__ == "__main__": main()
