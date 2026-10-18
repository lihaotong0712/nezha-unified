"""准备 Dashboard 内嵌前端：管理前端来自本仓库，公开主题来自锁定产物。"""

import hashlib
import io
import json
import re
import shutil
import stat
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent


def replace_bundle(source: Path, target: Path) -> None:
    """替换生成目录，同时保留上游已跟踪的 .gitkeep。"""
    if not (source / "index.html").is_file():
        raise ValueError(f"前端产物缺少 index.html：{source}")
    target.mkdir(parents=True, exist_ok=True)
    for child in target.iterdir():
        if child.name == ".gitkeep":
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    shutil.copytree(source, target, dirs_exist_ok=True)


def prepare_public_frontend(frontend: dict) -> None:
    name = frontend["path"]
    if not re.fullmatch(r"[a-z][a-z0-9-]*-dist", name) or name == "admin-dist":
        raise ValueError(f"无效的公开主题目录：{name}")
    digest = frontend["sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError(f"无效的 SHA-256：{name}")
    cache = ROOT / ".cache" / "frontends" / f"{digest}.zip"
    if cache.exists():
        data = cache.read_bytes()
    else:
        print(f"下载公开主题：{name} {frontend['version']}", flush=True)
        with urllib.request.urlopen(frontend["url"], timeout=120) as response:
            data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"公开主题 SHA-256 校验失败：{name}，请检查或删除缓存 {cache}")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(data)
    with tempfile.TemporaryDirectory(dir=cache.parent) as staging:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                path = PurePosixPath(member.filename)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not path.parts
                    or path.parts[0] != "dist"
                    or "\\" in member.filename
                    or stat.S_ISLNK(member.external_attr >> 16)
                ):
                    raise ValueError(f"公开主题包含无效路径：{member.filename}")
            archive.extractall(staging)
        replace_bundle(Path(staging) / "dist", ROOT / "cmd/dashboard" / name)
    print(f"公开主题已校验：{name} {frontend['version']}", flush=True)


def main() -> None:
    lock = json.loads((ROOT / "upstreams.lock.json").read_text())
    if lock["schema_version"] != 1:
        raise ValueError("不支持的上游版本锁文件格式")
    replace_bundle(ROOT / "web/admin/dist", ROOT / "cmd/dashboard/admin-dist")
    for frontend in lock["public_frontends"]:
        prepare_public_frontend(frontend)


if __name__ == "__main__":
    main()
