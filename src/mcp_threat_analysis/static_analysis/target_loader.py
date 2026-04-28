"""Fetch / unpack a ScanTarget into a sandboxed WorkDir.

Supports local paths, S3 URLs, and tarball/zip archives.
Enforces total-size and file-count limits.
"""
from __future__ import annotations

import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

import httpx

from ..common.config import get_settings
from ..common.logging import get_logger
from ..common.models import ScanTarget, WorkDir

log = get_logger(__name__)

_LANG_MAP = {
    ".py": "python",
    ".pyi": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".cs": "csharp",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
}

_MAX_FILES = 50_000
_TEXT_EXT = set(_LANG_MAP.keys()) | {".json", ".md", ".yaml", ".yml", ".toml"}


class ArtifactTooLarge(Exception):
    pass


class TargetLoader:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root or get_settings().workdir_root)
        self.root.mkdir(parents=True, exist_ok=True)

    def prepare(self, target: ScanTarget) -> WorkDir:
        wd = Path(tempfile.mkdtemp(prefix=f"l2-{target.server_id}-", dir=self.root))
        try:
            artifact = self._fetch(target.artifact_path, wd)
            self._extract(artifact, wd)
            artifact.unlink(missing_ok=True)
            lang_files = self._index_languages(wd)
            return WorkDir(root_path=wd, primary_lang=target.primary_lang, lang_files=lang_files)
        except Exception:
            shutil.rmtree(wd, ignore_errors=True)
            raise

    def cleanup(self, wd: WorkDir) -> None:
        shutil.rmtree(wd.root_path, ignore_errors=True)

    def _fetch(self, src: str, into: Path) -> Path:
        dst = into / "artifact.bin"
        if src.startswith("s3://"):
            # Stub: in production wire boto3; here we fail loud.
            raise NotImplementedError("S3 fetch requires boto3 wiring; not in scaffold")
        if src.startswith(("http://", "https://")):
            with httpx.stream("GET", src, timeout=60.0, follow_redirects=True) as resp:
                resp.raise_for_status()
                total = 0
                limit = get_settings().artifact_max_bytes
                with dst.open("wb") as f:
                    for chunk in resp.iter_bytes():
                        total += len(chunk)
                        if total > limit:
                            raise ArtifactTooLarge(f"artifact exceeded {limit} bytes")
                        f.write(chunk)
            return dst
        # local path
        local = Path(src)
        if not local.exists():
            raise FileNotFoundError(src)
        if local.stat().st_size > get_settings().artifact_max_bytes:
            raise ArtifactTooLarge(str(local))
        shutil.copyfile(local, dst)
        return dst

    def _extract(self, archive: Path, into: Path) -> None:
        # Support tarball / wheel(zip) / npm tgz.
        if tarfile.is_tarfile(archive):
            with tarfile.open(archive, "r:*") as tf:
                self._safe_extract_tar(tf, into)
            return
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as zf:
                self._safe_extract_zip(zf, into)
            return
        # Treat as a single source file: leave it in place.

    def _safe_extract_tar(self, tf: tarfile.TarFile, into: Path) -> None:
        count = 0
        for member in tf.getmembers():
            if member.name.startswith(("/", "..")) or ".." in Path(member.name).parts:
                continue
            count += 1
            if count > _MAX_FILES:
                raise ArtifactTooLarge("file count exceeded")
            tf.extract(member, into)

    def _safe_extract_zip(self, zf: zipfile.ZipFile, into: Path) -> None:
        count = 0
        for info in zf.infolist():
            name = info.filename
            if name.startswith(("/", "..")) or ".." in Path(name).parts:
                continue
            count += 1
            if count > _MAX_FILES:
                raise ArtifactTooLarge("file count exceeded")
            zf.extract(info, into)

    def _index_languages(self, root: Path) -> dict[str, list[Path]]:
        out: dict[str, list[Path]] = {}
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            lang = _LANG_MAP.get(p.suffix.lower())
            if lang:
                out.setdefault(lang, []).append(p)
        return out


def is_text_file(p: Path) -> bool:
    return p.suffix.lower() in _TEXT_EXT
