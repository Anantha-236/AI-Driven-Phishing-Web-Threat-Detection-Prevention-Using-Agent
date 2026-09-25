from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

HTML_SUFFIXES = {".html", ".htm"}


class SelectiveExtractionError(RuntimeError):
    pass


def safe_member_path(name: str) -> PurePosixPath | None:
    if not isinstance(name, str):
        return None

    cleaned = name.replace("\\", "/").strip()
    if not cleaned or cleaned.endswith("/"):
        return None

    # Reject absolute paths, drive-qualified paths and parent traversal.
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        return None

    path = PurePosixPath(cleaned)
    if any(part in ("", ".", "..") for part in path.parts):
        return None

    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_html_only(zip_path: Path, destination: Path) -> dict:
    if not zip_path.is_file():
        raise SelectiveExtractionError(f"ZIP not found: {zip_path}")

    destination.mkdir(parents=True, exist_ok=True)

    extracted = []
    skipped_bad_name = 0
    skipped_non_html = 0
    skipped_duplicate = 0
    skipped_read_error = 0

    seen_targets: set[str] = set()

    try:
        archive = zipfile.ZipFile(zip_path, "r")
    except Exception as exc:
        raise SelectiveExtractionError(f"cannot open ZIP central directory: {exc}") from exc

    with archive:
        try:
            members = archive.infolist()
        except Exception as exc:
            raise SelectiveExtractionError(f"cannot enumerate ZIP members: {exc}") from exc

        for index, info in enumerate(members):
            try:
                name = info.filename
            except Exception:
                skipped_bad_name += 1
                continue

            safe = safe_member_path(name)
            if safe is None:
                skipped_bad_name += 1
                continue

            if safe.suffix.lower() not in HTML_SUFFIXES:
                skipped_non_html += 1
                continue

            relative = Path(*safe.parts)
            key = relative.as_posix().lower()

            if key in seen_targets:
                skipped_duplicate += 1
                continue

            target = destination / relative
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, target.open("wb") as sink:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        sink.write(chunk)
            except Exception:
                skipped_read_error += 1
                try:
                    target.unlink(missing_ok=True)
                except Exception:
                    pass
                continue

            seen_targets.add(key)
            extracted.append({
                "archive_name": safe.as_posix(),
                "output_path": relative.as_posix(),
                "size": target.stat().st_size,
                "sha256": sha256_file(target),
            })

    if not extracted:
        raise SelectiveExtractionError(
            "ZIP was readable but no safe .html/.htm members could be extracted"
        )

    return {
        "status": "PASS",
        "zip": str(zip_path),
        "destination": str(destination),
        "archive_member_count": len(members),
        "html_extracted": len(extracted),
        "skipped_bad_name_or_path": skipped_bad_name,
        "skipped_non_html": skipped_non_html,
        "skipped_duplicate_html_path": skipped_duplicate,
        "skipped_html_read_error": skipped_read_error,
        "extracted": extracted,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely extract only HTML/HTM captures from a Stage B archive ZIP."
    )
    parser.add_argument("zip_path", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    result = extract_html_only(args.zip_path, args.destination)

    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered + "\n", encoding="utf-8")

    # Keep console output compact for very large archives.
    print(json.dumps({
        key: value
        for key, value in result.items()
        if key != "extracted"
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
