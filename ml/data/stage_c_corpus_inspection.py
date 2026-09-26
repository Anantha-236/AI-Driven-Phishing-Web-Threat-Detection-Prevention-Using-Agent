
"""Stage C Task 5 hotfix: robust MySQL parsing + filename reconciliation."""
from __future__ import annotations
from collections import Counter, defaultdict
from io import BytesIO
import hashlib, json, re, zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

REPORT_SCHEMA = "stage-c-development-corpus-inspection-2"
_SAFE_SQL_MAX = 64 * 1024 * 1024
_SAFE_NESTED_ZIP_MAX = 512 * 1024 * 1024

class StageCCorpusInspectionError(ValueError):
    pass

def canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()

def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCCorpusInspectionError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCCorpusInspectionError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCCorpusInspectionError(f"JSON root must be an object: {path}")
    return value

def _require_task4_seal(seal: Mapping[str, Any]) -> None:
    checks = {
        "schema_version": "stage-c-public-download-local-seal-1",
        "status": "PASS",
        "stage": "C",
        "role": "DEVELOPMENT",
        "verification_mode": "PUBLIC_DOWNLOAD_LOCAL_SEAL",
        "model_training_authorized": False,
        "extraction_authorized": False,
        "final_holdout_touched": False,
    }
    for k, v in checks.items():
        if seal.get(k) != v:
            raise StageCCorpusInspectionError(f"Task-4 seal guard mismatch: {k}")

def _scan_statement_end(text: str, start: int) -> int:
    quote = None
    escape = False
    line_comment = False
    block_comment = False
    i = start
    while i < len(text):
        ch = text[i]
        nxt = text[i+1] if i+1 < len(text) else ""
        if line_comment:
            if ch in "\r\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                if i + 1 < len(text) and text[i+1] == quote and quote in {"'", '"'}:
                    i += 1
                else:
                    quote = None
            i += 1
            continue
        if ch in {"'", '"', "`"}:
            quote = ch
        elif ch == "-" and nxt == "-":
            line_comment = True
            i += 1
        elif ch == "#":
            line_comment = True
        elif ch == "/" and nxt == "*":
            block_comment = True
            i += 1
        elif ch == ";":
            return i + 1
        i += 1
    return len(text)

def _balanced_paren_end(text: str, open_index: int) -> int:
    if open_index >= len(text) or text[open_index] != "(":
        raise StageCCorpusInspectionError("balanced-parenthesis scan did not start at '('")
    depth = 0
    quote = None
    escape = False
    i = open_index
    while i < len(text):
        ch = text[i]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                if i + 1 < len(text) and text[i+1] == quote and quote in {"'", '"'}:
                    i += 1
                else:
                    quote = None
        else:
            if ch in {"'", '"', "`"}:
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    raise StageCCorpusInspectionError("unterminated parenthesized SQL structure")

def _split_top_level(text: str) -> list[str]:
    parts, buf = [], []
    depth = 0
    quote = None
    escape = False
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                if i + 1 < len(text) and text[i+1] == quote and quote in {"'", '"'}:
                    buf.append(text[i+1]); i += 1
                else:
                    quote = None
        else:
            if ch in {"'", '"', "`"}:
                quote = ch; buf.append(ch)
            elif ch == "(":
                depth += 1; buf.append(ch)
            elif ch == ")":
                depth = max(0, depth-1); buf.append(ch)
            elif ch == "," and depth == 0:
                parts.append("".join(buf).strip()); buf = []
            else:
                buf.append(ch)
        i += 1
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p]

_CREATE_START_RE = re.compile(
    r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>`[^`]+`|[A-Za-z0-9_.-]+)\s*\(",
    re.I,
)
_INSERT_START_RE = re.compile(
    r"\bINSERT\s+INTO\s+(?P<name>`[^`]+`|[A-Za-z0-9_.-]+)\s*",
    re.I,
)
_COLUMN_RE = re.compile(r"^\s*`?([A-Za-z_][A-Za-z0-9_$.-]*)`?\s+(.+)$", re.S)

def _parse_create_tables(text: str) -> list[dict[str, Any]]:
    tables = []
    for m in _CREATE_START_RE.finditer(text):
        name = m.group("name").strip("`")
        open_i = m.end() - 1
        close_i = _balanced_paren_end(text, open_i)
        body = text[open_i+1:close_i]
        columns, constraints = [], []
        for part in _split_top_level(body):
            upper = part.lstrip().upper()
            if upper.startswith(("PRIMARY ", "UNIQUE ", "FOREIGN ", "CONSTRAINT ", "KEY ", "CHECK ", "INDEX ")):
                constraints.append(part[:500]); continue
            cm = _COLUMN_RE.match(part)
            if cm:
                columns.append({"name": cm.group(1), "definition": cm.group(2).strip()[:500]})
            else:
                constraints.append(part[:500])
        stmt_end = _scan_statement_end(text, close_i+1)
        options = text[close_i+1:stmt_end].strip().rstrip(";").strip()
        tables.append({"table": name, "columns": columns, "constraints": constraints, "table_options": options[:1000]})
    tables.sort(key=lambda x: x["table"].casefold())
    return tables

def _parse_sql_scalar(token: str) -> Any:
    token = token.strip()
    if not token:
        return ""
    if token.upper() == "NULL":
        return None
    if token[0] in {"'", '"'} and len(token) >= 2 and token[-1] == token[0]:
        q = token[0]
        inner = token[1:-1]
        out, i = [], 0
        translations = {"0":"\0","n":"\n","r":"\r","t":"\t","b":"\b","Z":"\x1a","\\":"\\","'":"'","\"":"\""}
        while i < len(inner):
            ch = inner[i]
            if ch == "\\" and i+1 < len(inner):
                out.append(translations.get(inner[i+1], inner[i+1])); i += 2; continue
            if ch == q and i+1 < len(inner) and inner[i+1] == q:
                out.append(q); i += 2; continue
            out.append(ch); i += 1
        return "".join(out)
    if re.fullmatch(r"[-+]?\d+", token):
        return int(token)
    if re.fullmatch(r"[-+]?(?:\d+\.\d*|\d*\.\d+)", token):
        return float(token)
    return token

def _parse_value_tuples(blob: str) -> list[list[Any]]:
    rows, i = [], 0
    while i < len(blob):
        while i < len(blob) and (blob[i].isspace() or blob[i] == ","):
            i += 1
        if i >= len(blob):
            break
        if blob[i] != "(":
            raise StageCCorpusInspectionError(f"unexpected VALUES token near offset {i}: {blob[i:i+30]!r}")
        end = _balanced_paren_end(blob, i)
        rows.append([_parse_sql_scalar(x) for x in _split_top_level(blob[i+1:end])])
        i = end + 1
    return rows

def _parse_inserts(text: str):
    stmt_counts = Counter()
    row_counts = Counter()
    rows_by_table = defaultdict(list)
    column_sets = defaultdict(set)
    for m in _INSERT_START_RE.finditer(text):
        table = m.group("name").strip("`")
        cursor = m.end()
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        columns = None
        if cursor < len(text) and text[cursor] == "(":
            close = _balanced_paren_end(text, cursor)
            columns = [x.strip().strip("`\"[] ") for x in _split_top_level(text[cursor+1:close])]
            column_sets[table].add(tuple(columns))
            cursor = close + 1
        vm = re.match(r"\s*VALUES\b", text[cursor:], re.I)
        if not vm:
            continue
        values_start = cursor + vm.end()
        stmt_end = _scan_statement_end(text, values_start)
        tuples = _parse_value_tuples(text[values_start:stmt_end-1])
        stmt_counts[table] += 1
        row_counts[table] += len(tuples)
        if columns:
            for vals in tuples:
                if len(vals) != len(columns):
                    raise StageCCorpusInspectionError(
                        f"INSERT arity mismatch for table {table}: columns={len(columns)} values={len(vals)}"
                    )
                rows_by_table[table].append(dict(zip(columns, vals)))
    return stmt_counts, row_counts, rows_by_table, column_sets

def inspect_index_sql(sql_bytes: bytes) -> dict[str, Any]:
    if len(sql_bytes) > _SAFE_SQL_MAX:
        raise StageCCorpusInspectionError(f"index.sql exceeds safe inspection limit: {len(sql_bytes)}")
    try:
        text = sql_bytes.decode("utf-8"); encoding = "utf-8"
    except UnicodeDecodeError:
        text = sql_bytes.decode("utf-8", errors="replace"); encoding = "utf-8-with-replacement"

    tables = _parse_create_tables(text)
    stmt_counts, row_counts, rows_by_table, column_sets = _parse_inserts(text)
    all_cols = {c["name"].casefold(): c["name"] for t in tables for c in t["columns"]}
    semantic = {
        "record_id": sorted(v for k,v in all_cols.items() if k in {"id","rec_id","record_id","uuid","key"} or k.endswith("_id")),
        "url": sorted(v for k,v in all_cols.items() if k in {"url","uri","link"} or "url" in k),
        "label": sorted(v for k,v in all_cols.items() if k in {"label","class","result","target","is_phishing","phishing"} or any(x in k for x in ("label","class","phish"))),
        "html_or_path": sorted(v for k,v in all_cols.items() if k in {"website","html","html_file","filename","file","path"} or any(x in k for x in ("html","file","path","website"))),
        "time": sorted(v for k,v in all_cols.items() if k in {"created_date","created_at","timestamp","scan_date","date","time"} or any(x in k for x in ("date","time","created","scan"))),
    }
    return {
        "size_bytes": len(sql_bytes),
        "sha256": hashlib.sha256(sql_bytes).hexdigest(),
        "decoded_as": encoding,
        "create_table_count": len(tables),
        "tables": tables,
        "insert_summary": {
            "insert_statements_by_table": dict(sorted(stmt_counts.items())),
            "insert_rows_by_table": dict(sorted(row_counts.items())),
            "explicit_insert_column_sets": {k:[list(x) for x in sorted(v)] for k,v in sorted(column_sets.items())},
            "total_insert_statements": sum(stmt_counts.values()),
            "total_insert_rows": sum(row_counts.values()),
        },
        "semantic_column_candidates": semantic,
        "_rows_by_table": rows_by_table,
    }

def inspect_nested_zip_bytes(name: str, payload: bytes) -> dict[str, Any]:
    if len(payload) > _SAFE_NESTED_ZIP_MAX:
        raise StageCCorpusInspectionError(f"nested ZIP exceeds safe in-memory inspection limit: {name}")
    try:
        with zipfile.ZipFile(BytesIO(payload), "r", allowZip64=True) as z:
            infos = z.infolist()
            files = [x for x in infos if not x.is_dir()]
            bad = z.testzip()
            if bad is not None:
                raise StageCCorpusInspectionError(f"nested ZIP CRC/decompression failure: {name}: {bad}")
            html_infos = [x for x in files if PurePosixPath(x.filename).suffix.casefold() in {".html",".htm"}]
            names = [x.filename for x in files]
            basenames = [PurePosixPath(x.filename).name for x in files]
            html_basenames = [PurePosixPath(x.filename).name for x in html_infos]
            total_u = sum(x.file_size for x in files)
            total_c = sum(x.compress_size for x in files)
            largest = max(files, key=lambda x:x.file_size, default=None)
            return {
                "name": name,
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "member_count": len(infos),
                "file_count": len(files),
                "html_files": len(html_infos),
                "unique_member_names": len(set(names)),
                "unique_basenames": len(set(basenames)),
                "unique_html_basenames": len(set(html_basenames)),
                "duplicate_member_names": len(names)-len(set(names)),
                "duplicate_basenames": len(basenames)-len(set(basenames)),
                "duplicate_html_basenames": len(html_basenames)-len(set(html_basenames)),
                "oversized_members_over_12_mib": sum(x.file_size > 12*1024*1024 for x in files),
                "total_uncompressed_bytes": total_u,
                "total_compressed_bytes": total_c,
                "aggregate_compression_ratio": total_u/max(total_c,1) if total_u else 0.0,
                "extension_counts": dict(sorted(Counter(PurePosixPath(x.filename).suffix.casefold() or "<no-extension>" for x in files).items())),
                "largest_member": {"name":largest.filename[:500],"size_bytes":largest.file_size} if largest else None,
                "_html_basenames": set(html_basenames),
            }
    except zipfile.BadZipFile as exc:
        raise StageCCorpusInspectionError(f"invalid nested ZIP {name}: {exc}") from exc

def _canonical_index_rows(index_report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows_by_table = index_report.get("_rows_by_table")
    if not isinstance(rows_by_table, Mapping):
        raise StageCCorpusInspectionError("parsed SQL rows missing")
    candidates = []
    for table, rows in rows_by_table.items():
        if not isinstance(rows, list) or not rows or not isinstance(rows[0], Mapping):
            continue
        names = {str(x).casefold() for x in rows[0].keys()}
        if {"rec_id","url","website","result","created_date"}.issubset(names):
            candidates.append((table, rows))
    if len(candidates) != 1:
        raise StageCCorpusInspectionError(f"expected exactly one canonical metadata table, found {len(candidates)}")
    return candidates[0][1]

def inspect_development_corpus(*, archive_path: Path, seal: Mapping[str, Any]) -> dict[str, Any]:
    _require_task4_seal(seal)
    sealed_archive = seal.get("archive")
    if not isinstance(sealed_archive, Mapping):
        raise StageCCorpusInspectionError("Task-4 seal archive identity missing")
    if not archive_path.is_file():
        raise StageCCorpusInspectionError(f"development archive not found: {archive_path}")
    if archive_path.name != sealed_archive.get("filename") or archive_path.stat().st_size != sealed_archive.get("size_bytes"):
        raise StageCCorpusInspectionError("development archive identity differs from Task-4 seal")

    expected_hashes = {
        x["name"]:x["sha256"] for x in seal.get("members",[])
        if isinstance(x,Mapping) and isinstance(x.get("name"),str) and isinstance(x.get("sha256"),str)
    }

    try:
        with zipfile.ZipFile(archive_path,"r",allowZip64=True) as outer:
            infos = [x for x in outer.infolist() if not x.is_dir()]
            index_infos = [x for x in infos if PurePosixPath(x.filename).name=="index.sql"]
            nested_infos = [x for x in infos if PurePosixPath(x.filename).suffix.casefold()==".zip"]
            if len(index_infos)!=1: raise StageCCorpusInspectionError(f"expected exactly one index.sql, found {len(index_infos)}")
            if not nested_infos: raise StageCCorpusInspectionError("no nested dataset ZIPs found")

            index_info = index_infos[0]
            index_bytes = outer.read(index_info)
            if hashlib.sha256(index_bytes).hexdigest() != expected_hashes.get(index_info.filename):
                raise StageCCorpusInspectionError("index.sql hash differs from Task-4 seal")
            index_report = inspect_index_sql(index_bytes)
            canonical_rows = _canonical_index_rows(index_report)

            nested_reports=[]
            archive_html_names=set()
            dup_across=0
            for info in sorted(nested_infos,key=lambda x:x.filename):
                payload=outer.read(info)
                if hashlib.sha256(payload).hexdigest() != expected_hashes.get(info.filename):
                    raise StageCCorpusInspectionError(f"nested ZIP hash differs from Task-4 seal: {info.filename}")
                report=inspect_nested_zip_bytes(info.filename,payload)
                current=report.pop("_html_basenames")
                dup_across += len(archive_html_names.intersection(current))
                archive_html_names.update(current)
                nested_reports.append(report)
    except zipfile.BadZipFile as exc:
        raise StageCCorpusInspectionError(f"invalid development outer ZIP: {exc}") from exc

    website_values=[str(r.get("website","")) for r in canonical_rows]
    unique_websites=set(website_values)
    labels=Counter(str(r.get("result")) for r in canonical_rows)
    dates=sorted(str(r.get("created_date")) for r in canonical_rows if r.get("created_date") not in {None,""})
    rec_ids=[r.get("rec_id") for r in canonical_rows]
    missing=sorted(unique_websites-archive_html_names)
    extras=sorted(archive_html_names-unique_websites)
    ext=Counter()
    for r in nested_reports: ext.update(r["extension_counts"])

    clean_index=dict(index_report); clean_index.pop("_rows_by_table",None)
    reconciliation={
        "metadata_rows":len(canonical_rows),
        "metadata_unique_rec_ids":len(set(rec_ids)),
        "metadata_duplicate_rec_ids":len(rec_ids)-len(set(rec_ids)),
        "metadata_unique_website_filenames":len(unique_websites),
        "metadata_duplicate_website_references":len(website_values)-len(unique_websites),
        "archive_unique_html_basenames":len(archive_html_names),
        "archive_duplicate_html_basenames_across_archives":dup_across,
        "metadata_missing_html_count":len(missing),
        "archive_extra_html_count":len(extras),
        "metadata_website_set_sha256":canonical_hash(sorted(unique_websites)),
        "archive_html_basename_set_sha256":canonical_hash(sorted(archive_html_names)),
        "missing_html_set_sha256":canonical_hash(missing),
        "extra_html_set_sha256":canonical_hash(extras),
        "published_expected_records":80000,
        "metadata_rows_equal_published_expected":len(canonical_rows)==80000,
        "class_counts":dict(sorted(labels.items())),
        "created_date_min":dates[0] if dates else None,
        "created_date_max":dates[-1] if dates else None,
    }
    result={
        "schema_version":REPORT_SCHEMA,
        "status":"PASS",
        "stage":"C","role":"DEVELOPMENT",
        "inspection_mode":"READ_ONLY_IN_MEMORY_NO_EXTRACTION",
        "research_only":True,"deployment_authorized":False,
        "model_training_authorized":False,"extraction_authorized":False,"final_holdout_touched":False,
        "source":{"doi":seal["source"]["doi"],"version":seal["source"]["version"],"archive_sha256":sealed_archive["sha256"],"member_set_sha256":seal["member_set_sha256"]},
        "index_sql":clean_index,
        "nested_archives":nested_reports,
        "aggregate":{
            "nested_archive_count":len(nested_reports),
            "nested_member_files":sum(x["file_count"] for x in nested_reports),
            "html_files":sum(x["html_files"] for x in nested_reports),
            "unique_html_basenames":len(archive_html_names),
            "extension_counts":dict(sorted(ext.items())),
        },
        "reconciliation":reconciliation,
        "next_gate":"BUILD_DETERMINISTIC_DEVELOPMENT_RECORD_INDEX" if (not missing and len(canonical_rows)==80000) else "REVIEW_METADATA_ARCHIVE_RECONCILIATION",
    }
    result["inspection_evidence_sha256"]=canonical_hash(result)
    return result
