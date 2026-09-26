
from __future__ import annotations
import argparse, json
from pathlib import Path
from .stage_c_corpus_inspection import StageCCorpusInspectionError, inspect_development_corpus, load_json

def frozen_write(path: Path, value: dict) -> str:
    rendered=json.dumps(value,indent=2,sort_keys=True)+"\n"
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        existing=json.loads(path.read_text(encoding="utf-8"))
        if existing!=value:
            raise StageCCorpusInspectionError(f"refusing to replace non-identical frozen Task-5 report: {path}")
        return "EXISTING_MATCH"
    path.write_text(rendered,encoding="utf-8")
    return "CREATED"

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--archive",type=Path,required=True)
    p.add_argument("--seal",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    try:
        result=inspect_development_corpus(archive_path=a.archive,seal=load_json(a.seal))
        state=frozen_write(a.output,result)
    except (OSError,ValueError,StageCCorpusInspectionError) as exc:
        print(json.dumps({"status":"FAIL","error":str(exc)},indent=2)); return 2
    r=result["reconciliation"]
    print(json.dumps({
        "status":"PASS","inspection_mode":result["inspection_mode"],
        "tables":result["index_sql"]["create_table_count"],
        "metadata_rows":r["metadata_rows"],"class_counts":r["class_counts"],
        "metadata_unique_websites":r["metadata_unique_website_filenames"],
        "archive_html_files":result["aggregate"]["html_files"],
        "archive_unique_html_basenames":r["archive_unique_html_basenames"],
        "missing_html":r["metadata_missing_html_count"],"extra_html":r["archive_extra_html_count"],
        "created_date_min":r["created_date_min"],"created_date_max":r["created_date_max"],
        "inspection_evidence_sha256":result["inspection_evidence_sha256"],
        "model_training_authorized":False,"extraction_authorized":False,"final_holdout_touched":False,
        "state":state,"output":str(a.output),"next_gate":result["next_gate"],
    },indent=2)); return 0

if __name__=="__main__":
    raise SystemExit(main())
