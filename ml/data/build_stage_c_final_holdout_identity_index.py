from __future__ import annotations
import argparse, json
from pathlib import Path
from .stage_c_final_holdout_identity_index import StageCFinalHoldoutIdentityIndexError, build_final_holdout_identity_index, frozen_write_json
ROOT = Path(__file__).resolve().parents[2]
def main() -> int:
    p=argparse.ArgumentParser(description='Build privacy-reduced CompPhish v3 final-holdout identity index')
    p.add_argument('--task28-seal',type=Path,required=True); p.add_argument('--html-archive',type=Path,required=True); p.add_argument('--mapping-workbook',type=Path,required=True); p.add_argument('--output-root',type=Path,required=True); a=p.parse_args()
    try:
        index,report=build_final_holdout_identity_index(repo_root=ROOT,task28_seal_path=a.task28_seal,html_archive_path=a.html_archive,mapping_workbook_path=a.mapping_workbook)
        ip=a.output_root/'final-holdout-identity-index-v1.json'; rp=a.output_root/'final-holdout-mapping-schema-report-v1.json'
        ist=frozen_write_json(ip,index); rst=frozen_write_json(rp,report)
    except (OSError,ValueError,StageCFinalHoldoutIdentityIndexError) as exc:
        print(json.dumps({'status':'FAIL','error':str(exc)},indent=2)); return 2
    print(json.dumps({'status':'PASS','identity_index':str(ip),'identity_index_state':ist,'schema_report':str(rp),'schema_report_state':rst,
        'sample_count':index['sample_count'],'class_counts':index['class_counts'],'headers':report['headers'],'resolved_columns':report['resolved_columns'],
        'record_set_sha256':index['record_set_sha256'],'index_identity_sha256':index['index_identity_sha256'],
        'exact_html_duplicate_groups_within_holdout':report['exact_html_duplicate_groups_within_holdout'],
        'normalized_url_duplicate_groups_within_holdout':report['normalized_url_duplicate_groups_within_holdout'],
        'raw_urls_persisted':index['raw_urls_persisted'],'mapping_labels_accessed_for_identity_index':index['mapping_labels_accessed_for_identity_index'],
        'html_features_extracted':index['html_features_extracted'],'model_scoring_performed':index['model_scoring_performed'],'next_gate':index['next_gate']},indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
