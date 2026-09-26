from __future__ import annotations
import argparse, json
from pathlib import Path
from .stage_c_feature_extraction_authorization import *
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--experiment-contract",type=Path,required=True)
    p.add_argument("--feature-semantics",type=Path,required=True)
    p.add_argument("--split-contract",type=Path,required=True)
    p.add_argument("--split-manifest",type=Path,required=True)
    p.add_argument("--output-root",type=Path,required=True)
    a=p.parse_args()
    try:
        reg,auth=register_and_authorize(
            experiment_contract=load_json(a.experiment_contract),
            feature_semantics=load_json(a.feature_semantics),
            split_contract=load_json(a.split_contract),
            split_manifest=load_json(a.split_manifest))
        rp=a.output_root/"development-split-registration.json"
        ap=a.output_root/"feature-extraction-authorization.json"
        states={"registration":frozen_write_json(rp,reg),"authorization":frozen_write_json(ap,auth)}
    except Exception as exc:
        print(json.dumps({"status":"FAIL","error":str(exc)},indent=2)); return 2
    print(json.dumps({
        "status":"PASS","registered_split_state":reg["registered_split_state"],
        "authorized_partitions":auth["scope"]["authorized_partitions"],
        "authorized_sample_count":auth["scope"]["authorized_sample_count"],
        "feature_version":auth["feature_contract"]["source_feature_version"],
        "feature_count":auth["feature_contract"]["feature_count"],
        "prohibited_model_observables":auth["feature_contract"]["prohibited_model_observables"],
        "feature_extraction_authorized":True,"model_training_authorized":False,
        "model_selection_authorized":False,"calibration_fitting_authorized":False,
        "threshold_selection_authorized":False,"model_scoring_authorized":False,
        "final_holdout_touched":False,
        "registration_sha256":reg["registration_sha256"],
        "authorization_sha256":auth["authorization_sha256"],
        "states":states,
        "outputs":{"registration":str(rp),"authorization":str(ap)},
        "next_gate":auth["next_gate"],
    },indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())
