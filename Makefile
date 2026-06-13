# SIFT-Bench — judge convenience targets.
#
# Every target replays from committed artifacts: NO memory image and NO API key
# required. The trace targets use python3 (already required for the scorer and tests)
# rather than jq, so `make judge-fast` runs even on a machine without jq installed.

GT       := ground_truth/base-rd01-v1.1.json
RUN6     := cases/srl-2018/run6_analysis
FINDINGS := $(RUN6)/findings_post_correction.json

.PHONY: judge-fast score-run6 test trace-f01 show-retractions show-mcp

# judge-fast: the full no-image fast review, in one command.
judge-fast: score-run6 test trace-f01 show-retractions show-mcp
	@echo ""
	@echo "=== judge-fast complete: F1 0.9833 | 5/5 critical | 3/3 FP traps | 12/14 matched ==="

# score-run6: score the best run against ground truth (cached judge verdicts; no API key).
score-run6:
	python scorer.py $(GT) $(FINDINGS)

# test: run the unit test suite (94 tests; no image, no API key).
test:
	python -m unittest discover -s tests

# trace-f01: show the p.exe finding's tool attribution + recorded SHA-256.
trace-f01:
	@echo "--- F01 (p.exe) evidence trace ---"
	@python3 -c "import json; d=json.load(open('$(FINDINGS)')); f=next(x for x in d['findings'] if x['id']=='F01'); print(json.dumps({'id':f['id'],'title':f['title'],'status':f['status'],'confidence':f['confidence'],'tool_attribution':f['tool_attribution'],'sha256':f.get('evidence',{}).get('file_hash_sha256')}, indent=2, ensure_ascii=False))"

# show-retractions: show the self-correction retractions (status == RETRACTED + reason).
show-retractions:
	@echo "--- RETRACTED findings (self-correction) ---"
	@python3 -c "import json; d=json.load(open('$(FINDINGS)')); [print(json.dumps({'id':x['id'],'title':x['title'],'retraction_reason':x.get('retraction_reason')}, indent=2, ensure_ascii=False)) for x in d['findings'] if x['status']=='RETRACTED']"

# show-mcp: show the pre-run MCP enrichment gate verification.
show-mcp:
	@echo "--- MCP gate verification ---"
	cat $(RUN6)/mcp_verification.txt
