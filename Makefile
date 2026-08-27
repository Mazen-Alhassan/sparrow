.PHONY: run test demo superset prompts verify score labels graph clean

TARGET ?= targets/superset
SUPERSET_TAG ?= 3.1.0

run:
	python3 -m src.cli scan --target data/sample --out data/results-sample.json \
		--sinks data/sinks --name sample-report-service

test:
	python3 -m pytest tests/ -q

superset: $(TARGET)
	python3 -m src.cli scan --target $(TARGET) --lockfile $(TARGET)/requirements/base.txt \
		--out data/results.json --sinks data/sinks --name "Apache Superset $(SUPERSET_TAG)"

$(TARGET):
	git clone --depth 1 --branch $(SUPERSET_TAG) https://github.com/apache/superset.git $(TARGET)

prompts: $(TARGET)
	python3 -m src.cli prompts --target $(TARGET) --lockfile $(TARGET)/requirements/base.txt \
		--out data/prompts --mode advisory+patch --missing-only

verify: $(TARGET)
	python3 -m src.cli verify --target $(TARGET) --lockfile $(TARGET)/requirements/base.txt \
		--sinks data/sinks

labels: $(TARGET)
	python3 tools/label.py --target $(TARGET) --lockfile $(TARGET)/requirements/base.txt \
		--out docs/labels --limit 30

score:
	python3 tools/score.py --sinks data/sinks --mode advisory+patch \
		--json docs/labels/score-advisory-patch.json
	@echo
	python3 tools/score.py --sinks data/sinks-advisory-only --mode advisory-only \
		--json docs/labels/score-advisory-only.json

graph: $(TARGET)
	python3 tools/graph_report.py --target $(TARGET) \
		--lockfile $(TARGET)/requirements/base.txt --skip-tests \
		--json docs/graph-failures.json

demo:
	vhs demo.tape

hero: $(TARGET)
	bash docs/capture.sh

clean:
	rm -rf .pytest_cache tests/__pycache__ src/__pycache__ src/sparrow/__pycache__
