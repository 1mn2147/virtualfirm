PYTHON ?= python3
PYTHONPATH := src

.PHONY: sample analyze run extract infer emulate loop report validate test lint compile

sample:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m firmware_mvp.cli init-sample --out samples/demo_firmware.bin

analyze:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m firmware_mvp.cli analyze samples/demo_firmware.bin --device stm32f1 --out runs/demo

run:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m firmware_mvp.cli run samples/demo_firmware.bin --device stm32f1 --out runs/demo --probe-address 0x40011000

extract:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m firmware_mvp.cli extract samples/demo_firmware.bin --out runs/staged

infer:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m firmware_mvp.cli infer runs/staged/context.json --device stm32f1 --out runs/staged

emulate:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m firmware_mvp.cli emulate runs/staged/emulator_config.json --out runs/staged --probe-address 0x40011000

loop:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m firmware_mvp.cli loop runs/demo/emulator_config.json --out runs/loop-demo --probe-address 0x50000000 --access write --pc 0x08000120

report:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m firmware_mvp.cli report runs/demo --source-command "make report"

validate:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m firmware_mvp.cli validate runs/demo

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m unittest discover -s tests -q

lint:
	$(PYTHON) -m ruff check .

compile:
	$(PYTHON) -m compileall -q src
