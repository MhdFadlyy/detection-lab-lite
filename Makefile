.PHONY: bootstrap up down status logs attack verify verify-all report lint docs-serve

bootstrap: ; ./lab bootstrap
up:        ; ./lab up
down:      ; ./lab down
status:    ; ./lab status
logs:      ; ./lab logs
report:    ; ./lab report

attack:    ; ./lab attack $(T)
verify:    ; ./lab verify $(T)
verify-all:; python3 harness/verify.py --all

lint:
	ruff check harness/
	yamllint -d relaxed detections/ attacks/
	@command -v sigma >/dev/null && sigma check detections/ || echo "sigma-cli not installed, skipping"

docs-serve:
	mkdocs serve
