.ONESHELL:

.PHONY: install

clean:
	rm -rf .venv

install: clean
	python3 -m venv .venv
	. .venv/bin/activate
	pip3 install boto3