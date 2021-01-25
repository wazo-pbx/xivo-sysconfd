test-setup: egg-info sysconfd sysconfd-test db

test:
	pytest -x

egg-info:
	cd .. && python setup.py egg_info

sysconfd:
	docker build -t wazoplatform/xivo-sysconfd ..

sysconfd-test: egg-info
	docker build --no-cache -t xivo-sysconfd-test -f Dockerfile-sysconfd ..

db:
	docker build -f ../contribs/docker/Dockerfile-db -t wazoplatform/xivo-sysconfd-db ..

.PHONY: test-setup test egg-info sysconfd sysconfd-test
