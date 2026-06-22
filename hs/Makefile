SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

GHC  ?= 9.12
MAIN ?= Main
EXE  := $(shell basename $(MAIN) .Main)

.PHONY: dev exe env pg

dev:
	ghciwatch --clear --no-interrupt-reloads \
		--command ghci-$(GHC) \
		--error-file ghcid.txt \
		--restart-glob Makefile \
		--restart-glob .ghc.environment.* \
		--enable-eval --watch .

exe:
	mkdir -p .build && ln -sf .build .hiefiles && ln -sf .build .hifiles
	ghc-$(GHC) -threaded -isrc -outputdir .build -main-is $(MAIN) -o .build/$(EXE) $(MAIN)

env:
	rm .ghc.environment.*$(GHC)* || true
	cabal install -w ghc-$(GHC) --allow-newer --enable-documentation \
		--package-env . --lib \
		base relude containers stm-containers text vector template-haskell \
		aeson aeson-optics generic-data optics witch safe-wild-cards strict-wrapper \
		hasql hasql-th hasql-dynamic-statements hasql-pool hasql-postgresql-types postgresql-types \
		http-api-data http-types ihp-hsx ihp-router lucid2 servant servant-server wai wai-extra warp \
		bluefin co-log co-log-core fast-logger ki mtl io-classes io-sim grace \
		breakpoint nothunks rapid tasty tasty-hunit tasty-html tasty-silver tasty-wai

pg:
	docker run --name postgres \
		-e POSTGRES_PASSWORD=$(PGPASSWORD) \
		-p 5432:5432 \
		-d postgres
