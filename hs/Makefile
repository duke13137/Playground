SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

GHC  ?= 9.12
MAIN ?= Main
EXE  := $(shell basename $(MAIN) .Main)

.PHONY: dev exe env hie pg

dev:
	ghciwatch --clear --no-interrupt-reloads \
		--command ghci-$(GHC) \
		--error-file ghcid.txt \
		--enable-eval --watch .

exe:
	mkdir -p .build && ln -sf .build .hiefiles && ln -sf .build .hifiles
	ghc-$(GHC) -threaded -isrc -outputdir .build -main-is $(MAIN) -o .build/$(EXE) $(MAIN)

env:
	rm .ghc.environment.*$(GHC)* || true
	cabal install -w ghc-$(GHC) --allow-newer --enable-documentation \
		--package-env . --lib \
		base containers optics relude template-haskell text vector \
		aeson aeson-optics generic-data safe-wild-cards strict-wrapper \
		hasql hasql-th hasql-pool hasql-transaction stm-containers \
		ihp-hsx lucid2 http-media http-types servant servant-server \
		twain wai wai-extra warp tasty tasty-hunit tasty-wai \
		breakpoint co-log io-classes io-sim ki nothunks rapid

hie:
	hiedb-$(GHC) -D .hiedb index .build

pg:
	docker run --name postgres \
		-e POSTGRES_PASSWORD=$(PGPASSWORD) \
		-p 5432:5432 \
		-d postgres
