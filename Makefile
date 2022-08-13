.PHONY: all
all: dist

dist: node_modules $(wildcard src/*)
	yarn esbuild src/index.ts \
		--bundle \
		--format=esm \
		--outfile=dist/index.mjs

.PHONY: clean
clean:
	rm -rf dist

.PHONY: distclean
distclean: clean
	rm -rf node_modules

node_modules:
	yarn install


.PHONY: dev
dev:
	yarn miniflare -w --wrangler-env dev
	#yarn tsc -w --noEmit

.PHONY: test
test:
	NODE_OPTIONS=--experimental-vm-modules yarn jest --watchAll --runInBand