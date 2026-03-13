# ── Configuration ────────────────────────────────────────────────
COUNTRY       ?= de
FILTER        ?=
LIMIT         ?=
TEST_MUNICIPALITY ?= Aachen

# Build CLI flags from variables
_COUNTRY_FLAG  = --country $(COUNTRY)
_FILTER_FLAG   = $(if $(FILTER),--filter "$(FILTER)")
_LIMIT_FLAG    = $(if $(LIMIT),--limit $(LIMIT))
_CLI_FLAGS     = $(_COUNTRY_FLAG) $(_FILTER_FLAG) $(_LIMIT_FLAG)

# ── Full pipeline ────────────────────────────────────────────────
.PHONY: all
all: preprocess postprocess validate build-site  ## Run the full pipeline for COUNTRY

# ── Individual steps ─────────────────────────────────────────────
.PHONY: preprocess
preprocess:  ## Fetch Wikidata + scan MX/SPF records
	uv run preprocess $(_CLI_FLAGS)

.PHONY: postprocess
postprocess:  ## Enrich data (SMTP banners, websites, etc.)
	uv run postprocess $(_COUNTRY_FLAG)

.PHONY: validate
validate:  ## Run data quality checks
	uv run validate $(_COUNTRY_FLAG)

.PHONY: build-site
build-site:  ## Generate HTML site
	uv run build-site $(_COUNTRY_FLAG)

# ── Test with a single municipality ─────────────────────────────
.PHONY: test-municipality
test-municipality:  ## Quick test: run pipeline for a single municipality (TEST_MUNICIPALITY=Aachen)
	uv run preprocess $(_COUNTRY_FLAG) --filter "$(TEST_MUNICIPALITY)" --limit 1
	uv run postprocess $(_COUNTRY_FLAG)
	uv run validate $(_COUNTRY_FLAG)
	uv run build-site $(_COUNTRY_FLAG)

# ── Local preview ────────────────────────────────────────────────
.PHONY: serve
serve:  ## Serve the built site locally (http://localhost:8000)
	python3 -m http.server 8000 --directory sites/$(COUNTRY)

# ── Dev tools ────────────────────────────────────────────────────
.PHONY: test
test:  ## Run pytest with coverage
	uv run pytest --cov --cov-report=term-missing

.PHONY: lint
lint:  ## Run ruff linter and formatter check
	uv run ruff check src tests
	uv run ruff format src tests --check

.PHONY: fmt
fmt:  ## Auto-format code with ruff
	uv run ruff format src tests
	uv run ruff check src tests --fix

.PHONY: sync
sync:  ## Install/sync dependencies
	uv sync --group dev

.PHONY: clean
clean:  ## Remove generated site artifacts for COUNTRY
	rm -rf sites/$(COUNTRY)

# ── Help ─────────────────────────────────────────────────────────
.PHONY: help
help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
