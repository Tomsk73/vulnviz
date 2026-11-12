# vulnviz developer entry points. See README.md for the full walkthrough.
DATABASE_URL ?= postgres://vulnviz:vulnviz@localhost:5433/vulnviz?sslmode=disable
export DATABASE_URL
TAG ?= dev
KIND_CLUSTER ?= vulnviz

.PHONY: build test run-api run-web db-up db-down ingest-all ingest-cve ingest-advisories ingest-sync aggregate images kind-up kind-load kind-deploy kind-bootstrap kind-down manifests

build:            ## Build the Go binaries into bin/
	go build -o bin/api ./cmd/api
	go build -o bin/ingest ./cmd/ingest

test:             ## Unit tests and type-check the frontend
	go test ./...
	go vet ./...
	cd web && npx tsc -b

db-up:            ## Start a local PostgreSQL (Chainguard image) on :5433
	docker run -d --name vulnviz-pg -e POSTGRES_PASSWORD=vulnviz -e POSTGRES_USER=vulnviz -e POSTGRES_DB=vulnviz \
	  -p 5433:5432 -v vulnviz-pgdata:/var/lib/postgresql/data cgr.dev/chainguard/postgres:latest \
	  -c shared_buffers=1GB -c work_mem=256MB -c maintenance_work_mem=512MB -c max_wal_size=4GB

db-down:          ## Stop and remove the local PostgreSQL container (data volume is kept)
	docker rm -f vulnviz-pg

run-api: build    ## Run the API on :8080 against DATABASE_URL
	./bin/api

run-web:          ## Run the Vite dev server on :5173 (proxies /api to :8080)
	cd web && npm install && npm run dev

ingest-all: build ## Full load: CVE list, every enabled distro, then aggregate
	./bin/ingest all

ingest-cve: build
	./bin/ingest cve

ingest-advisories: build
	./bin/ingest advisories $(DISTROS)

ingest-sync: build
	./bin/ingest sync $(DISTROS)

aggregate: build  ## Rebuild derived tables only
	./bin/ingest aggregate

images:           ## Build the three container images (tag: $(TAG))
	docker build -f build/Dockerfile.api     -t vulnviz-api:$(TAG) .
	docker build -f build/Dockerfile.ingest  -t vulnviz-ingest:$(TAG) .
	docker build -f build/Dockerfile.web     -t vulnviz-web:$(TAG) .

deploy/k8s/base/sources.yaml: configs/sources.yaml  ## kustomize can only read files under its own directory
	cp configs/sources.yaml deploy/k8s/base/sources.yaml

manifests: deploy/k8s/base/sources.yaml ## Render the kind overlay to stdout
	kubectl kustomize deploy/k8s/overlays/kind

kind-up:          ## Create a local kind cluster with port 30080 mapped to localhost:8000
	kind create cluster --name $(KIND_CLUSTER) --config hack/kind.yaml

kind-load: images ## Load locally built images into kind
	kind load docker-image vulnviz-api:$(TAG) vulnviz-ingest:$(TAG) vulnviz-web:$(TAG) --name $(KIND_CLUSTER)

kind-deploy: deploy/k8s/base/sources.yaml ## Apply the kind overlay (db, api, web, cronjobs; bootstrap job starts the full load)
	kubectl apply -k deploy/k8s/overlays/kind
	kubectl -n vulnviz rollout status statefulset/vulnviz-db --timeout=180s
	kubectl -n vulnviz rollout status deployment/vulnviz-api --timeout=180s
	kubectl -n vulnviz rollout status deployment/vulnviz-web --timeout=180s
	@echo "Open http://localhost:8000 once the bootstrap job has finished: kubectl -n vulnviz logs -f job/vulnviz-ingest-bootstrap"

kind-down:
	kind delete cluster --name $(KIND_CLUSTER)
