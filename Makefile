.PHONY: test go-test python-test typescript-test integration-test integration-preflight go-integration-test python-integration-test typescript-integration-test clean

test: go-test python-test typescript-test

go-test:
	cd go && go test ./...

python-test:
	cd python && pytest -v

typescript-test:
	cd typescript && npm test

integration-test: integration-preflight go-integration-test python-integration-test typescript-integration-test

integration-preflight:
	@./scripts/preflight-integration.sh

go-integration-test:
	@echo "Running Go SDK integration tests..."
	@cd go && APLANE_SDK_INTEGRATION=1 go test -run Integration -count=1 ./...

python-integration-test:
	@echo "Running Python SDK integration tests..."
	@cd python && APLANE_SDK_INTEGRATION=1 pytest -q tests/test_integration.py

typescript-integration-test:
	@echo "Running TypeScript SDK integration tests..."
	@cd typescript && APLANE_SDK_INTEGRATION=1 node --import tsx --test --test-reporter=dot integration/live_signer.test.ts
	@echo "TypeScript SDK integration tests passed"

clean:
	rm -rf python/.pytest_cache python/build python/dist python/*.egg-info
	rm -rf typescript/dist typescript/*.tgz
