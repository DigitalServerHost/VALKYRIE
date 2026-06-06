.PHONY: build test compile-circuits clean

# Default target
all: build

# Build the valkyrie binary
build:
	@echo "🛠️ Compiling valkyrie daemon..."
	@mkdir -p build
	go build -o build/valkyrie cmd/valkyrie-proxy/main.go
	@echo "✅ valkyrie successfully compiled to build/valkyrie"

# Run tests
test: build
	@echo "🧪 Running VALKYRIE unit tests..."
	go test -v ./...
	@echo "🧪 Running VALKYRIE proxy integration test..."
	./build/valkyrie --mode=test --port=9005

# Compile R1CS/AIR and Range circuits (stubs for future implementation)
compile-circuits:
	@echo "⚡ Compiling ZK and Range-Bounded arithmetic circuits..."
	@python3 -m json.tool circuits/digital_exact/constraints.json > /dev/null && echo "✅ digital_exact constraints are valid JSON"
	@python3 -m json.tool circuits/analog_range/constraints.json > /dev/null && echo "✅ analog_range constraints are valid JSON"

# Clean compiled artifacts
clean:
	@echo "🧹 Cleaning VALKYRIE build targets..."
	rm -rf build
	@echo "✨ Clean completed"

