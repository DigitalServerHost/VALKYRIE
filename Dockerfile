# Stage 1: Build the VALKYRIE Go binary
FROM golang:1.23-bookworm AS builder

WORKDIR /workspace

# Copy both modules for local replacement resolution
COPY ORCHID/go.mod ORCHID/
COPY VALKYRIE/go.mod VALKYRIE/

# Copy application sources
COPY ORCHID/ ORCHID/
COPY VALKYRIE/ VALKYRIE/

# Build standalone static binary
WORKDIR /workspace/VALKYRIE
RUN go build -ldflags="-s -w" -o build/valkyrie cmd/valkyrie-proxy/main.go

# Stage 2: Distroless hardened runtime stage
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /
COPY --from=builder /workspace/VALKYRIE/build/valkyrie /valkyrie
COPY --from=builder /workspace/VALKYRIE/circuits /circuits

EXPOSE 9001

ENTRYPOINT ["/valkyrie"]
CMD ["--mode=server", "--port=9001"]
