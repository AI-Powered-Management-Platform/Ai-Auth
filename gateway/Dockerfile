# Build
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway

# Run: distroless static, nonroot — no shell, no package manager, nothing
# to live off. Read-only fs and dropped capabilities come from compose.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gateway /gateway
ENTRYPOINT ["/gateway"]
