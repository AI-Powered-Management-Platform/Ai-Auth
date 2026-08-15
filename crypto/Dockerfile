# Build. aws-lc's C code compiles here; the runtime stage carries none of it.
# bookworm builder to match distroless cc-debian12's glibc — a newer
# builder produces a binary the runtime image cannot load.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked

# Run: distroless cc (glibc only), nonroot. The design target is `scratch`
# with a fully static binary — that lands with the musl/static build pass;
# cc-distroless is the honest interim: still no shell, no busybox, nothing.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/aiauth-crypto /crypto
ENTRYPOINT ["/crypto"]
