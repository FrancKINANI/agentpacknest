# syntax=docker/dockerfile:1

# --- Chef ------------------------------------------------------------------
# cargo-chef turns the dependency set into a stable "recipe" so that the
# expensive compile of third-party crates is cached until Cargo.toml or
# Cargo.lock actually change.
FROM rust:1-bookworm AS chef
# The base image ships a version-pinned toolchain, while rust-toolchain.toml
# asks for the `stable` channel. Install that channel here once so it lands in
# a cached layer instead of being re-downloaded inside the source-build layer
# on every rebuild.
RUN rustup toolchain install stable --profile minimal \
    --component clippy --component rustfmt
RUN cargo install cargo-chef --locked
WORKDIR /app

# --- Planner ---------------------------------------------------------------
# Computes recipe.json describing the dependency graph.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- Builder ---------------------------------------------------------------
# Cook the recipe (deps only), then build the binary. Only the final COPY
# layer is invalidated when application source changes.
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --bin pn

# --- Runtime ---------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN useradd --create-home --uid 10001 pn
COPY --from=builder /app/target/release/pn /usr/local/bin/pn
USER pn
ENTRYPOINT ["pn"]
