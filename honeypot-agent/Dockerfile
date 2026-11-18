# ---------- Stage 1: build ----------
# The Go image (~300MB) is used only here; it does not end up in the final image.
FROM golang:1.27-alpine AS build
WORKDIR /src

# go.mod + go.sum first: Docker caches the download step until the dependencies change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 = static binary (needs no C library) -> runs on an empty image.
# -trimpath -ldflags="-s -w" = no local paths and no debug info -> smaller binary.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/honeypot-agent .

# Data folder (SSH key). Created here because stage 2 has no shell, so no mkdir either.
RUN mkdir -p /out/data

# ---------- Stage 2: what actually runs ----------
# distroless/static = almost empty: no shell, no package manager, no curl. Just our binary.
FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=build /out/honeypot-agent /honeypot-agent

# /data belongs to the nonroot user (65532), so the agent can write the SSH key there.
# docker-compose.yml mounts a volume over it -> the key stays the same after a rebuild.
COPY --from=build --chown=65532:65532 /out/data /data

# The agent reads/writes the SSH key in the current directory -> the current directory is /data.
WORKDIR /data
USER 65532:65532

# Ports the agent listens on INSIDE the container (see main.go).
EXPOSE 2121 2222 2323 8080

ENTRYPOINT ["/honeypot-agent"]
