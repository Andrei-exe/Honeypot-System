# ---------- Etapa 1: compilam ----------
# Imaginea cu Go (~300MB) e folosita DOAR aici; nu ajunge in imaginea finala.
FROM golang:1.27-alpine AS build
WORKDIR /src

# Intai doar go.mod + go.sum: Docker tine minte (cache) pasul cu bibliotecile descarcate
# si nu-l mai repeta la fiecare build, cat timp nu schimbi dependentele.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 = binar static (nu are nevoie de nicio librarie C) -> merge pe o imagine goala.
# -trimpath -ldflags="-s -w" = fara caile de pe PC-ul tau si fara info de debug -> binar mai mic.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/honeypot-agent .

# Folderul pentru date (cheia SSH). Il facem aici pentru ca in etapa 2 nu exista shell, deci nici mkdir.
RUN mkdir -p /out/data

# ---------- Etapa 2: ce ruleaza efectiv ----------
# distroless/static = aproape gol: fara shell, fara apt, fara curl. Doar binarul nostru.
FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=build /out/honeypot-agent /honeypot-agent

# /data e al userului nonroot (65532), ca agentul sa poata scrie acolo cheia SSH.
# In docker-compose.yml montam un volum peste el -> cheia ramane aceeasi si dupa rebuild.
COPY --from=build --chown=65532:65532 /out/data /data

# Agentul cauta/scrie cheia SSH in folderul curent -> folderul curent e /data.
WORKDIR /data
USER 65532:65532

# Porturile pe care asculta agentul IN container (vezi main.go).
EXPOSE 2121 2222 2323 8080

ENTRYPOINT ["/honeypot-agent"]
