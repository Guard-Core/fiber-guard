# Build context is the repository root (see docker-compose.yml):
#   docker build -f examples/advanced_app/Dockerfile .
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

# The adapter package lives at the repository root (package fiber); the example
# is a second package tree inside the same module.
COPY middleware.go request.go ./
COPY examples/advanced_app/ examples/advanced_app/

RUN CGO_ENABLED=0 go build -trimpath -o /out/server ./examples/advanced_app/cmd/server

FROM alpine:3.22

RUN addgroup -S guard && adduser -S -G guard guard

COPY --from=build /out/server /usr/local/bin/server

USER guard

EXPOSE 8080

ENTRYPOINT ["server"]
