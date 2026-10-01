# Build context is the repository root (see docker-compose.yml):
#   docker build -f examples/simple_app/Dockerfile .
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

# The adapter package lives at the repository root (package fiber); the example
# is a second package inside the same module.
COPY middleware.go request.go ./
COPY examples/simple_app/ examples/simple_app/

RUN CGO_ENABLED=0 go build -trimpath -o /out/simple_app ./examples/simple_app

FROM alpine:3.22

RUN adduser -D -H guard

COPY --from=build /out/simple_app /usr/local/bin/simple_app

USER guard

EXPOSE 8080

ENTRYPOINT ["simple_app"]
