FROM golang:1.16-alpine as build

WORKDIR /src
COPY . .

RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/flood-webauthn

# build image
FROM alpine:latest

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    app

COPY --from=build /app/flood-webauthn /app/flood-webauthn
COPY --from=build /src/static /app/static

RUN mkdir /users/ && chown app:app /users/

USER app:app

CMD ["--userdb-directory", "/users/"]
ENTRYPOINT /app/flood-webauthn
