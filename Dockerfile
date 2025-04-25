FROM golang:latest as build

WORKDIR /src/
COPY . /src/
RUN go mod download
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -buildmode=plugin -o /usr/lib/olric-consul-plugin.so

FROM ghcr.io/olric-data/olric:latest
COPY --from=build /usr/lib/olric-consul-plugin.so /usr/lib/olric-consul-plugin.so
