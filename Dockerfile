ARG ARCH="amd64"
ARG OS="linux"
FROM golang:1.23 AS builder

COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG ARCH="amd64"
ARG OS="linux"
RUN CGO_ENABLED=0 GOOS=${OS} GOARCH=${ARCH} go build -a -o .build/${OS}-${ARCH}/blackbox_exporter .

FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

ARG ARCH="amd64"
ARG OS="linux"
COPY --from=builder /go/.build/${OS}-${ARCH}/blackbox_exporter  /bin/blackbox_exporter
COPY blackbox.yml       /etc/blackbox_exporter/config.yml

EXPOSE      9115
ENTRYPOINT  [ "/bin/blackbox_exporter" ]
CMD         [ "--config.file=/etc/blackbox_exporter/config.yml" ]
