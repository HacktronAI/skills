FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=off

COPY go.mod ./
COPY *.go ./
COPY coraza.conf ./

RUN go mod tidy && CGO_ENABLED=0 go build -o waf-proxy main.go

FROM alpine:3.19

WORKDIR /app
COPY --from=builder /app/waf-proxy .
COPY coraza.conf .

EXPOSE 9090

CMD ["./waf-proxy"]
