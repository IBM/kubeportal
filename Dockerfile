FROM golang:1.25-alpine3.22 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /app/kubeportal

FROM alpine:3.22
COPY --from=builder /app/kubeportal /app/kubeportal
RUN apk --no-cache upgrade ca-certificates-bundle
ENTRYPOINT ["/app/kubeportal"]
