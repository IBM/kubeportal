FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /app/kubeportal

FROM alpine
COPY --from=builder /app/kubeportal /app/kubeportal
ENTRYPOINT ["/app/kubeportal"]
