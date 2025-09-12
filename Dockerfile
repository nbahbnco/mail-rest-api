
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .


RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-w -s" -o /go-email-api .


FROM alpine:latest

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder /go-email-api /go-email-api

USER appuser

EXPOSE 8080

CMD ["/go-email-api"]