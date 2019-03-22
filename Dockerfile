FROM golang:alpine as builder
RUN apk update && apk add --no-cache git
RUN mkdir /build
ADD . /build
WORKDIR /build
RUN go get -d -v
RUN go build -o rhino64 .
FROM alpine
COPY --from=builder /build/rhino64 /app/
WORKDIR /app
EXPOSE 5353:53/udp
ENTRYPOINT ["./rhino64"]
