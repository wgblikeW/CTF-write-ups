FROM golang:alpine
RUN apk add build-base

WORKDIR /server

COPY ./gomod .
COPY ./go.sum .
RUN go mod download

COPY ./server/. .
COPY ./main.go .


EXPOSE 8080

CMD ["/abusedkeyserver"]