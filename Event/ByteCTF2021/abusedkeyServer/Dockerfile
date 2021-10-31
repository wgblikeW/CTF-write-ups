FROM golang:alpine
RUN apk add build-base

WORKDIR $GOPATH/src/abusedkeyServer

COPY ./go.mod .
COPY ./go.sum .
RUN go env -w GOPROXY="https://goproxy.cn,direct"
RUN go mod download

COPY ./cipherfactory/. .
COPY ./server/. .
COPY ./main.go .
RUN go env -w GO111MODULE="auto"
RUN go build 

ENV IPADDR "0.0.0.0"
ENV PORT ":8080"
ENV PRIVATEKEY "61a218ccaca794cf29e7107287546248a088b9835def635686028f291623ab90"
ENV PUBKEY_C_X "b5b1b07d251b299844d968be56284ef32dffd0baa6a0353baf10c90298dfd117"
ENV PUBKEY_C_Y "ea62978d102a76c3d6747e283091ac5f2b4c3ba5fc7a906fe023ee3bc61b50fe"
ENV SECRET "NiceTasteShouldbeTreasured"

EXPOSE 8080

CMD ["/abusedkeyserver"]