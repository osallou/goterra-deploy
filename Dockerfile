FROM golang:1.11

LABEL maintainer="Olivier Sallou <olivier.sallou@irisa.fr>"

# Set the Current Working Directory inside the container
WORKDIR $GOPATH/src/github.com/osallou/goterra-deploy

# Copy everything from the current directory to the PWD(Present Working Directory) inside the container
COPY . .
RUN go get -u github.com/golang/dep/cmd/dep
#RUN go get -d -v ./...
RUN dep ensure

# Install the package
RUN go build -o goterra-deploy -ldflags "-X  main.Version=`git rev-parse --short HEAD`"
RUN cp goterra-deploy.yml.example goterra.yml

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
COPY --from=0 /go/src/github.com/osallou/goterra-deploy/goterra.yml .
COPY --from=0 /go/src/github.com/osallou/goterra-deploy/goterra-deploy .
CMD ["./goterra-deploy"]
