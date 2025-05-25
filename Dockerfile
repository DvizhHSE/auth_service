FROM golang:1.24

WORKDIR /app 

COPY . .

RUN go build -o auth_service  /app/cmd/auth_service/ 

CMD [ "./auth_service",  "-config", "/app/config/config.yaml" ]