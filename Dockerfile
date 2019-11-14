FROM ubuntu:18.04

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y git curl pkg-config libncurses5-dev libpcre3-dev

RUN curl -sSL https://get.haskellstack.org/ | sh

WORKDIR /data

COPY . /data

RUN stack install --local-bin-path bin

FROM ubuntu:18.04

# auto install ca by curl
RUN apt-get update && apt-get install -y libatomic1 curl

COPY --from=0 /data/bin/* /usr/bin/
COPY config-dev.yml /config.yml
COPY services-dev.yml /services-dev.yml

ENTRYPOINT ["/usr/bin/yuntan-mqtt"]

CMD ["broker", "-c", "/config.yaml"]
