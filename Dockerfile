FROM adoptopenjdk/openjdk11:x86_64-alpine-jre-11.0.3_7

ENV ES_TMPDIR "/tmp"
ENV ES_VERSION 7.2.0
ENV DOWNLOAD_URL "https://artifacts.elastic.co/downloads/elasticsearch"
ENV ES_TARBALL "${DOWNLOAD_URL}/elasticsearch-${ES_VERSION}-linux-x86_64.tar.gz"
#ENV ES_TARBALL_ASC "${DOWNLOAD_URL}/elasticsearch-${ES_VERSION}.tar.gz.asc"
ENV GPG_KEY "46095ACC8548582C1A2699A9D27D666CD88E42B4"
ENV PATH /elasticsearch/bin:$PATH

# Install Elasticsearch.
RUN apk add --no-cache --update bash ca-certificates su-exec util-linux curl openssl rsync tar gzip
RUN apk add --no-cache -t .build-deps gnupg \
  && mkdir /install \
  && cd /install \
  && echo "===> Install Elasticsearch..." \
  && curl -k -o elasticsearch.tar.gz -Lskj "$ES_TARBALL"; \
  if [ "$ES_TARBALL_ASC" ]; then \
    curl -k -o elasticsearch.tar.gz.asc -Lskj "$ES_TARBALL_ASC"; \
    export GNUPGHOME="$(mktemp -d)"; \
    gpg --keyserver ha.pool.sks-keyservers.net --recv-keys "$GPG_KEY"; \
    gpg --batch --verify elasticsearch.tar.gz.asc elasticsearch.tar.gz; \
    rm -r "$GNUPGHOME" elasticsearch.tar.gz.asc; \
  fi; \
  tar -xvf elasticsearch.tar.gz \
  && mv elasticsearch-$ES_VERSION /elasticsearch \
  && rm -rf /elasticsearch/modules/x-pack-ml/platform/linux-x86_64 \
  && rm -rf /install \
  && adduser -DH -s /sbin/nologin elasticsearch

ADD ./plugins/elastic-auth-plugin*.zip /plugins/elastic-auth-plugin.zip

RUN echo "===> Installing auth plugin..." \
  && /elasticsearch/bin/elasticsearch-plugin install -b "file:///plugins/elastic-auth-plugin.zip"
RUN apk del --purge .build-deps

RUN mkdir -p /.backup/elasticsearch/
COPY config /.backup/elasticsearch/config
RUN cp -f /.backup/elasticsearch/config/elasticsearch.yml /elasticsearch/config/elasticsearch.yml \
  && cp -f /.backup/elasticsearch/config/jvm.options /elasticsearch/config/jvm.options

RUN mkdir -p /elasticsearch/data /elasticsearch/logs 
RUN chown -R elasticsearch:elasticsearch /elasticsearch 
VOLUME /elasticsearch/data /elasticsearch/logs

EXPOSE 9200 9300

USER elasticsearch
ENTRYPOINT ["elasticsearch"]
