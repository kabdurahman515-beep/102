# Railway build: use the reviewed, version-controlled source files in this repository.
# Do not overlay the older approval ZIP: it contains stale Dart files and
# can silently replace newer fixes during the image build.
ARG DART_VERSION=stable
FROM dart:${DART_VERSION}
WORKDIR /app

COPY . .
RUN dart pub get
RUN mkdir -p /data
ENV DATA_DIR=/data
EXPOSE 8080
CMD ["dart", "run", "bin/server.dart"]
