# Railway build: extract the approved backend source archive before building.
ARG DART_VERSION=stable
FROM dart:${DART_VERSION}
WORKDIR /app

# The repository stores the approved backend as a ZIP. Extract it over the
# repository snapshot so Railway builds the uploaded source, not stale root files.
COPY . .
RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip \
    && unzip -o Universal_Device_Agent_Backend_Approval_BUILD_FIXED.zip -d /app \
    && rm -f Universal_Device_Agent_Backend_Approval_BUILD_FIXED.zip \
    && rm -rf /var/lib/apt/lists/*

RUN dart pub get
RUN mkdir -p /data
ENV DATA_DIR=/data
EXPOSE 8080
CMD ["dart", "run", "bin/server.dart"]
