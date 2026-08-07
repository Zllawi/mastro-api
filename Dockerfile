FROM dart:stable AS build

WORKDIR /app

COPY pubspec.* ./
RUN dart pub get

COPY . .
RUN dart pub get --offline
RUN dart compile exe server/http_server.dart -o /app/bin/mastro_api

FROM dart:stable

WORKDIR /app
COPY --from=build /app/bin/mastro_api /app/bin/mastro_api

ENV HOST=0.0.0.0

CMD ["/app/bin/mastro_api"]
