# ── Build stage ───────────────────────────────────────────────────────────────
FROM ruby:3.2-alpine AS builder

WORKDIR /app

RUN apk add --no-cache build-base

# Gem layer cached separately so a code-only change skips re-bundling.
# BUNDLE_WITHOUT=test keeps rspec/rack-test out of the shipped image.
COPY Gemfile Gemfile.lock ./
RUN bundle config set --local without 'test' && \
    bundle install --jobs 4 --retry 3


# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM ruby:3.2-alpine

RUN addgroup -S shallotfacade && \
    adduser -S -G shallotfacade -h /app -s /sbin/nologin shallotfacade

WORKDIR /app

COPY --from=builder /usr/local/bundle /usr/local/bundle

COPY --chown=shallotfacade:shallotfacade VERSION app.rb config.ru ./
COPY --chown=shallotfacade:shallotfacade lib/ ./lib/

ARG SHALLOT_FACADE_VERSION
LABEL org.opencontainers.image.title="shallot-facade" \
      org.opencontainers.image.version="${SHALLOT_FACADE_VERSION}" \
      org.opencontainers.image.description="Shallot-shaped facade in front of Severance"

USER shallotfacade

# 4567 is just the documented default -- app.rb reads SHALLOT_FACADE_PORT/SHALLOT_FACADE_BIND from the
# environment at runtime, so `docker run -e SHALLOT_FACADE_PORT=...` (or docker-compose environment:)
# overrides it.
ENV SHALLOT_FACADE_PORT=4567 SHALLOT_FACADE_BIND=0.0.0.0
EXPOSE 4567

CMD ["sh", "-c", "bundle exec rackup -o ${SHALLOT_FACADE_BIND} -p ${SHALLOT_FACADE_PORT}"]
