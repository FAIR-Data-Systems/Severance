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

# `bundle exec` needs the Gemfile itself present at runtime (to resolve/activate the already-vendored
# gems above), not just the vendored gems -- confirmed live: omitting this fails every run with
# "Could not locate Gemfile", even though /usr/local/bundle has everything bundle install put there.
COPY --chown=shallotfacade:shallotfacade Gemfile Gemfile.lock VERSION app.rb config.ru ./
COPY --chown=shallotfacade:shallotfacade lib/ ./lib/

# net-imap ships as a Ruby "default gem" baked into this base image at whatever version that Ruby
# patch release bundled (0.3.9 here) -- pinning a newer version in the Gemfile (unused by this app;
# pulled in purely to get a patched version) installs it alongside the old one rather than replacing
# it, since Bundler and RubyGems' own default-gem installation use different paths. The stale,
# vulnerable default copy still sits on disk either way; remove it explicitly so it isn't there at
# all. Same fix as external/internal's own Dockerfiles; must run before USER drops root below, since
# removing a system gem needs write access to /usr/local/lib/ruby/gems.
RUN gem uninstall -i /usr/local/lib/ruby/gems/3.2.0 net-imap --all --force || true

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
