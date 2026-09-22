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

# net-imap, erb, and resolv all ship as Ruby "default gems" baked into this base image at whatever
# version that Ruby patch release bundled -- pinning a newer version in the Gemfile (unused by this
# app; pulled in purely to get a patched version) installs it alongside the old one rather than
# replacing it, since Bundler and RubyGems' own default-gem installation use different paths. Attempt
# to remove each stale default copy explicitly so it isn't there at all; must run before USER drops
# root below, since removing a system gem needs write access to /usr/local/lib/ruby/gems. Confirmed
# live: net-imap is a pure-Ruby default gem and uninstalls cleanly. erb and resolv are *compiled*
# default gems (same category as external/Dockerfile's json) and refuse uninstall outright ("cannot
# be uninstalled because it is a default gem") -- `|| true` lets the build continue rather than fail
# on that. Their stale, vulnerable copies stay physically present on disk (Trivy will likely keep
# flagging them by filesystem presence), but `bundle exec` -- the only way this app ever runs, see the
# CMD below -- correctly resolves the newer Bundler-managed copy first, so the pin is still real and
# effective for anything this process actually loads at runtime.
RUN gem uninstall -i /usr/local/lib/ruby/gems/3.2.0 net-imap --all --force || true
RUN gem uninstall -i /usr/local/lib/ruby/gems/3.2.0 erb --all --force || true
RUN gem uninstall -i /usr/local/lib/ruby/gems/3.2.0 resolv --all --force || true

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
