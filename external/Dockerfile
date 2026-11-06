# Two stages: native gems are compiled in `build`, and only the installed gems
# are copied into the runtime image. build-essential (gcc, libc6-dev, dpkg-dev,
# perl, and linux-libc-dev -- 2,500+ kernel header files) is needed to compile
# gems, never to run them. Leaving it in the runtime image was the source of
# most of this image's Trivy findings (182 of 243 on 2026-11-06, including
# every CRITICAL) -- kernel CVEs reported against header files that contain no
# executable code, in a container that runs the host's kernel anyway.
FROM ruby:3.2-slim AS build

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install --jobs 4 --retry 3

# Plain public image, not a "hardened" vendor variant -- real-world security
# scan comparisons (own patching pipeline: shell in, OS-level upgrade,
# recommit) showed better results from this than from Docker Hardened
# Images, so that's the deliberate choice here, not an oversight.
FROM ruby:3.2-slim

# gosu (for dropping privileges safely) -- the only package the runtime needs
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user/group. UID is pinned to 1000 (matching
# internal/Dockerfile's own convention) because entrypoint.sh chowns the
# mounted volumes to ${UID:-1000}:${GID:-1000} before gosu drops privileges
# to this user -- without an explicit UID here, useradd auto-assigns one
# from the system range (999, confirmed live), leaving the app running as
# a different UID than the one its own entrypoint just chowned the volumes
# to, and unable to write to /data/queue or /data/results at all.
RUN groupadd -r -g 1000 severance && \
    useradd -r -u 1000 -g severance -d /app -s /sbin/nologin -c "Docker app user" severance

WORKDIR /app

# Gems as installed (and compiled) by the build stage; /usr/local/bundle is the
# official ruby image's GEM_HOME/BUNDLE_PATH.
COPY Gemfile Gemfile.lock ./
COPY --from=build /usr/local/bundle /usr/local/bundle

# net-imap ships as a Ruby "default gem" baked into the base image at
# whatever version that Ruby patch release bundled (0.3.9 here) -- pinning
# a newer version in the Gemfile (unused by this app; pulled in purely to
# get a patched version) installs it alongside the old one rather than
# replacing it, since Bundler and RubyGems' own default-gem installation
# use different paths. The stale, vulnerable default copy still sits on
# disk either way; remove it explicitly so it isn't there at all, rather
# than just shadowed by the newer bundled copy at runtime.
RUN gem uninstall -i /usr/local/lib/ruby/gems/3.2.0 net-imap --all --force || true
RUN gem uninstall -i /usr/local/lib/ruby/gems/3.2.0 erb --all --force || true
RUN gem uninstall -i /usr/local/lib/ruby/gems/3.2.0 resolv --all --force || true
# json is also a default gem, and IS actually used by this app (unlike
# net-imap) -- confirmed live that `bundle exec` (what entrypoint.sh
# actually runs under) correctly resolves the newer Bundler-managed copy
# first, so the version bump in the Gemfile is real and effective. Unlike
# net-imap, RubyGems refuses to uninstall it ("cannot be uninstalled
# because it is a default gem" -- it's a compiled default gem, not a pure
# Ruby one) -- the older, vulnerable version stays physically present on
# disk (Trivy will keep flagging it) but is never loaded by the running
# application.

# Copy app + entrypoint
COPY VERSION outie.rb ./
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Not just documentation -- outie.rb reads this same file at runtime and
# reports it from GET /severance, so the running version is queryable, not
# just visible on the image metadata.
ARG SEVERANCE_VERSION
LABEL org.opencontainers.image.title="severance-external" \
      org.opencontainers.image.version="${SEVERANCE_VERSION}" \
      org.opencontainers.image.description="Severance: secure SPARQL service (External component)"

# Pre-create dirs (optional, but good for non-volume cases)
RUN mkdir -p /data/queue /data/results

# VOLUME declaration (Docker knows this is a mount point)
VOLUME /data

ENV PORT=3000
EXPOSE 3000

# Start as root → entrypoint will chown then drop to severance
ENTRYPOINT ["./entrypoint.sh"]
