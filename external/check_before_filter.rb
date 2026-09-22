#!/usr/bin/env ruby
# frozen_string_literal: true

# Standalone check for outie.rb's `before` filter -- confirms the routing-prefix bug (a caller-facing
# GET falling under the internal-IP-only branch because it shared a path prefix with an Innie-only
# route) stays fixed. Deliberately not an rspec/rack-test suite: `external/` carries no test framework
# today, and Severance is kept intentionally small -- see CLAUDE_SESSION_HANDOFF_2026-09-22.md. `rack`
# is already a transitive dependency of sinatra/rackup (see external/Gemfile.lock), and
# Rack::MockRequest ships inside it, so this needs no new gem.
#
# Run directly: `ruby check_before_filter.rb` (exits non-zero and prints failures on any mismatch).

require 'tmpdir'
require 'fileutils'
require 'json'

ENV['ENCRYPTION_KEY_HEX'] = '1' * 64
ENV['AUTH_TOKEN'] = 'test-token'
ENV['ALLOWED_INTERNAL_IPS'] = '203.0.113.0/24'
scratch = Dir.mktmpdir('severance-before-filter-check')
ENV['QUEUE_DIR'] = File.join(scratch, 'queue')
ENV['RESULTS_DIR'] = File.join(scratch, 'results')
ENV['METADATA_DIR'] = File.join(scratch, 'metadata')
FileUtils.mkdir_p(ENV.fetch('METADATA_DIR'))

require 'rack/mock'
require_relative 'outie'

app = Rack::MockRequest.new(Sinatra::Application)

EXTERNAL_IP = '198.51.100.7' # outside ALLOWED_INTERNAL_IPS
INTERNAL_IP = '203.0.113.5'  # inside ALLOWED_INTERNAL_IPS' 203.0.113.0/24

def env_for(ip, headers = {})
  { 'REMOTE_ADDR' => ip }.merge(headers)
end

bearer = { 'HTTP_AUTHORIZATION' => "Bearer #{ENV.fetch('AUTH_TOKEN')}" }

failures = []

def check(failures, label, response, expected_statuses)
  return if expected_statuses.include?(response.status)

  failures << "#{label}: expected #{expected_statuses.inspect}, got #{response.status}"
end

# A Bearer-authenticated caller on an EXTERNAL IP must be able to reach the caller-facing routes...
check(failures, '[external IP, Bearer] GET /severance/jobs/:uuid',
      app.get('/severance/jobs/does-not-exist', env_for(EXTERNAL_IP, bearer)), [404])
check(failures, '[external IP, Bearer] GET /severance/available_queries',
      app.get('/severance/available_queries', env_for(EXTERNAL_IP, bearer)), [200, 404])

# ...and must NOT be able to reach Innie's own routes, even with a valid Bearer token.
check(failures, '[external IP, Bearer] GET /severance/queue/pull (should be internal-IP only)',
      app.get('/severance/queue/pull', env_for(EXTERNAL_IP, bearer)), [403])
result_post_opts = { input: 'x' * 32, 'CONTENT_TYPE' => 'application/octet-stream' }

check(failures, '[external IP, Bearer] POST /severance/jobs/:uuid/result (should be internal-IP only)',
      app.post('/severance/jobs/does-not-exist/result', env_for(EXTERNAL_IP, bearer).merge(result_post_opts)),
      [403])

# A caller on an INTERNAL IP with no Bearer token at all must be able to reach Innie's own routes...
check(failures, '[internal IP, no Bearer] GET /severance/queue/pull',
      app.get('/severance/queue/pull', env_for(INTERNAL_IP)), [204])
check(failures, '[internal IP, no Bearer] POST /severance/jobs/:uuid/result',
      app.post('/severance/jobs/does-not-exist/result', env_for(INTERNAL_IP).merge(result_post_opts)),
      [200])

# POST /severance/available_queries (Innie pushing its catalogue) shares its path with the
# caller-facing GET of the same name, but is itself an Innie-only route (innie.rb never sends a
# Bearer token for this push) -- missed by the first before-filter fix above, caught only by a real
# end-to-end run (see CLAUDE_SESSION_HANDOFF_2026-09-22.md), so covered explicitly here.
available_queries_post_opts = { input: '[]', 'CONTENT_TYPE' => 'application/json' }
check(failures, '[internal IP, no Bearer] POST /severance/available_queries',
      app.post('/severance/available_queries', env_for(INTERNAL_IP).merge(available_queries_post_opts)),
      [200])
check(failures, '[external IP, Bearer] POST /severance/available_queries (should be internal-IP only)',
      app.post('/severance/available_queries', env_for(EXTERNAL_IP, bearer).merge(available_queries_post_opts)),
      [403])
# Unlike the caller-facing GET/jobs routes, a POST here is *always* IP-gated (never falls through to
# the Bearer check, since Innie never sends one) -- so a non-internal caller gets 403 regardless of
# whether it presents a Bearer token, not 401.
check(failures, '[external IP, no auth] POST /severance/available_queries',
      app.post('/severance/available_queries', env_for(EXTERNAL_IP).merge(available_queries_post_opts)),
      [403])

# ...but still needs a Bearer token for the caller-facing routes -- being on an allowed internal IP
# doesn't grant a free pass to routes gated by AUTH_TOKEN instead of the IP check.
check(failures, '[internal IP, no Bearer] GET /severance/jobs/:uuid',
      app.get('/severance/jobs/does-not-exist', env_for(INTERNAL_IP)), [401])

# A caller with neither a Bearer token nor an allowed IP gets 401 on the caller-facing routes (the
# Bearer check applies) and 403 on Innie's routes (the IP check applies).
check(failures, '[external IP, no auth] GET /severance/jobs/:uuid',
      app.get('/severance/jobs/does-not-exist', env_for(EXTERNAL_IP)), [401])
check(failures, '[external IP, no auth] GET /severance/queue/pull',
      app.get('/severance/queue/pull', env_for(EXTERNAL_IP)), [403])

if failures.empty?
  puts 'OK: before filter routes internal vs external access correctly.'
  exit 0
else
  warn 'FAILED:'
  failures.each { |f| warn "  - #{f}" }
  exit 1
end
