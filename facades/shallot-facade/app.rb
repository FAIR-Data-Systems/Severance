# frozen_string_literal: true

require 'sinatra'
require 'json'
require_relative 'lib/severance_client'
require_relative 'lib/query_catalogue'
require_relative 'lib/openapi_builder'

# Sinatra 4.x/rack-protection 4.x enable Rack::Protection::HostAuthorization by default, which rejects
# any Host header outside a small built-in allowlist (localhost, IP literals, etc.) with a bare 403
# "Host not permitted" -- the identical issue already documented and fixed the same way in this repo's
# ../../external/outie.rb (see its own comment for the full history: `set :protection, except:` has
# proven unreliable across versions here). This facade is meant to be reached under its own real
# hostname (SHALLOT_FACADE_BASE_URL), not just localhost, and -- like outie.rb -- never renders
# browser-served HTML or trusts the Host header for anything security-sensitive, so disabling this
# specific check costs nothing real here.
require 'rack/protection/host_authorization'
class Rack::Protection::HostAuthorization
  def accepts?(_request)
    true
  end
end

# SHALLOT_FACADE_-prefixed env var names throughout this file are deliberate, not decorative -- this
# runs alongside Severance and other host services, and generic names like PORT/BIND risk colliding
# with unrelated env vars set elsewhere on the same host or in the same docker-compose file.
set :bind, ENV.fetch('SHALLOT_FACADE_BIND', '0.0.0.0')
set :port, ENV.fetch('SHALLOT_FACADE_PORT', '4567').to_i
set :show_exceptions, :after_handler

FACADE_VERSION = File.read(File.join(__dir__, 'VERSION')).strip

# This facade's own externally-reachable base URL -- must match the scheme/host/path prefix under
# which each query's route will be registered as `dcat:endpointURL` (<BASE_URL>/<query_id>), since
# the VP's Service#retrieve_endpoint compares the OpenAPI doc's servers[].url + path against that
# registered endpoint (see lib/openapi_builder.rb).
BASE_URL = ENV.fetch('SHALLOT_FACADE_BASE_URL', 'http://localhost:4567')

# There's no way to learn what content type(s) a given Severance deployment's RESULT_FORMAT actually
# returns from available_queries alone -- this just has to be told, to advertise accurately in the
# OpenAPI doc this facade serves. The real per-request Content-Type always comes straight from
# Severance's own response (see SeveranceClient::Result), never from this.
PRODUCES = ENV.fetch('SHALLOT_FACADE_PRODUCES', 'application/sparql-results+json').split(',').map(&:strip)

# Exposed as constants (rather than plain top-level locals) so specs can stub SEVERANCE_CLIENT's
# methods directly instead of touching the network -- requiring this file never makes an HTTP call on
# its own (QueryCatalogue fetches lazily, on first use).
SEVERANCE_CLIENT = SeveranceClient.new(
  base_url: ENV.fetch('SHALLOT_FACADE_SEVERANCE_URL', 'http://localhost:3000'),
  auth_token: ENV.fetch('SHALLOT_FACADE_SEVERANCE_AUTH_TOKEN', 'YesItsMe'),
  poll_interval: ENV.fetch('SHALLOT_FACADE_POLL_INTERVAL', '1').to_f,
  poll_ceiling: ENV.fetch('SHALLOT_FACADE_POLL_CEILING', '20').to_f
)
CATALOGUE = QueryCatalogue.new(SEVERANCE_CLIENT)

# Root: a minimal banner, unauthenticated, matching the spirit of Severance's own GET /severance.
get '/' do
  content_type :json
  { name: 'shallot-facade', facadeVersion: FACADE_VERSION, queries: CATALOGUE.all.map { |q| q['query_id'] } }.to_json
end

# The OpenAPI/Swagger document Shallot itself would serve at its registration URL -- this is what
# `dcat:endpointDescription` should point to for a query routed through this facade. Defined ahead of
# the catch-all `GET /:query_id` below so it isn't swallowed as a (nonexistent) query_id.
get '/openapi.json' do
  content_type :json
  OpenapiBuilder.build(queries: CATALOGUE.all, base_url: BASE_URL, produces: PRODUCES).to_json
end

# One route per query_id, exactly as Shallot itself would serve it (GET /<query_id>?param=...) --
# except that query_id isn't known until runtime, so this is a single dynamic route rather than one
# `get` block per query. Query-string params are forwarded to Severance as bindings by name; no
# translation is needed, since Severance's binding names already are the Shallot (GRLC-derived) variable names.
get '/:query_id' do
  query = CATALOGUE.find(params['query_id'])
  halt 404, { error: "no such query: #{params['query_id']}" }.to_json unless query

  bindings = params.reject { |k, _| k == 'query_id' || k == 'splat' || k == 'captures' }

  begin
    result = SEVERANCE_CLIENT.query(query_id: query['query_id'], bindings: bindings)
  rescue SeveranceClient::PollTimeout => e
    halt 504, { error: 'poll_timeout', message: e.message }.to_json
  rescue SeveranceClient::QueryFailed => e
    halt 502, { error: 'severance_query_failed', message: e.message }.to_json
  rescue SystemCallError, SocketError => e
    halt 502, { error: 'severance_unreachable', message: e.message }.to_json
  end

  content_type result.content_type unless result.content_type.to_s.empty?
  result.body
end

error JSON::ParserError do
  status 400
  content_type :json
  { error: 'invalid_json' }.to_json
end
