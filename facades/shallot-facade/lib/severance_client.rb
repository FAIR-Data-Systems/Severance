# frozen_string_literal: true

require 'net/http'
require 'json'
require 'uri'

# Talks to Severance External: fetches the query catalogue, and owns the
# submit -> poll -> fetch cycle for a single query. Blocking by design -- the
# facade holds the caller's HTTP connection open for the whole cycle so a
# Shallot-style caller never sees Severance's async job mechanics.
# Unlike Beacon2/facade/lib/severance_client.rb (its domain-specific sibling
# that parses SPARQL-JSON/CSV rows into a Ruby structure), this stays fully
# generic: results are returned as opaque bytes plus a content type, exactly
# as Severance produced them -- this facade doesn't know or care what shape
# any given query's results are.
class SeveranceClient
  class CatalogueFetchFailed < StandardError; end
  class PollTimeout < StandardError; end
  class QueryFailed < StandardError; end

  Result = Struct.new(:body, :content_type)

  def initialize(base_url:, auth_token:, poll_interval: 1.0, poll_ceiling: 20.0)
    @base_url = base_url
    @auth_token = auth_token
    @poll_interval = poll_interval
    @poll_ceiling = poll_ceiling
  end

  # @return [Array<Hash>] the catalogue from GET /severance/available_queries -- one entry per
  #   query_id, each with 'variables'/'variable_types'/etc. (see internal/annotation_parser.rb). An
  #   empty catalogue (Severance's "no queries available yet" 404) is returned as [], not an error --
  #   there's nothing wrong, Internal just hasn't pushed anything yet.
  def available_queries
    uri = URI("#{@base_url}/severance/available_queries")
    req = Net::HTTP::Get.new(uri)
    req['Authorization'] = "Bearer #{@auth_token}"
    req['Accept'] = 'application/json'

    res = http_request(uri, req)
    return [] if res.code.to_i == 404
    unless res.code.to_i == 200
      raise CatalogueFetchFailed, "Severance rejected available_queries: #{res.code} #{res.body}"
    end

    JSON.parse(res.body.to_s)
  rescue JSON::ParserError => e
    raise CatalogueFetchFailed, "Severance returned unparseable available_queries: #{e.message}"
  rescue SystemCallError, SocketError, Timeout::Error => e
    # A network-level failure to even reach Severance External (connection refused, DNS failure,
    # timeout -- an ordinary operational condition, not an attack) is wrapped here rather than left to
    # propagate raw. GET /:query_id already rescues these explicitly around SeveranceClient#query; this
    # method's only caller, QueryCatalogue#refresh, only ever rescued CatalogueFetchFailed -- an
    # unwrapped connection error reached Sinatra's uncaught-exception path and leaked a full stack
    # trace (file paths, gem versions) to the caller on GET / and GET /openapi.json, confirmed live.
    raise CatalogueFetchFailed, "could not reach Severance at #{@base_url}: #{e.class} #{e.message}"
  end

  # @param query_id [String]
  # @param bindings [Hash] Severance binding hash (Shallot/GRLC variable name => value)
  # @return [Result]
  def query(query_id:, bindings:)
    location = submit(query_id, bindings)
    poll(location)
  end

  private

  def submit(query_id, bindings)
    uri = URI("#{@base_url}/severance/queries")
    req = Net::HTTP::Post.new(uri)
    req['Content-Type'] = 'application/json'
    req['Authorization'] = "Bearer #{@auth_token}"
    req.body = JSON.generate({ query_id: query_id, bindings: bindings })

    res = http_request(uri, req)
    raise QueryFailed, "Severance rejected query submission: #{res.code} #{res.body}" unless res.code.to_i == 201

    location = res['Location']
    raise QueryFailed, 'Severance did not return a Location header' unless location

    location
  end

  def poll(location)
    uri = URI(location)
    deadline = Time.now + @poll_ceiling

    loop do
      req = Net::HTTP::Get.new(uri)
      req['Authorization'] = "Bearer #{@auth_token}"

      res = http_request(uri, req)

      return Result.new(res.body.to_s, res['Content-Type'].to_s) if res.code.to_i == 200
      raise QueryFailed, "Severance job failed: #{res.code} #{res.body}" unless [201, 202].include?(res.code.to_i)
      raise PollTimeout, "Poll ceiling (#{@poll_ceiling}s) reached for #{location}" if Time.now > deadline

      sleep @poll_interval
    end
  end

  def http_request(uri, req)
    Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }
  end
end
