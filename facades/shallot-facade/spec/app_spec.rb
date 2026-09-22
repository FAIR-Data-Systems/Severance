# frozen_string_literal: true

require 'spec_helper'
require 'rack/test'
require 'tmpdir'

# app.rb builds a real SEVERANCE_CLIENT/CATALOGUE at load time (from env defaults, pointing nowhere
# useful in a spec run), but QueryCatalogue fetches lazily, so loading it here makes no network call --
# each example below stubs SEVERANCE_CLIENT's methods directly before exercising a route.
require_relative '../app'

RSpec.describe 'shallot-facade routes' do
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  # CATALOGUE is a module-level constant, built once when app.rb loads, so its cache would otherwise
  # persist across examples -- reset it before each one so every example's own available_queries stub
  # is what actually gets used, not a previous example's cached result.
  before { CATALOGUE.instance_variable_set(:@by_id, nil) }

  describe 'GET /' do
    it 'returns a banner with the known query ids' do
      allow(SEVERANCE_CLIENT).to receive(:available_queries).and_return([{ 'query_id' => 'IUCN_categories' }])

      get '/'

      expect(last_response).to be_ok
      body = JSON.parse(last_response.body)
      expect(body['queries']).to eq(['IUCN_categories'])
      expect(body['name']).to eq('shallot-facade')
    end
  end

  describe 'GET /openapi.json' do
    it 'serves a Swagger 2.0 doc built from the catalogue' do
      allow(SEVERANCE_CLIENT).to receive(:available_queries).and_return(
        [{ 'query_id' => 'IUCN_categories', 'variables' => [], 'variable_types' => {} }]
      )

      get '/openapi.json'

      expect(last_response).to be_ok
      doc = JSON.parse(last_response.body)
      expect(doc['swagger']).to eq('2.0')
      expect(doc['paths'].keys).to eq(['/IUCN_categories'])
    end
  end

  describe 'unhandled exceptions (defense in depth)' do
    # Regression test: before SeveranceClient#available_queries wrapped connection-level failures,
    # an unreachable Severance leaked a full stack trace to the caller here -- confirmed live against
    # a real Docker build (show_exceptions is :after_handler, so Sinatra's detailed exception page
    # renders for ANY uncaught exception, in every environment, unless something catches it first).
    # This test forces a *different* unhandled error through GET / (bypassing SeveranceClient's own
    # wrapping entirely) to prove the generic `error StandardError` handler is the actual backstop,
    # not just that one call site's fix.
    it 'never leaks exception details, even for an error no specific rescue anticipates' do
      allow(SEVERANCE_CLIENT).to receive(:available_queries).and_raise(NoMethodError, "undefined method 'foo'")

      get '/'

      expect(last_response.status).to eq(500)
      expect(last_response.body).to eq({ error: 'internal_error' }.to_json)
      expect(last_response.body).not_to include('NoMethodError', 'app.rb', '.rb:')
    end
  end

  describe 'GET /:query_id' do
    it 'forwards query-string params as Severance bindings and returns the result body/content-type' do
      allow(SEVERANCE_CLIENT).to receive(:available_queries).and_return(
        [{ 'query_id' => 'species_location', 'variables' => ['speciesname'] }]
      )
      allow(SEVERANCE_CLIENT).to receive(:query)
        .with(query_id: 'species_location', bindings: { 'speciesname' => 'Arabidopsis thaliana' })
        .and_return(SeveranceClient::Result.new('lat,lon\n1,2', 'text/csv'))

      get '/species_location?speciesname=Arabidopsis+thaliana'

      expect(last_response).to be_ok
      expect(last_response.body).to eq('lat,lon\n1,2')
      # Sinatra's content_type helper appends a default charset to text/* types on its own.
      expect(last_response.content_type).to eq('text/csv;charset=utf-8')
    end

    it 'returns 404 for an unknown query_id' do
      allow(SEVERANCE_CLIENT).to receive(:available_queries).and_return([])

      get '/does_not_exist'

      expect(last_response.status).to eq(404)
    end

    it 'returns 502 if Severance rejects the query' do
      allow(SEVERANCE_CLIENT).to receive(:available_queries).and_return([{ 'query_id' => 'q', 'variables' => [] }])
      allow(SEVERANCE_CLIENT).to receive(:query).and_raise(SeveranceClient::QueryFailed, 'nope')

      get '/q'

      expect(last_response.status).to eq(502)
    end

    it 'returns 504 on a poll timeout' do
      allow(SEVERANCE_CLIENT).to receive(:available_queries).and_return([{ 'query_id' => 'q', 'variables' => [] }])
      allow(SEVERANCE_CLIENT).to receive(:query).and_raise(SeveranceClient::PollTimeout, 'too slow')

      get '/q'

      expect(last_response.status).to eq(504)
    end
  end
end
