# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/openapi_builder'

RSpec.describe OpenapiBuilder do
  describe '.build' do
    it 'derives host/basePath/schemes from base_url' do
      doc = described_class.build(queries: [], base_url: 'https://facade.example.org/prefix')

      expect(doc['swagger']).to eq('2.0')
      expect(doc['host']).to eq('facade.example.org')
      expect(doc['basePath']).to eq('/prefix')
      expect(doc['schemes']).to eq(['https'])
    end

    it 'includes a non-standard port in host' do
      doc = described_class.build(queries: [], base_url: 'http://localhost:4567')

      expect(doc['host']).to eq('localhost:4567')
    end

    it 'defaults basePath to / when base_url has no path' do
      doc = described_class.build(queries: [], base_url: 'http://localhost:4567')

      expect(doc['basePath']).to eq('/')
    end

    it 'builds one GET path per query_id, with no parameters for a parameterless query' do
      query = { 'query_id' => 'IUCN_categories', 'summary' => 'endangerment status', 'tags' => ['IUCN_categories'],
                'variables' => [], 'variable_types' => {} }

      doc = described_class.build(queries: [query], base_url: 'http://localhost:4567')

      expect(doc['paths'].keys).to eq(['/IUCN_categories'])
      get = doc['paths']['/IUCN_categories']['get']
      expect(get['summary']).to eq('endangerment status')
      expect(get['tags']).to eq(['IUCN_categories'])
      expect(get['parameters']).to eq([])
    end

    it 'builds a required, typed, defaulted query parameter' do
      # 'examples', not 'defaults', is the field Severance's real available_queries catalogue uses
      # for this (see internal/innie.rb#process_queries) -- confirmed against a real end-to-end run.
      query = {
        'query_id' => 'species_location',
        'summary' => 'geo-coordinates for a species',
        'variables' => ['speciesname'],
        'variable_types' => { 'speciesname' => 'string' },
        'required' => ['speciesname'],
        'examples' => { 'speciesname' => 'Arabidopsis thaliana' }
      }

      doc = described_class.build(queries: [query], base_url: 'http://localhost:4567')

      params = doc['paths']['/species_location']['get']['parameters']
      expect(params).to eq(
        [
          { 'name' => 'speciesname', 'in' => 'query', 'required' => true, 'type' => 'string',
            'default' => 'Arabidopsis thaliana' }
        ]
      )
    end

    it 'maps every GRLC/Severance variable type to a Swagger 2.0 type' do
      query = {
        'query_id' => 'q',
        'variables' => %w[a b c d e],
        'variable_types' => { 'a' => 'iri', 'b' => 'integer', 'c' => 'float', 'd' => 'boolean', 'e' => 'date' }
      }

      doc = described_class.build(queries: [query], base_url: 'http://localhost:4567')
      by_name = doc['paths']['/q']['get']['parameters'].to_h { |p| [p['name'], p] }

      expect(by_name['a']).to include('type' => 'string', 'format' => 'uri')
      expect(by_name['b']).to include('type' => 'integer')
      expect(by_name['c']).to include('type' => 'number')
      expect(by_name['d']).to include('type' => 'boolean')
      expect(by_name['e']).to include('type' => 'string', 'format' => 'date')
    end

    it 'sets produces from the given content types' do
      query = { 'query_id' => 'q', 'variables' => [] }

      doc = described_class.build(queries: [query], base_url: 'http://localhost:4567', produces: ['text/csv'])

      expect(doc['paths']['/q']['get']['produces']).to eq(['text/csv'])
    end
  end
end
