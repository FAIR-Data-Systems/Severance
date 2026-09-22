# frozen_string_literal: true

require 'spec_helper'
require 'tempfile'
require 'fileutils'
require_relative '../annotation_parser'

RSpec.describe QueryAnnotationParser::Parser do
  let(:temp_file) { Tempfile.new(['test_query', '.rq']) }

  after do
    temp_file.close
    temp_file.unlink
  end

  describe '.parse' do
    context 'with a basic query file' do
      before do
        temp_file.puts '#+query_id: test_query' # no space after #+
        temp_file.puts '#+title: Simple Test Query'
        temp_file.puts '#+tags:'
        temp_file.puts '#+- test'
        temp_file.puts '#+- sparql'
        temp_file.puts ''
        temp_file.puts 'SELECT ?s ?p ?o WHERE {'
        temp_file.puts '  ?s ?p ?o .'
        temp_file.puts '}'
        temp_file.rewind
      end

      it 'extracts metadata correctly' do
        metadata = described_class.parse(temp_file.path)

        expect(metadata['query_id']).to eq('test_query')
        expect(metadata['title']).to eq('Simple Test Query')
        expect(metadata['tags']).to contain_exactly('test', 'sparql')
        expect(metadata['query']).to include('SELECT ?s ?p ?o')
      end
    end

    context 'with simple key:value decorators' do
      before do
        temp_file.puts '#+title: Countries Query'
        temp_file.puts '#+endpoint: https://query.wikidata.org/sparql'
        temp_file.puts '#+method: GET'
        temp_file.puts '#+pagination: 100'
        temp_file.puts '#+endpoint_in_url: false'
        temp_file.puts ''
        temp_file.puts 'SELECT ?country WHERE { ?country wdt:P31 wd:Q6256 . }'
        temp_file.rewind
      end

      it 'parses strings, integers, and booleans correctly' do
        metadata = described_class.parse(temp_file.path)

        expect(metadata['title']).to eq('Countries Query')
        expect(metadata['endpoint']).to eq('https://query.wikidata.org/sparql')
        expect(metadata['method']).to eq('GET')
        expect(metadata['pagination']).to eq(100)
        expect(metadata['endpoint_in_url']).to be false
      end
    end

    context 'with defaults section' do
      before do
        temp_file.puts '#+defaults:'
        temp_file.puts '#+- limit: 50'
        temp_file.puts '#+- lang: "en"'
        temp_file.puts '#+- debug: false'
        temp_file.puts ''
        temp_file.puts 'SELECT ?item WHERE { ?item wdt:P31 ?class . }'
        temp_file.rewind
      end

      it 'parses defaults as a hash with proper types' do
        metadata = described_class.parse(temp_file.path)

        expect(metadata['defaults']).to eq({
                                             'limit' => 50,
                                             'lang' => 'en',
                                             'debug' => false
                                           })
      end
    end

    context 'with enumerate section' do
      before do
        temp_file.puts '#+enumerate:'
        temp_file.puts '#+- continent:'
        temp_file.puts '#+- Europe'
        temp_file.puts '#+- Asia'
        temp_file.puts '#+- Africa'
        temp_file.puts ''
        temp_file.puts 'SELECT ?country WHERE { ?country wdt:P30 ?_continent_iri . }'
        temp_file.rewind
      end

      it 'parses enumerate lists correctly' do
        metadata = described_class.parse(temp_file.path)

        expect(metadata['enumerate']).to eq({
                                              'continent' => %w[Europe Asia Africa]
                                            })
      end
    end

    context 'with grlc-style parameters' do
      before do
        temp_file.puts '#+title: Parameterized Query'
        temp_file.puts ''
        temp_file.puts 'SELECT ?name WHERE {'
        temp_file.puts '  ?person foaf:name ?name .'
        temp_file.puts '  FILTER(?age > ?_age_integer)'
        temp_file.puts '  ?person schema:country ?_country_iri .'
        temp_file.puts '}'
        temp_file.rewind
      end

      it 'detects variables and normalizes types' do
        metadata = described_class.parse(temp_file.path)

        expect(metadata['variables']).to contain_exactly('age', 'country')
        expect(metadata['variable_types']).to eq({
                                                   'age' => 'integer',
                                                   'country' => 'iri'
                                                 })
      end
    end

    context 'with a #+ parameters: block (GRLC dialect, no type-suffixed inline placeholder)' do
      before do
        # Mirrors FLAIR-GG's species_location.rq: a bare `?_speciesname` placeholder (no `_type`
        # suffix), so extract_parameters alone would find nothing -- the parameter is declared only
        # via the `#+ parameters:` block instead.
        temp_file.puts '#+summary: the geo-coordinates for every sample of a given species'
        temp_file.puts '#+method: GET'
        temp_file.puts '#+parameters:'
        temp_file.puts '#+  - name: speciesname'
        temp_file.puts '#+    type: string'
        temp_file.puts '#+    description: The species scientific name'
        temp_file.puts '#+    required: true'
        temp_file.puts '#+    default: "Arabidopsis thaliana"'
        temp_file.puts ''
        temp_file.puts 'SELECT ?scientific_name WHERE {'
        temp_file.puts '  ?taxon dwc:scientificName ?scientific_name .'
        temp_file.puts '  FILTER(contains(lcase(str(?scientific_name)), lcase(?_speciesname)))'
        temp_file.puts '}'
        temp_file.rewind
      end

      it 'folds the parameter into variables, variable_types, defaults, and required' do
        metadata = described_class.parse(temp_file.path)

        expect(metadata['variables']).to contain_exactly('speciesname')
        expect(metadata['variable_types']).to eq({ 'speciesname' => 'string' })
        expect(metadata['defaults']).to eq({ 'speciesname' => 'Arabidopsis thaliana' })
        expect(metadata['required']).to contain_exactly('speciesname')
        expect(metadata['parameters']).to eq(
          [{ 'name' => 'speciesname', 'type' => 'string', 'description' => 'The species scientific name',
             'required' => true, 'default' => 'Arabidopsis thaliana' }]
        )
      end
    end

    context 'with a #+ parameters: block alongside an inline typed placeholder' do
      before do
        # The inline `?_age_integer` is found first by extract_parameters; the parameters block also
        # mentions `age` (untyped) -- the inline type must win, not be overwritten by the block.
        temp_file.puts '#+parameters:'
        temp_file.puts '#+  - name: age'
        temp_file.puts '#+    type: string'
        temp_file.puts ''
        temp_file.puts 'SELECT ?p WHERE { ?p :age ?_age_integer . }'
        temp_file.rewind
      end

      it 'does not let the parameters block override a type already found inline' do
        metadata = described_class.parse(temp_file.path)

        expect(metadata['variable_types']).to eq({ 'age' => 'integer' })
      end
    end

    context 'when no decorators are present' do
      before do
        temp_file.puts 'SELECT * WHERE { ?s ?p ?o . }'
        temp_file.rewind
      end

      it 'still returns the query and a fallback query_id' do
        metadata = described_class.parse(temp_file.path)

        expect(metadata['query']).to include('SELECT * WHERE')
        expect(metadata['title']).to be_nil
      end
    end
  end

  describe '.process_folder' do
    let(:temp_dir) { Dir.mktmpdir }

    after do
      FileUtils.remove_entry(temp_dir)
    end

    it 'processes all .rq and .sparql files recursively' do
      subfolder = File.join(temp_dir, 'subfolder')
      FileUtils.mkdir_p(subfolder)

      File.write(File.join(temp_dir, 'query1.rq'), "#+title: Query One\n\nSELECT ?x WHERE {}")
      File.write(File.join(subfolder, 'query2.sparql'), "#+title: Query Two\n\nASK {}")

      results = described_class.process_folder(temp_dir)

      titles = results.map { |m| m['title'] }
      expect(titles).to contain_exactly('Query One', 'Query Two')
    end

    it 'raises an error when folder does not exist' do
      expect do
        described_class.process_folder('/non/existent/path')
      end.to raise_error(RuntimeError, /Folder not found/)
    end
  end

  describe '.parse_value' do
    it 'converts strings, numbers, booleans, and nil correctly' do
      expect(described_class.parse_value('42')).to eq(42)
      expect(described_class.parse_value('3.14')).to eq(3.14)
      expect(described_class.parse_value('true')).to be true
      expect(described_class.parse_value('false')).to be false
      expect(described_class.parse_value('"hello"')).to eq('hello')
      expect(described_class.parse_value("'world'")).to eq('world')
      expect(described_class.parse_value('')).to be_nil
      expect(described_class.parse_value(nil)).to be_nil
      expect(described_class.parse_value('plain text')).to eq('plain text')
    end
  end

  describe '.normalize_type' do
    it 'normalizes grlc-style type suffixes' do
      expect(described_class.normalize_type('iri')).to eq('iri')
      expect(described_class.normalize_type('URI')).to eq('iri')
      expect(described_class.normalize_type('integer')).to eq('integer')
      expect(described_class.normalize_type('int')).to eq('integer')
      expect(described_class.normalize_type('float')).to eq('float')
      expect(described_class.normalize_type('boolean')).to eq('boolean')
      expect(described_class.normalize_type('date')).to eq('date')
      expect(described_class.normalize_type('unknown')).to eq('string')
    end
  end
end
