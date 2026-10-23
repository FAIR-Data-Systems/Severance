# frozen_string_literal: true

require 'spec_helper'

# innie.rb's main polling loop is guarded by `if __FILE__ == $PROGRAM_NAME`, so requiring it here
# (as $PROGRAM_NAME is rspec's own path, not innie.rb's) loads its method definitions without
# entering the infinite loop. ENCRYPTION_KEY_HEX must be set before the require, or the file aborts
# the process outright (see innie.rb's own startup check).
ENV['ENCRYPTION_KEY_HEX'] ||= '1' * 64
require_relative '../innie'

RSpec.describe '#substitute_grlc_bindings (internal/innie.rb)' do
  it 'substitutes a type-suffixed inline placeholder (?_key_type)' do
    query = 'FILTER(?age > ?_age_integer)'

    result = substitute_grlc_bindings(query.dup, { 'age' => 18 }, { 'age' => 'integer' })

    expect(result).to eq('FILTER(?age > 18)')
  end

  it 'substitutes a double-underscore type-suffixed placeholder (?__key_type)' do
    query = 'FILTER(?age > ?__age_integer)'

    result = substitute_grlc_bindings(query.dup, { 'age' => 18 }, { 'age' => 'integer' })

    expect(result).to eq('FILTER(?age > 18)')
  end

  it 'substitutes a bare, untyped placeholder (?_key) declared only via a #+ parameters: block' do
    # Regression test: FLAIR-GG's species_location.rq declares `speciesname` only via a
    # #+ parameters: block and uses the bare ?_speciesname placeholder (no _type suffix). Before this
    # fix, the pattern required a type suffix, so this placeholder was silently left unreplaced in the
    # query sent to the triplestore -- an unbound SPARQL variable, always zero rows, no error anywhere
    # in the chain. Caught only by a real end-to-end run (see CLAUDE_SESSION_HANDOFF_2026-09-22.md).
    query = 'FILTER(contains(lcase(str(?scientific_name)), lcase(?_speciesname)))'

    result = substitute_grlc_bindings(query.dup, { 'speciesname' => 'Arabidopsis' }, { 'speciesname' => 'string' })

    expect(result).to eq('FILTER(contains(lcase(str(?scientific_name)), lcase("Arabidopsis")))')
  end

  it 'does not let a bare placeholder match a longer variable name sharing the same prefix' do
    query = '?_species ?_speciesname'

    result = substitute_grlc_bindings(query.dup, { 'species' => 'Plantae' }, {})

    expect(result).to eq('"Plantae" ?_speciesname')
  end

  it 'quotes and IRI-wraps according to the declared variable type' do
    query = '?taxon schema:country ?_country_iri'

    result = substitute_grlc_bindings(query.dup, { 'country' => 'http://example.org/Spain' }, { 'country' => 'iri' })

    expect(result).to eq('?taxon schema:country <http://example.org/Spain>')
  end

  it 'raises InvalidIriError for a binding declared as iri with disallowed characters' do
    query = '?_bad_iri'

    expect do
      substitute_grlc_bindings(query.dup, { 'bad' => 'not a valid iri <>' }, { 'bad' => 'iri' })
    end.to raise_error(InvalidIriError)
  end

  it 'raises InvalidEncodingError for a binding with invalid UTF-8' do
    query = '?_bad_string'
    invalid = (+"\xFF").force_encoding('UTF-8')

    expect do
      substitute_grlc_bindings(query.dup, { 'bad' => invalid }, {})
    end.to raise_error(InvalidEncodingError)
  end

  it 'leaves the query untouched when bindings are empty or nil' do
    query = '?_speciesname'

    expect(substitute_grlc_bindings(query.dup, {}, {})).to eq(query)
    expect(substitute_grlc_bindings(query.dup, nil, {})).to eq(query)
  end
end

RSpec.describe 'single-pass substitution (internal/innie.rb)' do
  let(:query) do
    <<~Q
      SELECT ?p WHERE {
        ?p foaf:name ?_name_string ;
           ex:country ?_country_string .
      }
    Q
  end
  let(:types) { { 'name' => 'string', 'country' => 'string' } }

  it 'never treats text inserted by one binding as a placeholder for another' do
    bindings = { 'name' => 'x ?_country_string', 'country' => '} UNION { ?s ?p ?o } #' }

    result = substitute_grlc_bindings(query.dup, bindings, types)

    # name's value is a plain, fully-quoted literal that merely *contains* the placeholder text
    expect(result).to include('foaf:name "x ?_country_string" ;')
    # country's value is a plain, fully-quoted literal too
    expect(result).to include('ex:country "} UNION { ?s ?p ?o } #" .')
    # and the injected text only ever appears inside quotes: no raw UNION outside a literal
    expect(result.gsub(/"(?:[^"\\]|\\.)*"/, '""')).not_to include('UNION')
  end

  it 'gives the same result regardless of binding order' do
    a = substitute_grlc_bindings(query.dup, { 'name' => 'x ?_country_string', 'country' => 'y' }, types)
    b = substitute_grlc_bindings(query.dup, { 'country' => 'y', 'name' => 'x ?_country_string' }, types)

    expect(a).to eq(b)
  end

  it 'still prefers the longer key when one key is a prefix of another' do
    q = 'FILTER(?_species_string = ?_species2_string)'

    result = substitute_grlc_bindings(q.dup, { 'species' => 'a', 'species2' => 'b' },
                                      { 'species' => 'string', 'species2' => 'string' })

    expect(result).to eq('FILTER("a" = "b")')
  end

  it 'rejects an invalid IRI binding without substituting anything' do
    q = 'SELECT * WHERE { ?s ex:country ?_country_iri ; ex:name ?_name_string }'

    expect do
      substitute_grlc_bindings(q.dup, { 'name' => 'ok', 'country' => 'http://x> } #' },
                               { 'name' => 'string', 'country' => 'iri' })
    end.to raise_error(InvalidIriError)
  end
end
