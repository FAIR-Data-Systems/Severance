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
