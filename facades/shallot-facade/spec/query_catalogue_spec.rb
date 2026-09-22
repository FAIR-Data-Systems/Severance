# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/severance_client'
require_relative '../lib/query_catalogue'

RSpec.describe QueryCatalogue do
  let(:severance) { instance_double(SeveranceClient) }

  it 'does not fetch anything until first use' do
    allow(severance).to receive(:available_queries).and_return([])

    described_class.new(severance)

    expect(severance).not_to have_received(:available_queries)
  end

  it 'fetches on the first #all call, and caches for subsequent calls' do
    allow(severance).to receive(:available_queries).and_return([{ 'query_id' => 'count' }])
    catalogue = described_class.new(severance)

    2.times { catalogue.all }

    expect(severance).to have_received(:available_queries).once
  end

  it '#find returns a known entry without refetching' do
    allow(severance).to receive(:available_queries).and_return([{ 'query_id' => 'count' }])
    catalogue = described_class.new(severance)

    expect(catalogue.find('count')).to eq({ 'query_id' => 'count' })
    expect(severance).to have_received(:available_queries).once
  end

  it '#find refreshes once on a miss, in case the query was just installed' do
    call_count = 0
    allow(severance).to receive(:available_queries) do
      call_count += 1
      call_count == 1 ? [] : [{ 'query_id' => 'new_query' }]
    end
    catalogue = described_class.new(severance)

    expect(catalogue.find('new_query')).to eq({ 'query_id' => 'new_query' })
    expect(severance).to have_received(:available_queries).twice
  end

  it '#find returns nil, without looping, if the query still does not exist after a refresh' do
    allow(severance).to receive(:available_queries).and_return([])
    catalogue = described_class.new(severance)

    expect(catalogue.find('nonexistent')).to be_nil
    expect(severance).to have_received(:available_queries).twice # initial fetch + one refresh-on-miss
  end

  it 'keeps the previous catalogue and does not raise if a refresh fails' do
    allow(severance).to receive(:available_queries)
      .and_return([{ 'query_id' => 'count' }])
      .once
    catalogue = described_class.new(severance)
    catalogue.all # populate the cache

    allow(severance).to receive(:available_queries).and_raise(SeveranceClient::CatalogueFetchFailed, 'down')

    expect(catalogue.find('missing')).to be_nil
    expect(catalogue.find('count')).to eq({ 'query_id' => 'count' }) # still there from before the failed refresh
  end
end
