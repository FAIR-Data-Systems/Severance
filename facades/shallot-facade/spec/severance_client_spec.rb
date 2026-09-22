# frozen_string_literal: true

require 'spec_helper'
require_relative '../lib/severance_client'

RSpec.describe SeveranceClient do
  JOB_LOCATION = 'http://severance.example/severance/jobs/abc'

  subject(:client) do
    described_class.new(base_url: 'http://severance.example', auth_token: 'tok', poll_interval: 0, poll_ceiling: 1)
  end

  def fake_response(code:, body: '', headers: {})
    double('Net::HTTPResponse', code: code.to_s, body: body).tap do |res|
      allow(res).to receive(:[]) { |key| headers[key] }
    end
  end

  def stub_http(response)
    fake_http = instance_double(Net::HTTP, request: response)
    allow(Net::HTTP).to receive(:start).and_yield(fake_http)
  end

  describe '#available_queries' do
    it 'parses the catalogue on 200' do
      stub_http(fake_response(code: 200, body: '[{"query_id":"count"}]'))

      expect(client.available_queries).to eq([{ 'query_id' => 'count' }])
    end

    it 'returns an empty array on 404 (no queries installed yet)' do
      stub_http(fake_response(code: 404, body: '{"error":"No queries available yet"}'))

      expect(client.available_queries).to eq([])
    end

    it 'raises CatalogueFetchFailed on any other non-200 status' do
      stub_http(fake_response(code: 500, body: 'boom'))

      expect { client.available_queries }.to raise_error(SeveranceClient::CatalogueFetchFailed, /500/)
    end

    it 'raises CatalogueFetchFailed on unparseable JSON' do
      stub_http(fake_response(code: 200, body: 'not json'))

      expect { client.available_queries }.to raise_error(SeveranceClient::CatalogueFetchFailed)
    end

    it 'sends the Bearer token' do
      captured = nil
      fake_http = instance_double(Net::HTTP)
      allow(Net::HTTP).to receive(:start) do |&blk|
        blk.call(fake_http)
      end
      allow(fake_http).to receive(:request) do |req|
        captured = req['Authorization']
        fake_response(code: 200, body: '[]')
      end

      client.available_queries

      expect(captured).to eq('Bearer tok')
    end
  end

  describe '#query' do
    it 'submits, polls through a 202, and returns the result on 200' do
      submit_response = fake_response(code: 201, headers: { 'Location' => JOB_LOCATION })
      pending_response = fake_response(code: 202, body: '{"status":"processing"}')
      done_response = fake_response(code: 200, body: 'a,b\n1,2', headers: { 'Content-Type' => 'text/csv' })

      responses = [submit_response, pending_response, done_response]
      fake_http = instance_double(Net::HTTP)
      allow(Net::HTTP).to receive(:start).and_yield(fake_http)
      allow(fake_http).to receive(:request) { responses.shift }

      result = client.query(query_id: 'count', bindings: { 'orphacode' => 'http://example.org/1' })

      expect(result.body).to eq('a,b\n1,2')
      expect(result.content_type).to eq('text/csv')
    end

    it 'raises QueryFailed if submission is rejected' do
      stub_http(fake_response(code: 400, body: 'bad request'))

      expect do
        client.query(query_id: 'count', bindings: {})
      end.to raise_error(SeveranceClient::QueryFailed, /rejected query submission/)
    end

    it 'raises QueryFailed if no Location header is returned' do
      stub_http(fake_response(code: 201, body: ''))

      expect do
        client.query(query_id: 'count', bindings: {})
      end.to raise_error(SeveranceClient::QueryFailed, /Location header/)
    end

    it 'raises QueryFailed if the job itself fails' do
      submit_response = fake_response(code: 201, headers: { 'Location' => JOB_LOCATION })
      failed_response = fake_response(code: 500, body: 'job blew up')

      responses = [submit_response, failed_response]
      fake_http = instance_double(Net::HTTP)
      allow(Net::HTTP).to receive(:start).and_yield(fake_http)
      allow(fake_http).to receive(:request) { responses.shift }

      expect do
        client.query(query_id: 'count', bindings: {})
      end.to raise_error(SeveranceClient::QueryFailed, /job failed/)
    end

    it 'raises PollTimeout once the poll ceiling is reached' do
      submit_response = fake_response(code: 201, headers: { 'Location' => JOB_LOCATION })
      pending_response = fake_response(code: 202, body: '{"status":"processing"}')

      fake_http = instance_double(Net::HTTP)
      allow(Net::HTTP).to receive(:start).and_yield(fake_http)
      allow(fake_http).to receive(:request).and_return(
        submit_response, pending_response, pending_response, pending_response
      )

      slow_client = described_class.new(
        base_url: 'http://severance.example', auth_token: 'tok', poll_interval: 0, poll_ceiling: -1
      ) # already-elapsed ceiling

      expect do
        slow_client.query(query_id: 'count', bindings: {})
      end.to raise_error(SeveranceClient::PollTimeout)
    end
  end
end
