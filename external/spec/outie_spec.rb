# frozen_string_literal: true

require 'tmpdir'
require 'rack/test'
require 'json'

ENV['APP_ENV'] = 'test'
ENV['RACK_ENV'] = 'test'
ROOT = Dir.mktmpdir('outie-spec')
ENV['QUEUE_DIR'] = "#{ROOT}/queue"
ENV['RESULTS_DIR'] = "#{ROOT}/results"
ENV['METADATA_DIR'] = "#{ROOT}/meta"
ENV['ENCRYPTION_KEY_HEX'] = 'ab' * 32
ENV['AUTH_TOKEN'] = 'a' * 40
ENV['INNIE_TOKEN'] = 'b' * 40
ENV['MAX_PENDING_JOBS'] = '2'
ENV['ALLOWED_INTERNAL_IPS'] = '127.0.0.1,10.1.2.0/24'
Dir.mkdir(ENV['METADATA_DIR'])
require_relative '../outie'

# ZeroingBody wipes the plaintext in #close (after the real server has flushed the socket), and
# Rack's test client buffers the very same String object -- so capture a copy as it is yielded.
ZeroingBody.prepend(Module.new do
  def each
    super { |chunk| Thread.current[:delivered] = chunk.dup; yield chunk }
  end
end)

RSpec.describe 'External (outie.rb) hardening' do
  include Rack::Test::Methods

  def app = Sinatra::Application

  let(:user)  { { 'HTTP_AUTHORIZATION' => "Bearer #{ENV['AUTH_TOKEN']}" } }
  let(:innie) { { 'HTTP_AUTHORIZATION' => "Bearer #{ENV['INNIE_TOKEN']}" } }
  let(:json)  { { 'CONTENT_TYPE' => 'application/json' } }
  let(:octet) { { 'CONTENT_TYPE' => 'application/octet-stream' } }

  before do
    AUTH_FAILURES.clear
    FileUtils.rm_f(Dir["#{ENV['QUEUE_DIR']}/*"] + Dir["#{ENV['RESULTS_DIR']}/*"])
  end

  describe 'startup' do
    def boot(env)
      full = { 'AUTH_TOKEN' => nil, 'INNIE_TOKEN' => nil, 'APP_ENV' => 'test', 'ENCRYPTION_KEY_HEX' => 'ab' * 32, 'QUEUE_DIR' => "#{ROOT}/q2",
               'RESULTS_DIR' => "#{ROOT}/r2" }.merge(env)
      out = IO.popen(full.merge('RUBYLIB' => ENV['RUBYLIB'].to_s), ['ruby', '-e', "require '#{File.expand_path('../outie', __dir__)}'; puts 'BOOTED'"],
                     err: %i[child out], &:read)
      out.dup.force_encoding(Encoding::UTF_8)
    end

    it 'refuses to start without AUTH_TOKEN' do
      expect(boot('INNIE_TOKEN' => 'b' * 40)).to include('FATAL: AUTH_TOKEN is not set')
    end

    it 'refuses the shipped example token and short tokens' do
      expect(boot('AUTH_TOKEN' => 'YesItsMe', 'INNIE_TOKEN' => 'b' * 40)).to include('too short or is an example')
      expect(boot('AUTH_TOKEN' => 'a' * 40, 'INNIE_TOKEN' => 'short')).to include('too short or is an example')
    end

    it 'refuses identical tokens' do
      expect(boot('AUTH_TOKEN' => 'c' * 40, 'INNIE_TOKEN' => 'c' * 40)).to include('must differ')
    end
  end

  describe 'caller authentication' do
    it 'rejects missing and wrong tokens' do
      get '/severance'
      expect(last_response.status).to eq(401)
      get '/severance', {}, { 'HTTP_AUTHORIZATION' => 'Bearer nope' }
      expect(last_response.status).to eq(401)
    end

    it 'treats the token as case-sensitive (previously the whole header was compared case-insensitively)' do
      get '/severance', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{ENV['AUTH_TOKEN'].upcase}" }
      expect(last_response.status).to eq(401)
    end

    it 'accepts the right token, and a differently-cased scheme' do
      get '/severance', {}, user
      expect(last_response.status).to eq(200)
      get '/severance', {}, { 'HTTP_AUTHORIZATION' => "bearer #{ENV['AUTH_TOKEN']}" }
      expect(last_response.status).to eq(200)
    end

    it 'throttles repeated failures per client IP' do
      AUTH_FAIL_LIMIT.times { get '/severance', {}, { 'HTTP_AUTHORIZATION' => 'Bearer wrong' } }
      get '/severance', {}, user
      expect(last_response.status).to eq(429)
    end
  end

  describe 'Innie-only routes' do
    it 'need the INNIE_TOKEN even from an allow-listed IP' do
      get '/severance/queue/pull'
      expect(last_response.status).to eq(401)
      get '/severance/queue/pull', {}, user # the caller token must not work here
      expect(last_response.status).to eq(401)
      get '/severance/queue/pull', {}, innie
      expect(last_response.status).to eq(204)
    end

    it 'still refuse a non-allow-listed IP even with the token' do
      get '/severance/queue/pull', {}, innie.merge('REMOTE_ADDR' => '203.0.113.9')
      expect(last_response.status).to eq(403)
    end

    it 'accept a CIDR-listed IP with the token' do
      get '/severance/queue/pull', {}, innie.merge('REMOTE_ADDR' => '10.1.2.77')
      expect(last_response.status).to eq(204)
    end

    it 'do not let the INNIE_TOKEN into caller routes' do
      get '/severance', {}, innie
      expect(last_response.status).to eq(401)
    end
  end

  describe 'input validation' do
    it 'rejects non-UUID job ids on both job routes' do
      get '/severance/jobs/not-a-uuid', {}, user
      expect(last_response.status).to eq(404)
      post '/severance/jobs/not-a-uuid/result', 'x' * 64, innie.merge(octet)
      expect(last_response.status).to eq(400)
      expect(last_response.body).to eq('Invalid job id')
      expect(Dir["#{ENV['RESULTS_DIR']}/*"]).to be_empty
    end

    it 'rejects oversized request bodies' do
      post '/severance/queries', { query_id: 'count', bindings: { a: 'x' * 70_000 } }.to_json, user.merge(json)
      expect(last_response.status).to eq(413)
    end

    it 'requires bindings to be an object' do
      post '/severance/queries', { query_id: 'count', bindings: ['x'] }.to_json, user.merge(json)
      expect(last_response.status).to eq(400)
    end

    it 'caps the pending queue' do
      2.times do
        post '/severance/queries', { query_id: 'count', bindings: {} }.to_json, user.merge(json)
        expect(last_response.status).to eq(201)
      end
      post '/severance/queries', { query_id: 'count', bindings: {} }.to_json, user.merge(json)
      expect(last_response.status).to eq(429)
    end
  end

  describe 'results are bound to their job' do
    let(:job_a) { SecureRandom.uuid }
    let(:job_b) { SecureRandom.uuid }

    it 'delivers a result to the job it was encrypted for' do
      Thread.current[:delivered] = nil
      blob = send(:encrypt, 'secret rows', job_a)
      post "/severance/jobs/#{job_a}/result", blob, innie.merge(octet)
      expect(last_response.status).to eq(200)
      get "/severance/jobs/#{job_a}", {}, user
      expect(last_response.status).to eq(200)
      expect(Thread.current[:delivered]).to eq('secret rows')
    end

    it 'fails to decrypt a blob moved into another job slot' do
      Thread.current[:delivered] = nil
      blob = send(:encrypt, 'secret rows', job_a)
      post "/severance/jobs/#{job_b}/result", blob, innie.merge(octet) # swapped into B's slot
      get "/severance/jobs/#{job_b}", {}, user
      expect(last_response.status).to eq(500)
      expect(Thread.current[:delivered].to_s).not_to include('secret rows')
    end
  end
end
