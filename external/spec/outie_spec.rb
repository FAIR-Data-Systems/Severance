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

    it 'reads secrets from *_FILE paths (Docker secrets) instead of the environment' do
      files = { 'AUTH_TOKEN' => 'd' * 40, 'INNIE_TOKEN' => 'e' * 40, 'ENCRYPTION_KEY_HEX' => 'cd' * 32 }.to_h do |k, v|
        path = File.join(ROOT, "#{k.downcase}.secret")
        File.write(path, "#{v}\n")
        ["#{k}_FILE", path]
      end
      expect(boot(files.merge('ENCRYPTION_KEY_HEX' => nil))).to include('BOOTED')
      expect(boot('AUTH_TOKEN_FILE' => "#{ROOT}/missing", 'INNIE_TOKEN' => 'b' * 40))
        .to include('AUTH_TOKEN_FILE is set, but')
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

    it 'cannot be locked out by failed caller logins that spoof Innie\'s address' do
      # The TCP peer is a private address (Docker gateway / proxy), so Rack trusts X-Forwarded-For.
      spoofer = { 'REMOTE_ADDR' => '172.17.0.1', 'HTTP_X_FORWARDED_FOR' => '10.1.2.77',
                  'HTTP_AUTHORIZATION' => 'Bearer wrong' }
      AUTH_FAIL_LIMIT.times { get '/severance', {}, spoofer }
      expect(last_response.status).to eq(401)
      get '/severance', {}, spoofer
      expect(last_response.status).to eq(429) # the public route is throttled for that address...

      get '/severance/queue/pull', {}, innie.merge('REMOTE_ADDR' => '10.1.2.77')
      expect(last_response.status).to eq(204) # ...but Innie's poll is not
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

    it 'refuses multipart bodies before anything parses them, even without a token' do
      expect(Rack::Multipart::Parser).not_to receive(:parse)
      expect(Rack::Multipart).not_to receive(:parse_multipart)
      body = "--b\r\nContent-Disposition: form-data; name=\"query_id\"\r\n\r\ncount\r\n--b--\r\n"

      post '/severance/queries', body, { 'CONTENT_TYPE' => 'multipart/form-data; boundary=b' }
      expect(last_response.status).to eq(415)
      post '/severance/queries', body, user.merge('CONTENT_TYPE' => 'multipart/form-data; boundary=b')
      expect(last_response.status).to eq(415)
    end

    it 'still accepts a url-encoded form on POST /severance/queries' do
      post '/severance/queries', 'query_id=count', user.merge('CONTENT_TYPE' => 'application/x-www-form-urlencoded')
      expect(last_response.status).to eq(201)
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

  describe 'expiry sweep' do
    it 'deletes old results and stuck jobs, never pending ones or anything recent' do
      old = Time.now - (RESULT_TTL_HOURS * 3600) - 60
      paths = {
        old_result: "#{ENV['RESULTS_DIR']}/#{SecureRandom.uuid}.enc",
        old_processing: "#{ENV['QUEUE_DIR']}/#{SecureRandom.uuid}.processing.json",
        old_pending: "#{ENV['QUEUE_DIR']}/#{SecureRandom.uuid}.pending.json",
        new_result: "#{ENV['RESULTS_DIR']}/#{SecureRandom.uuid}.enc"
      }
      paths.each { |_, p| File.write(p, 'x') }
      %i[old_result old_processing old_pending].each { |k| File.utime(old, old, paths[k]) }

      expect(sweep_expired!).to eq(results: 1, processing: 1)
      expect(paths.transform_values { |p| File.exist?(p) })
        .to eq(old_result: false, old_processing: false, old_pending: true, new_result: true)
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
