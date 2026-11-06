#!/usr/bin/env ruby
# frozen_string_literal: true

require 'sinatra'
require 'json'
require 'securerandom'
require 'openssl'
require 'fileutils'
require 'ipaddr'

# Sinatra 4.x/rack-protection 4.x enable Rack::Protection::HostAuthorization
# by default, which rejects any Host header outside a small built-in
# allowlist (`localhost`, IP literals, etc.) with a bare 403 "Host not
# permitted" -- before any application code, including the `before` filter
# below, ever runs. `set :protection, except: :host_authorization` (the line
# this replaced) is Sinatra's documented way to disable one protection, but
# has proven unreliable across versions in this codebase's sibling projects
# (see Sextans-Suite's yarrrml-rml/t.rb and Daemon/transform-cdev2.rb, which
# hit the identical failure and document it in more detail) -- confirmed
# live here too: External still rejected requests addressed by any hostname
# other than `localhost`/an IP literal (e.g. `host.docker.internal`, or any
# real DNS name a deployment might put in EXTERNAL_URL) even with this
# setting in place. Monkeypatching `accepts?` directly is the fix that has
# actually held. HostAuthorization exists to defend against DNS-rebinding
# attacks, where a *browser* is tricked into sending a request with an
# attacker-chosen Host header; External doesn't render browser-served HTML
# or trust the Host header for anything security-sensitive (every mutating
# endpoint already requires its own Bearer token), so disabling this
# specific check costs nothing real here.
require 'rack/protection/host_authorization'
class Rack::Protection::HostAuthorization
  def accepts?(_request)
    true
  end
end

configure do
  set :server, 'puma'
  set :bind, '0.0.0.0'
  set :port, ENV.fetch('PORT', 4567).to_i
  # Let `error` blocks (see JSON::ParserError below) handle exceptions
  # regardless of RACK_ENV -- Sinatra's development-mode exception page
  # would otherwise intercept them before a custom handler ever runs.
  set :show_exceptions, :after_handler
  # Rack::MethodOverride (on by default for classic-style apps) reads the POST
  # body looking for a `_method` field -- i.e. it parses form/multipart bodies
  # before RefuseMultipart below, or any auth check, gets to see the request.
  # Nothing here uses `_method`.
  set :method_override, false
end

# Refuses multipart/form-data before anything parses it. Sinatra merges
# `request.params` (which includes a parsed multipart body) in dispatch!,
# *before* the `before` filter -- so every Rack multipart-parser bug was
# reachable without a token (e.g. GHSA-5v64-555j-wjxm, rack < 3.2.8: a crafted
# body is held in memory in full, enough to OOM this 512 MB container). No
# Severance route or known facade sends multipart -- callers send JSON, or a
# url-encoded form to POST /severance/queries -- so the whole parser is taken
# off the reachable surface instead of relying on it being bug-free.
class RefuseMultipart
  def initialize(app)
    @app = app
  end

  def call(env)
    if env['CONTENT_TYPE'].to_s.downcase.include?('multipart/')
      return [415, { 'content-type' => 'application/json' }, ['{"error":"multipart bodies are not accepted"}']]
    end

    @app.call(env)
  end
end
use RefuseMultipart

# Read once at boot from the same VERSION file the Dockerfile bakes in as an
# OCI label -- so the running service's version is queryable via GET
# /severance, not just visible on the image metadata.
SEVERANCE_VERSION = File.read(File.join(__dir__, 'VERSION')).strip

# Directory where pending and processing jobs are stored
QUEUE_DIR = ENV.fetch('QUEUE_DIR', '/data/queue')

# Directory where encrypted query results are stored
RESULTS_DIR = ENV.fetch('RESULTS_DIR', '/data/results')

# Debug - print ALL important variables
warn '=== Environment Debug ==='
warn "QUEUE_DIR = #{QUEUE_DIR.inspect}"
warn "RESULTS_DIR = #{RESULTS_DIR.inspect}"
warn "ENCRYPTION_KEY_HEX present = #{ENV['ENCRYPTION_KEY_HEX'] || ENV['ENCRYPTION_KEY_HEX_FILE'] ? 'YES' : 'NO'}"
warn "RESULT_FORMAT = #{ENV['RESULT_FORMAT'].inspect}"
warn '========================='

# Rack body wrapper that zeros out sensitive plaintext after the response
# has been fully flushed to the socket. Rack guarantees close is called
# after the last byte is written, so zeroing here is safe.
class ZeroingBody
  def initialize(data)
    @data = data
  end

  def each
    yield @data
  end

  def close
    return unless @data
    @data.replace("\0" * @data.bytesize)
    @data.clear
    @data = nil
    GC.start(full_mark: true, immediate_sweep: true) if defined?(GC)
  end
end

# AES-256-GCM encryption key derived from hex environment variable.
#
# Previously fell back to a fixed, literal default (published in this
# repo's own env_template/README as the example value) whenever
# ENCRYPTION_KEY_HEX wasn't set -- silently "encrypting" every result with
# a key anyone can read in this project's own source, giving a deployer who
# forgot to set it a false sense of security rather than an obvious error.
# Refusing to start is the fail-closed behavior this project uses
# everywhere else for exactly this class of mistake (see the IRI/encoding
# rejection paths in internal/innie.rb).
EXAMPLE_ENCRYPTION_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'

# Reads a secret from `<NAME>_FILE` (a path, e.g. a Docker secret mounted at
# /run/secrets/...) if that is set, otherwise from `<NAME>` itself. A secret
# in a plain environment variable is visible to anyone who can run
# `docker inspect` or read /proc/<pid>/environ; a file can be kept readable by
# this process only. Kept in sync with the identical helper in internal/innie.rb.
def env_secret(name)
  path = ENV["#{name}_FILE"].to_s.strip
  return ENV[name] if path.empty?

  File.read(path).strip
rescue SystemCallError => e
  abort "FATAL: #{name}_FILE is set, but #{path} cannot be read (#{e.class})."
end

raw_encryption_key_hex = env_secret('ENCRYPTION_KEY_HEX')&.strip
if raw_encryption_key_hex.nil? || raw_encryption_key_hex.empty?
  abort 'FATAL: ENCRYPTION_KEY_HEX is not set. Generate one with `openssl rand -hex 32` ' \
        'and set it identically on both External and Internal -- refusing to start with no key ' \
        'rather than silently falling back to a known, public default.'
elsif raw_encryption_key_hex == EXAMPLE_ENCRYPTION_KEY_HEX
  abort 'FATAL: ENCRYPTION_KEY_HEX is still the example value from env_template/README.md. ' \
        'Generate a real one with `openssl rand -hex 32` -- refusing to start with a key ' \
        'anyone can read in this project\'s own source.'
end
ENCRYPTION_KEY = [raw_encryption_key_hex].pack('H*')

# ============== Credentials: fail closed ==============
#
# Two distinct bearer secrets:
#   AUTH_TOKEN  -- presented by callers/facades on the public API.
#   INNIE_TOKEN -- presented only by Internal on its three calls
#                  (queue/pull, job result push, query catalogue push).
# Both are mandatory. Previously, an unset AUTH_TOKEN silently disabled
# authentication on the whole public API, and the shipped example value was
# accepted as-is; refusing to start is the same behaviour used for the
# encryption key above.
MIN_SECRET_LENGTH = 32
EXAMPLE_SECRETS = %w[YesItsMe changeme change-me secret password].freeze

def load_secret!(name)
  value = env_secret(name).to_s.strip
  if value.empty?
    abort "FATAL: #{name} is not set. Generate one with `openssl rand -hex 32` -- " \
          'refusing to start with authentication disabled.'
  end
  if value.length < MIN_SECRET_LENGTH || EXAMPLE_SECRETS.include?(value)
    abort "FATAL: #{name} is too short or is an example value. Generate one with " \
          "`openssl rand -hex 32` (minimum #{MIN_SECRET_LENGTH} characters)."
  end
  value
end

AUTH_TOKEN = load_secret!('AUTH_TOKEN')
INNIE_TOKEN = load_secret!('INNIE_TOKEN')
abort 'FATAL: INNIE_TOKEN must differ from AUTH_TOKEN.' if AUTH_TOKEN == INNIE_TOKEN

# Hard limits (bytes / counts); override via environment if a deployment needs more.
MAX_REQUEST_BYTES  = ENV.fetch('MAX_REQUEST_BYTES', 64 * 1024).to_i          # POST /severance/queries
MAX_CATALOG_BYTES  = ENV.fetch('MAX_CATALOG_BYTES', 2 * 1024 * 1024).to_i    # POST /severance/available_queries
MAX_RESULT_BYTES   = ENV.fetch('MAX_RESULT_BYTES', 256 * 1024 * 1024).to_i   # POST /severance/jobs/:uuid/result
MAX_PENDING_JOBS   = ENV.fetch('MAX_PENDING_JOBS', 1000).to_i

UUID_RE = /\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/.freeze

# Content-Type for query results (json or csv)
CONTENT_TYPE = ENV['RESULT_FORMAT'] == 'csv' ? 'text/csv' : 'application/sparql-results+json'

# How long an uncollected result, or a job stuck in "processing" (Internal
# took it but never answered), may sit on disk. Results are encrypted, but an
# answer nobody collects should not wait forever for whoever eventually learns
# its job id -- and without this, stuck jobs answered "processing" forever.
# Pending jobs are never expired: Internal being off for a while must not lose
# requests. 0 disables the sweep.
RESULT_TTL_HOURS = ENV.fetch('RESULT_TTL_HOURS', 168).to_i

# Deletes results and "processing" job files older than RESULT_TTL_HOURS.
# Logs counts only, never job ids.
#
# @param now [Time] the reference time (injectable for tests)
# @return [Hash] how many files of each kind were deleted
def sweep_expired!(now = Time.now)
  cutoff = now - (RESULT_TTL_HOURS * 3600)
  expired = lambda do |pattern|
    Dir[pattern].count do |path|
      File.mtime(path) < cutoff && File.delete(path)
    rescue Errno::ENOENT
      false # collected or swept concurrently
    end
  end
  counts = { results: expired.call("#{RESULTS_DIR}/*.enc"),
             processing: expired.call("#{QUEUE_DIR}/*.processing.json") }
  warn "Expired #{counts[:results]} uncollected result(s), #{counts[:processing]} stuck job(s)" if counts.values.sum.positive?
  counts
end

if RESULT_TTL_HOURS.positive? && !Sinatra::Application.test?
  Thread.new do
    loop do
      begin
        sweep_expired!
      rescue StandardError => e
        warn "⚠ Expiry sweep failed: #{e.class} - #{e.message}"
      end
      sleep 3600
    end
  end
end

# Create required directories on startup
begin
  FileUtils.mkdir_p([QUEUE_DIR, RESULTS_DIR])
  warn "✓ Successfully created directories: #{QUEUE_DIR} and #{RESULTS_DIR}"
rescue Errno::EACCES => e
  warn "❌ Permission error creating directories: #{e.message}"
  warn ' Make sure the volume is mounted and the user has write access.'
  raise
end

# ============== AES-256-GCM helpers ==============

# Encrypts data using AES-256-GCM.
#
# @param data [String] Plaintext data to encrypt
# @return [String] Encrypted binary data (nonce + tag + ciphertext)
def encrypt(data, aad)
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  cipher.key = ENCRYPTION_KEY
  nonce = cipher.random_iv
  cipher.auth_data = aad.to_s
  ciphertext = cipher.update(data) + cipher.final
  tag = cipher.auth_tag
  nonce + tag + ciphertext
end

# Decrypts data previously encrypted with {#encrypt}.
#
# @param encrypted [String] Binary encrypted data (nonce + tag + ciphertext)
# @param aad [String] Additional authenticated data -- the job UUID the blob must belong to
# @return [String] Decrypted plaintext
# @raise [OpenSSL::Cipher::CipherError] if decryption fails (wrong key, tampered data, etc.)
def decrypt(encrypted, aad)
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.decrypt
  cipher.key = ENCRYPTION_KEY
  nonce = encrypted[0, 12]
  tag = encrypted[12, 16]
  ct = encrypted[28..]
  cipher.iv = nonce
  cipher.auth_tag = tag
  cipher.auth_data = aad.to_s
  cipher.update(ct) + cipher.final
end

# Raised when a request body claims to be JSON but contains a byte sequence
# that isn't valid UTF-8. `JSON.parse` itself does not reject this -- it
# happily returns a String tagged UTF-8 whose bytes are invalid, which then
# blows up with an uncaught ArgumentError/Encoding::CompatibilityError the
# moment any ordinary string method (`.strip`, string interpolation, etc.)
# touches it later in the request. Caught in the same place, and treated the
# same way, as a `JSON::ParserError` (see the `error JSON::ParserError`
# handler below) -- from an API consumer's perspective a body that isn't
# valid UTF-8 is just as malformed as one that isn't valid JSON syntax.
class InvalidBodyEncodingError < StandardError; end
class PayloadTooLargeError < StandardError; end

# Reads and returns `request.body`, raising InvalidBodyEncodingError if it
# is not valid UTF-8. Call this before JSON.parse-ing a request body so the
# malformed-encoding case is rejected up front, not discovered later by
# whichever string method happens to touch the bad bytes first.
def read_utf8_body!(limit = MAX_REQUEST_BYTES)
  raw = request.body.read(limit + 1) || ''
  raise PayloadTooLargeError if raw.bytesize > limit
  raise InvalidBodyEncodingError unless raw.dup.force_encoding(Encoding::UTF_8).valid_encoding?

  raw
end

# ============== Security: Internal IP filtering for sensitive endpoints ==============

# Whether `client_ip` is covered by `entry`, an ALLOWED_INTERNAL_IPS list
# item -- either the literal keyword "localhost", a bare IP (unchanged
# behavior from before), or now also a CIDR range (e.g. "192.168.1.0/24").
# A malformed entry is skipped (logged, not matched) rather than crashing
# the whole check -- one bad entry in the list shouldn't take down every
# request to these internal-only endpoints. IPAddr#include? itself returns
# false (doesn't raise) when comparing across address families (e.g. a v4
# range against a v6 client), so no special-casing is needed for that.
def internal_ip_allowed?(entry, client_ip)
  return ['127.0.0.1', '::1'].include?(client_ip) if entry == 'localhost'

  IPAddr.new(entry).include?(IPAddr.new(client_ip))
rescue ArgumentError => e
  # IPAddr::Error (raised for a malformed entry/IP) is itself a subclass of
  # ArgumentError -- rescuing both would be redundant.
  warn "⚠ Skipping invalid ALLOWED_INTERNAL_IPS entry #{entry.inspect}: #{e.message}"
  false
end

# Constant-time check of an `Authorization: Bearer <token>` header. The scheme
# is matched case-insensitively (RFC 7235); the token itself is matched exactly,
# and both sides are hashed first so neither length nor content leaks via timing.
def bearer_ok?(header, expected)
  return false unless header

  scheme, token = header.split(' ', 2)
  return false unless scheme&.casecmp?('Bearer') && token

  Rack::Utils.secure_compare(OpenSSL::Digest::SHA256.digest(token),
                             OpenSSL::Digest::SHA256.digest(expected))
end

# Minimal in-process throttle on FAILED authentication, per client IP: after
# AUTH_FAIL_LIMIT failures within AUTH_FAIL_WINDOW seconds, further requests from
# that IP get 429 until the window passes. (Behind a reverse proxy, make sure
# the proxy forwards the real client address -- otherwise all callers share one
# bucket.) Not a substitute for rate limiting at the proxy, but it removes the
# "unlimited online guessing" case without adding a dependency.
AUTH_FAIL_LIMIT  = ENV.fetch('AUTH_FAIL_LIMIT', 10).to_i
AUTH_FAIL_WINDOW = ENV.fetch('AUTH_FAIL_WINDOW', 60).to_i
AUTH_FAILURES = {}
AUTH_FAILURES_LOCK = Mutex.new

def auth_throttled?(ip)
  AUTH_FAILURES_LOCK.synchronize do
    cutoff = Time.now.to_f - AUTH_FAIL_WINDOW
    stamps = (AUTH_FAILURES[ip] || []).select { |t| t > cutoff }
    AUTH_FAILURES[ip] = stamps
    stamps.size >= AUTH_FAIL_LIMIT
  end
end

def record_auth_failure(ip)
  AUTH_FAILURES_LOCK.synchronize do
    AUTH_FAILURES.clear if AUTH_FAILURES.size > 10_000 # bound memory under address-spraying
    (AUTH_FAILURES[ip] ||= []) << Time.now.to_f
  end
end

# Requires a valid bearer token (or halts 401/429). Never logs the expected token
# or the caller-supplied header -- the latter could itself be a leaked valid
# token from elsewhere, and container logs have a wider audience than anyone
# who should know the token.
#
# `throttle: false` is for Innie's own routes. Without it, Innie shared its
# failure bucket with the public routes, keyed on `request.ip` -- which Rack
# takes from X-Forwarded-For whenever the TCP peer is a private address (Docker's
# userland proxy, a reverse proxy, any LAN host). Ten bad-token requests to a
# public route claiming Innie's address then 429'd Innie's own polls, repeatable
# every AUTH_FAIL_WINDOW: a one-request-per-6-seconds stop of the whole pipeline.
# Innie's routes are already IP-filtered and need a >= 32-char random secret, so
# online guessing there is not a real risk worth that lockout.
def require_bearer!(expected, throttle: true)
  ip = request.ip
  if throttle && auth_throttled?(ip)
    halt 429, { 'Retry-After' => AUTH_FAIL_WINDOW.to_s }, 'Too many failed attempts'
  end
  return if bearer_ok?(request.env['HTTP_AUTHORIZATION'], expected)

  record_auth_failure(ip) if throttle
  state = request.env['HTTP_AUTHORIZATION'] ? 'present but did not match' : 'missing'
  warn "Auth failed from #{ip}: Authorization header #{state}"
  halt 401, 'Unauthorized'
end

# Security filter applied to every request.
#
# - The three routes used only by Innie -- `GET /severance/queue/pull`,
#   `POST /severance/jobs/:uuid/result`, `POST /severance/available_queries` --
#   require BOTH an allow-listed client IP (ALLOWED_INTERNAL_IPS; each entry a
#   bare IP or CIDR) AND `Authorization: Bearer <INNIE_TOKEN>`. The IP check is
#   defense in depth only: a source address is not an identity.
# - Every other endpoint requires `Authorization: Bearer <AUTH_TOKEN>`.
# - Each route is matched exactly by method + path, never by path prefix alone
#   (a prefix match once made the caller-facing GET routes unreachable).
# - Oversized requests are refused up front by declared Content-Length; bodies are
#   additionally read with a hard cap where they are consumed.
before do
  is_internal_get = request.request_method == 'GET' && request.path_info == '/severance/queue/pull'
  is_result_post = request.request_method == 'POST' && request.path_info =~ %r{\A/severance/jobs/[^/]+/result\z}
  is_catalog_post = request.request_method == 'POST' && request.path_info == '/severance/available_queries'

  limit = if is_result_post then MAX_RESULT_BYTES
          elsif is_catalog_post then MAX_CATALOG_BYTES
          else MAX_REQUEST_BYTES
          end

  if is_internal_get || is_result_post || is_catalog_post
    allowed_entries = (ENV['ALLOWED_INTERNAL_IPS'] || '127.0.0.1,::1,localhost').split(',').map(&:strip)
    client_ip = request.ip
    halt 403, 'Access denied' unless allowed_entries.any? { |entry| internal_ip_allowed?(entry, client_ip) }
    require_bearer!(INNIE_TOKEN, throttle: false)
  else
    require_bearer!(AUTH_TOKEN)
  end

  halt 413, { error: 'payload_too_large' }.to_json if request.content_length.to_i > limit
end

# Submits a new query job for asynchronous execution.
#
# Accepts either JSON body or form parameters.
#
# @return [201] with `Location` header pointing to the job status
# @return [400] if `query_id` is missing or empty
post '/severance/queries' do
  # Safely parse input whether it's JSON or form data
  data = if request.content_type&.include?('application/json')
           JSON.parse(read_utf8_body!)
         else
           # For form-encoded or query params
           { 'query_id' => params['query_id'], 'bindings' => params.except('query_id') }
         end

  # Ensure we have a hash and extract query_id safely
  query_id = data.is_a?(Hash) ? data['query_id'] : nil
  halt 400, { error: 'query_id is required' }.to_json if query_id.nil? || query_id.to_s.strip.empty?

  # query_id ends up as a bare filename component on Internal's side
  # (`#{QUERY_DIR}/#{query_id}.rq` in innie.rb) with no further sanitization
  # there. Without this whitelist a caller could set query_id to something
  # like `../demo-queries/count` and make Internal read and execute a .rq
  # file the deployer never installed/vetted in their own QUERY_DIR --
  # defeating "queries are named and pre-approved, not arbitrary" entirely.
  # Same flat, slash-free convention used for this exact purpose elsewhere
  # in this project family (yarrrml-rml's `t.rb` type whitelist).
  unless query_id.to_s.strip.match?(/\A[a-zA-Z0-9_-]+\z/)
    halt 400, { error: 'query_id contains invalid characters' }.to_json
  end

  bindings = data['bindings'] || {}
  halt 400, { error: 'bindings must be an object' }.to_json unless bindings.is_a?(Hash)

  # Bound the queue: refuse new work rather than let disk usage grow without limit.
  if Dir["#{QUEUE_DIR}/*.pending.json"].size >= MAX_PENDING_JOBS
    halt 429, { 'Retry-After' => '60' }, { error: 'queue_full' }.to_json
  end

  uuid = SecureRandom.uuid
  job = {
    'query_id' => query_id.to_s.strip,
    'bindings' => bindings,
    'submitted_at' => Time.now.to_i
  }

  File.write("#{QUEUE_DIR}/#{uuid}.pending.json", JSON.generate(job))

  status 201
  # PUBLIC_BASE_URL (if set) is used instead of the request's Host header, which
  # HostAuthorization no longer vets (see top of file).
  headers 'Location' => "#{(ENV['PUBLIC_BASE_URL'] || request.base_url).chomp('/')}/severance/jobs/#{uuid}"
  body ''
end

# ============== Catalog: Receive and serve list of available queries ==============

# Receives the full list of available queries from Innie and saves it to disk.
#
# @return [200] on success with count
# @return [400] if JSON is invalid
# @return [500] on other errors
post '/severance/available_queries' do
  queries = JSON.parse(read_utf8_body!(MAX_CATALOG_BYTES))
  metadata_dir = ENV.fetch('METADATA_DIR', '/queries-metadata')
  warn "Metadata directory for available queries: #{metadata_dir}"
  active_queries_path = "#{metadata_dir}/active_queries.json"
  begin
    File.write(active_queries_path, JSON.pretty_generate(queries))
  rescue Errno::EACCES => e
    warn "❌ Permission error writing available queries: #{e.message}"
    halt 500, { error: 'Permission denied writing available queries' }.to_json
  end
  warn "✓ Received and saved #{queries.size} available queries to #{active_queries_path}"

  status 200
  content_type 'application/json'
  body({ success: true, count: queries.size }.to_json)
rescue PayloadTooLargeError
  status 413
  content_type 'application/json'
  body({ error: 'payload_too_large' }.to_json)
rescue JSON::ParserError, InvalidBodyEncodingError => e
  warn "❌ Invalid JSON in /available_queries: #{e.message}"
  status 400
  content_type 'application/json'
  body({ error: 'Invalid JSON' }.to_json)
rescue StandardError => e
  warn "❌ Error saving available queries: #{e.message}"
  status 500
  content_type 'application/json'
  body({ error: 'Internal server error' }.to_json)
end

# Returns the current list of available queries (previously pushed by Innie).
get '/severance/available_queries' do
  metadata_dir = ENV.fetch('METADATA_DIR', '/queries-metadata')
  active_queries_path = "#{metadata_dir}/active_queries.json"

  if File.exist?(active_queries_path)
    content_type 'application/json'
    File.read(active_queries_path)
  else
    status 404
    content_type 'application/json'
    body({ error: 'No queries available yet' }.to_json)
  end
end

# ============== Status / Result retrieval ==============

# Returns the status or result of a job.
#
# @param uuid [String] Job UUID
# @return [202] if still processing
# @return [200] with result (and deletes files) if completed
# @return [404] if job not found
get '/severance/jobs/:uuid' do |uuid|
  halt 404, '{"error":"not found"}' unless uuid.match?(UUID_RE)

  pending     = "#{QUEUE_DIR}/#{uuid}.pending.json"
  processing  = "#{QUEUE_DIR}/#{uuid}.processing.json"
  result_file = "#{RESULTS_DIR}/#{uuid}.enc"

  if File.exist?(pending) || File.exist?(processing)
    status 202
    headers 'Retry-After' => '10'
    body '{"status":"processing"}'

  elsif File.exist?(result_file)
    plaintext = nil

    begin
      encrypted = File.binread(result_file)

      # Decrypt
      plaintext = decrypt(encrypted, uuid)

      # Hand plaintext to ZeroingBody, which yields it to Puma then zeros
      # it in close — called by Rack after the last byte hits the socket.
      content_type CONTENT_TYPE
      body ZeroingBody.new(plaintext)
      plaintext = nil # ZeroingBody is now sole owner

      # Clean up files
      File.delete(result_file) if File.exist?(result_file)
      File.delete(processing) if File.exist?(processing)
    rescue OpenSSL::Cipher::CipherError => e
      warn "[ERROR] Decryption failed for #{uuid}: #{e.message}"
      status 500
      body 'Decryption error'
    rescue StandardError => e
      warn "[ERROR] Serving result #{uuid}: #{e.message}"
      status 500
      body 'Server error'
    ensure
      # Safety net: zero plaintext if an exception fired before ZeroingBody took ownership
      if plaintext
        plaintext.replace("\0" * plaintext.bytesize)
        plaintext.clear
        plaintext = nil
        GC.start(full_mark: true, immediate_sweep: true) if defined?(GC)
      end
    end

  else
    status 404
    body '{"error":"not found"}'
  end
end

# ============== Internal: Push result from "Innie" ==============

# Receives the execution result from Innie and stores it encrypted.
#
# @param uuid [String] Job UUID
post '/severance/jobs/:uuid/result' do |uuid|
  halt 400, 'Invalid job id' unless uuid.match?(UUID_RE)

  # Read the incoming encrypted payload as raw binary, with a hard size cap
  encrypted_data = (request.body.read(MAX_RESULT_BYTES + 1) || '').force_encoding(Encoding::BINARY)
  halt 413, 'Result too large' if encrypted_data.bytesize > MAX_RESULT_BYTES
  if encrypted_data.empty? || encrypted_data.bytesize < 28 # minimum size for AES-GCM (nonce+tag+ciphertext)
    halt 400, 'Invalid or empty result data'
  end

  result_file = "#{RESULTS_DIR}/#{uuid}.enc"
  processing  = "#{QUEUE_DIR}/#{uuid}.processing.json"

  # Only accept a result for a job Internal actually took from the queue (and has not answered yet).
  # Without this, anything holding Internal's credentials could plant an answer under any job id --
  # one still waiting in the queue, or one answered and collected already. The same kind of flaw as
  # Vantage6's GHSA-82rc-cpqj-9926 ("socket data is trusted without verification").
  halt 409, 'No such job in progress' unless File.exist?(processing)

  # Write the already-encrypted data directly to disk
  File.binwrite(result_file, encrypted_data)

  # Clean up the processing marker
  File.delete(processing) if File.exist?(processing)

  status 200
  body ''
end
# ============== Internal: Poll for next job ==============

# Internal endpoint used by Innie to pull the next pending job.
#
# Returns 204 No Content if queue is empty.
get '/severance/queue/pull' do
  pending_files = Dir["#{QUEUE_DIR}/*.pending.json"].sort
  if pending_files.empty?
    status 204
    body ''
  else
    file = pending_files.first
    uuid = File.basename(file, '.pending.json')
    job_json = File.read(file)

    # Move to processing
    File.rename(file, "#{QUEUE_DIR}/#{uuid}.processing.json")

    # Add uuid to the response
    job = JSON.parse(job_json)
    job['uuid'] = uuid

    content_type 'application/json'
    body JSON.generate(job)
  end
end

# Optional helper route - health check / info
get '/severance' do
  "Outie service ready (v#{SEVERANCE_VERSION}). Use /severance/queries to submit jobs."
end

# Malformed JSON in a request body -- POST /severance/queries, the main
# externally-facing endpoint, had no rescue around its JSON.parse at all,
# so a caller sending broken JSON hit an unhandled exception (a generic
# 500, indistinguishable from a real server-side fault) rather than a
# clean 400. This is a catch-all safety net for any route in this file
# that doesn't already handle it locally (POST /severance/available_queries
# already has its own JSON::ParserError/InvalidBodyEncodingError rescue,
# kept as-is).
#
# InvalidBodyEncodingError is included here too: a body that parses as
# syntactically valid JSON but contains a string with an invalid UTF-8 byte
# sequence used to sail straight through JSON.parse (which does not
# validate encoding) and crash later -- with a full stack trace leaked to
# the caller -- the instant something as ordinary as `.strip` touched the
# tainted string (see `read_utf8_body!`, which now catches this up front).
error PayloadTooLargeError do
  content_type 'application/json'
  status 413
  { error: 'payload_too_large' }.to_json
end

error JSON::ParserError, InvalidBodyEncodingError do
  content_type 'application/json'
  status 400
  { error: 'invalid_json' }.to_json
end
