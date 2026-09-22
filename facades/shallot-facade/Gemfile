source 'https://rubygems.org'

gem 'sinatra', '~> 4.2'
gem 'puma', '~> 7.2'
gem 'rackup', '~> 2.3'
gem 'json', '~> 2.19'
# All three below are unused by this app -- each pinned purely to get a patched version into the
# Bundler-managed path; see the Dockerfile comment for why each base image's own stale default-gem
# copy still needs removing separately. Pinned exact (not ~>), unlike external/internal's own "~> 0.5"
# net-imap pin: since nothing here ever calls into any of them, there's no compatibility range to
# protect, so an exact pin means a Trivy finding against one can only ever be resolved by a deliberate
# version bump, never silently by a transitive resolver change.
gem 'erb', '6.0.7'
gem 'net-imap', '0.6.7'
gem 'resolv', '0.8.0'

group :test do
  gem 'rspec', '~> 3.13'
  gem 'rack-test', '~> 2.2'
end
