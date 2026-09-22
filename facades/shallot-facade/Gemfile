source 'https://rubygems.org'

gem 'sinatra', '~> 4.2'
gem 'puma', '~> 7.2'
gem 'rackup', '~> 2.3'
gem 'json', '~> 2.19'
# Unused by this app -- pinned purely to get a patched version into the Bundler-managed path;
# see the Dockerfile comment for why the base image's own stale default-gem copy still needs
# removing separately. Same pin as external/internal's own Gemfiles.
gem 'net-imap', '~> 0.5'

group :test do
  gem 'rspec', '~> 3.13'
  gem 'rack-test', '~> 2.2'
end
