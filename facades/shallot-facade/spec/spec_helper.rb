# frozen_string_literal: true

# spec/spec_helper.rb
# Loaded automatically by RSpec (thanks to .rspec file or manual require)

RSpec.configure do |config|
  # Use the modern expect syntax
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  # Use the modern mock syntax
  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  # Run focused tests when you use `fit`, `fdescribe`, etc.
  config.filter_run_when_matching :focus

  # Disable RSpec's global monkey-patching (cleaner and faster)
  config.disable_monkey_patching!

  # Run specs in random order (helps catch order dependencies)
  config.order = :random

  # Seed for the random order
  Kernel.srand config.seed
end
