# frozen_string_literal: true

require 'uri'

# Builds a Swagger 2.0 document (the same shape Shallot itself serves -- see
# `Data Service Configs/Shallot/shared-queries/current_yaml.json` in the FLAIR-GG repo) from
# Severance's own `GET /severance/available_queries` catalogue. This is deliberately modeled on
# Shallot's real output rather than a fresh design, since that exact shape is already proven to
# round-trip through the VP's swagger-converter -> Openapi3Parser pipeline
# (VP/vp-interface/lib/services.rb#retrieve_endpoint) with no VP-side change.
module OpenapiBuilder
  TYPE_MAP = {
    'string' => { 'type' => 'string' },
    'iri' => { 'type' => 'string', 'format' => 'uri' },
    'date' => { 'type' => 'string', 'format' => 'date' },
    'integer' => { 'type' => 'integer' },
    'float' => { 'type' => 'number' },
    'boolean' => { 'type' => 'boolean' }
  }.freeze

  # @param queries [Array<Hash>] the catalogue from SeveranceClient#available_queries
  # @param base_url [String] this facade's own externally-reachable base URL, e.g.
  #   "https://facade.example.org" -- must match the scheme/host/path prefix under which
  #   `dcat:endpointURL` will register each query's route (`<base_url>/<query_id>`), since the VP
  #   compares the two (ignoring scheme -- see Service#retrieve_endpoint).
  # @param produces [Array<String>] content type(s) this Severance deployment's RESULT_FORMAT
  #   actually returns -- there's no way to learn this from available_queries itself
  # @return [Hash] a Swagger 2.0 document
  def self.build(queries:, base_url:, produces: ['application/sparql-results+json'])
    uri = URI(base_url)

    {
      'swagger' => '2.0',
      'host' => uri.host + (uri.port && ![80, 443].include?(uri.port) ? ":#{uri.port}" : ''),
      'basePath' => (uri.path.empty? ? '/' : uri.path),
      'schemes' => [uri.scheme],
      'info' => {
        'title' => 'Severance data services (via shallot-facade)',
        'description' => 'Shallot-shaped facade in front of Severance -- see facades/shallot-facade/README.md',
        'version' => 'local'
      },
      'paths' => paths_for(queries, produces)
    }
  end

  def self.paths_for(queries, produces)
    queries.each_with_object({}) do |q, paths|
      paths["/#{q['query_id']}"] = { 'get' => path_item(q, produces) }
    end
  end
  private_class_method :paths_for

  def self.path_item(query, produces)
    {
      'summary' => query['summary'] || query['title'],
      'description' => query['description'],
      'tags' => query['tags'] || [],
      'parameters' => parameters_for(query),
      'produces' => produces,
      'responses' => {
        '200' => { 'description' => 'Query response' },
        'default' => { 'description' => 'Unexpected error' }
      }
    }
  end
  private_class_method :path_item

  def self.parameters_for(query)
    required = query['required'] || []
    # Severance's available_queries catalogue folds a query's #+ defaults: values (and enumerate
    # values, for a UI dropdown) into 'examples', not a 'defaults' key -- see
    # internal/innie.rb#process_queries. Confirmed against a real end-to-end run: a 'defaults' key is
    # never present here, only 'examples'.
    examples = query['examples'] || {}
    (query['variables'] || []).map do |name|
      {
        'name' => name,
        'in' => 'query',
        'required' => required.include?(name),
        **TYPE_MAP.fetch(query.dig('variable_types', name), TYPE_MAP['string'])
      }.tap { |param| param['default'] = examples[name] if examples.key?(name) }
    end
  end
  private_class_method :parameters_for
end
