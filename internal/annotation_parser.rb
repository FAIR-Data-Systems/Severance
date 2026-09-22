#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'pathname'

# Module for parsing SPARQL query files with special annotation comments.
#
# This module provides tools to extract structured metadata from query files
# that use #+ decorator comments, while preserving the original SPARQL query.
#
# Designed to work well with grlc-style queries and custom documentation needs.
module QueryAnnotationParser
  # Main parser class responsible for extracting metadata and query content
  # from annotated SPARQL files.
  class Parser
    # Parses a single SPARQL query file and returns structured metadata.
    #
    # @param file_path [String] Path to the .rq or .sparql file
    #
    # @return [Hash] Metadata hash containing query information and annotations
    # @option return [String] 'query_id'          Query identifier (defaults to filename)
    # @option return [String, nil] 'title'        Human-readable title
    # @option return [String, nil] 'summary'      Short summary of the query
    # @option return [String, nil] 'description'  Detailed description
    # @option return [String, nil] 'endpoint'     SPARQL endpoint URL
    # @option return [Integer, nil] 'pagination'  Default pagination size
    # @option return [String, nil] 'method'       HTTP method (GET/POST)
    # @option return [Boolean, nil] 'endpoint_in_url'  Whether endpoint is embedded in URL
    # @option return [Array<String>] 'tags'       List of tags
    # @option return [Hash] 'defaults'            Default parameter values
    # @option return [Hash] 'enumerate'           Enumeration lists for parameters
    # @option return [Array<String>] 'variables'  Detected query parameters
    # @option return [Hash] 'variable_types'      Parameter name → normalized type
    # @option return [Array<String>] 'required'   Names of parameters marked `required: true` in a
    #   `#+ parameters:` block
    # @option return [Array<Hash>] 'parameters'   Raw `#+ parameters:` block entries, one hash per
    #   parameter (`name`, `type`, `description`, `required`, `default`, whichever were given) --
    #   this is GRLC's own dialect for declaring a parameter that has no type-suffixed inline
    #   placeholder (`?_name` rather than `?_name_type`), as used by e.g. FLAIR-GG's
    #   `species_location.rq`. Every parameter found here is folded into `variables`/`variable_types`
    #   (without overwriting anything already found inline) and, when it has a `default`, into
    #   `defaults` -- so callers that only look at `variables`/`variable_types`/`defaults` don't need
    #   to know this block exists at all.
    # @option return [String] 'query'             The cleaned SPARQL query
    #
    # @example
    #   metadata = QueryAnnotationParser::Parser.parse("queries/countries.rq")
    #   puts metadata['title']
    def self.parse(file_path)
      content = File.read(file_path, encoding: 'UTF-8')
      lines = content.lines
      metadata = {
        'query_id' => File.basename(file_path, '.*'),
        'title' => nil,
        'summary' => nil,
        'description' => nil,
        'endpoint' => nil,
        'pagination' => nil,
        'method' => nil,
        'endpoint_in_url' => nil,
        'tags' => [],
        'defaults' => {},
        'enumerate' => {},
        'variables' => [],
        'variable_types' => {},
        'required' => [],
        'parameters' => [],
        'query' => ''
      }

      decorator_lines = []
      query_lines = []

      lines.each do |line|
        if line.strip.start_with?('#+')
          decorator_lines << line
        else
          query_lines << line
        end
      end

      # multi-line decorator parser
      parse_all_decorators(decorator_lines, metadata)
      metadata['query'] = query_lines.join("\n").strip

      # Extract grlc-style parameters (?_name_type)
      vars, types = extract_parameters(metadata['query'])
      metadata['variables'] = vars
      metadata['variable_types'] = types

      # Fold in any `#+ parameters:` block entries (GRLC's dialect for a parameter with no
      # type-suffixed inline placeholder) -- must run after extract_parameters above, which
      # otherwise-unconditionally overwrites 'variables'/'variable_types' wholesale.
      fold_parameters_block!(metadata)

      # Fallback query_id
      metadata['query_id'] = File.basename(file_path, '.*') if metadata['query_id'].nil? || metadata['query_id'].empty?

      warn "metadata for #{metadata['query_id']}: #{metadata.inspect}  "
      metadata
    end

    # ------------------------------------------------------------------
    # NEW parser that correctly handles tags, defaults, enumerate,
    # endpoint_in_url, and all simple key:value lines
    # ------------------------------------------------------------------
    #
    # @param decorator_lines [Array<String>] Lines starting with #+
    # @param metadata [Hash] The metadata hash to populate
    #
    # @note This is an internal method and subject to change.
    def self.parse_all_decorators(decorator_lines, metadata)
      current_key = nil
      current_list = nil
      current_param = nil # the parameter hash a "parameters:" continuation line belongs to

      decorator_lines.each do |line|
        clean = line.sub(/^#\+\s*/, '').strip
        next if clean.empty?

        # warn "Parsing decorator line: #{clean}  "

        # Section header like "tags:", "defaults:", "enumerate:", "parameters:"
        if clean.end_with?(':')
          key = clean.chomp(':').strip
          # warn "Found section header: #{key}  "

          case key
          when 'tags'
            metadata['tags'] = []
          when 'defaults'
            metadata['defaults'] = {}
          when 'enumerate'
            metadata['enumerate'] = {}
          when 'parameters'
            metadata['parameters'] = []
          end
          current_key = key
          current_list = nil
          current_param = nil
          next
        end
        # warn "Current key: #{current_key.inspect}, current list: #{current_list.inspect}  "
        # List item "- value" or "- key: value"
        if clean.start_with?('- ')
          item = clean.sub(/^- \s*/, '').strip
          case current_key
          when 'tags'
            metadata['tags'] << item
          when 'defaults'
            if item.include?(':')
              k, v = item.split(':', 2).map(&:strip)
              metadata['defaults'][k] = parse_value(v)
              # warn "→ Parsed default: #{k} → #{metadata['defaults'][k].inspect}  "
            end
          when 'enumerate'
            if item.include?(':') && item.end_with?(':')
              # "- country:" → start a new enumerate list
              enum_key = item.chomp(':').strip
              metadata['enumerate'][enum_key] ||= []
              current_list = metadata['enumerate'][enum_key]
            elsif current_list
              # subsequent "- value" lines belong to the current list
              current_list << parse_value(item)
            end
          when 'parameters'
            # "- name: speciesname" starts a new parameter entry; its continuation lines
            # (type/description/required/default/...) arrive as plain "key: value" lines below,
            # with no leading "- ", so they're routed by the `current_param` check in the
            # elsif branch rather than by this one.
            current_param = {}
            metadata['parameters'] << current_param
            if item.include?(':')
              k, v = item.split(':', 2).map(&:strip)
              current_param[k] = parse_value(v)
            end
          end

        # A "parameters:" continuation line (type/description/required/default/... belonging to the
        # current_param started by the last "- name: ..." list item) -- must be checked before the
        # generic fallback below, or it would be misread as a new top-level metadata key and would
        # also clear current_key, breaking every remaining line of this parameter.
        elsif current_key == 'parameters' && current_param && clean.include?(':')
          k, v = clean.split(':', 2).map(&:strip)
          current_param[k] = parse_value(v)

        # Simple one-line key: value (query_id, title, endpoint, endpoint_in_url, etc.)
        elsif clean.include?(':')
          key, val = clean.split(':', 2).map(&:strip)
          metadata[key] = parse_value(val)
          current_key = nil
        end
      end
    end

    # Folds `#+ parameters:` entries (GRLC's dialect for declaring a parameter that has no
    # type-suffixed inline placeholder, e.g. `?_speciesname` rather than `?_speciesname_string`) into
    # `variables`/`variable_types`/`defaults`/`required` -- called after `extract_parameters` has
    # already populated `variables`/`variable_types` from the query text, so callers that only look
    # at those (plus `defaults`) don't need to know the `parameters:` block exists. Never overwrites
    # a variable/type/default already found inline or in an explicit `#+ defaults:` block.
    #
    # @param metadata [Hash] the metadata hash being built by `.parse`
    def self.fold_parameters_block!(metadata)
      metadata['parameters'].each do |param|
        name = param['name']
        next unless name

        metadata['variables'] << name unless metadata['variables'].include?(name)
        metadata['variable_types'][name] ||= normalize_type(param['type'].to_s)
        metadata['defaults'][name] = param['default'] if param.key?('default') && !metadata['defaults'].key?(name)
        metadata['required'] << name if param['required'] == true && !metadata['required'].include?(name)
      end
    end

    # Helper to turn "18", "true", "\"John\"", "False" into proper Ruby types.
    #
    # @param val_str [String, nil] The string value to parse
    # @return [Integer, Float, Boolean, String, nil] Parsed Ruby value
    def self.parse_value(val_str)
      return nil if val_str.nil? || val_str.empty?

      v = val_str.strip
      if (v.start_with?('"') && v.end_with?('"')) || (v.start_with?("'") && v.end_with?("'"))
        v[1..-2]
      elsif v.match?(/^\d+$/)
        v.to_i
      elsif v.match?(/^\d+\.\d+$/)
        v.to_f
      elsif v.downcase == 'true'
        true
      elsif v.downcase == 'false'
        false
      else
        v
      end
    end

    # Extracts grlc-style parameters from the query text.
    #
    # Recognizes patterns like ?_name_integer or ?__country_iri
    #
    # @param query_text [String] The SPARQL query
    # @return [Array] Two-element array: [variables, variable_types]
    def self.extract_parameters(query_text)
      variables = []
      variable_types = {}

      query_text.scan(/\?(__?)(\w+)_([\w:]+)\b/) do |_, name, type_suffix|
        next if name.empty?

        param_name = name
        variables << param_name unless variables.include?(param_name)
        variable_types[param_name] = normalize_type(type_suffix)
      end

      [variables.uniq, variable_types]
    end

    # Normalizes grlc-style type suffixes to standard types.
    #
    # @param suffix [String] The type suffix from the parameter
    # @return [String] Normalized type: 'iri', 'integer', 'float', 'boolean', 'date', or 'string'
    def self.normalize_type(suffix)
      case suffix.downcase
      when 'iri', 'uri' then 'iri'
      when 'integer', 'int' then 'integer'
      when 'float', 'double', 'decimal' then 'float'
      when 'boolean', 'bool' then 'boolean'
      when 'date', 'datetime' then 'date'
      else 'string'
      end
    end

    # Processes all .rq and .sparql files in a folder recursively.
    #
    # @param folder_path [String] Path to the folder containing query files
    # @return [Array<Hash>] Array of metadata hashes, one per query file
    # @raise [RuntimeError] if the folder does not exist
    def self.process_folder(folder_path)
      folder = Pathname.new(folder_path)
      raise "Folder not found: #{folder_path}" unless folder.directory?

      results = []
      Dir[folder.join('**/*.{rq,sparql}')].sort.each do |file|
        puts "Processing: #{File.basename(file)}"
        metadata = parse(file)
        results << metadata
      end
      results
    end
  end
end
