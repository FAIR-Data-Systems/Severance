# frozen_string_literal: true

# Caches Severance's `GET /severance/available_queries` catalogue in memory, keyed by `query_id`.
# Lazily fetched on first use (not at construction) so building one doesn't make a network call before
# the app has even started serving -- and, incidentally, so requiring app.rb in a spec never triggers
# a real HTTP request either. Refreshed on a lookup miss (a query not yet in the cache might just have
# been installed on Severance Internal since the facade last asked) rather than on a timer, so there's
# nothing to configure and nothing running in the background -- a plain request-driven cache.
class QueryCatalogue
  def initialize(severance_client)
    @severance_client = severance_client
    @by_id = nil # nil (not yet fetched) vs {} (fetched, empty) are meaningfully different
  end

  # @param query_id [String]
  # @return [Hash, nil] the catalogue entry, or nil if it doesn't exist even after a refresh
  def find(query_id)
    refresh if @by_id.nil?
    return @by_id[query_id] if @by_id.key?(query_id)

    refresh
    @by_id[query_id]
  end

  # @return [Array<Hash>] every known catalogue entry, current as of the last successful fetch
  def all
    refresh if @by_id.nil?
    @by_id.values
  end

  private

  # Best-effort: a transient Severance outage shouldn't take this facade down or blank out an
  # already-known catalogue -- callers just keep serving whatever was last fetched successfully.
  def refresh
    @by_id = @severance_client.available_queries.to_h { |q| [q['query_id'], q] }
    true
  rescue SeveranceClient::CatalogueFetchFailed => e
    warn "shallot-facade: catalogue refresh failed, keeping previous catalogue: #{e.message}"
    @by_id ||= {} # never leave it nil, or every subsequent call would retry the failed fetch forever
    false
  end
end
