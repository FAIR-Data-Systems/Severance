#!/bin/bash
set -e

echo "=== Starting Severance Internal ==="

# Ensure the queries directory exists (as root, so we can create it if needed)
mkdir -p /queries

# Demo queries are OPT-IN. Every query in /queries is live -- anyone holding
# External's AUTH_TOKEN can run it -- so copying examples in by default meant
# every new install served queries the data provider never approved (one of
# them returns person-level rows). Set SEED_DEMO_QUERIES=true to copy them in on
# a first run (empty folder) for testing; delete the ones you don't want before
# real data goes in.
if [ -z "$(ls -A /queries 2>/dev/null)" ]; then
    if [ "${SEED_DEMO_QUERIES:-false}" = "true" ]; then
        echo "First run, SEED_DEMO_QUERIES=true → copying demo queries to your ./queries folder..."
        cp -r --no-preserve=ownership /demo-queries/* /queries/
        echo "Demo queries seeded. DELETE the ones you have not approved before real data goes in!"
    else
        echo "./queries is empty → no queries are available until you add your own."
        echo "(For testing, set SEED_DEMO_QUERIES=true to copy in the examples.)"
    fi
else
    echo "Using the queries in your ./queries folder."
fi

# Now fix ownership and permissions so the host user can edit everything
echo "Fixing ownership on /queries to match host user (${UID:-1000}:${GID:-1000})..."
chown -R "${UID:-1000}:${GID:-1000}" /queries
chmod -R u+rwX /queries

echo "Running as user ID: $(id -u)"

# Run the app as the correct (non-root) user
exec ruby innie.rb "$@"