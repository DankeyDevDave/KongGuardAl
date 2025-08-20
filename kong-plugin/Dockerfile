FROM kong:3.8.0

USER root

# Install build dependencies
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy plugin files
COPY ./kong /usr/local/share/lua/5.1/kong

# lua-resty-http is already included in Kong, skip installation

# Set environment variable to load our plugin
ENV KONG_PLUGINS=bundled,kong-guard-ai
ENV KONG_LUA_PACKAGE_PATH=/usr/local/share/lua/5.1/?.lua;;

# Shared memory is already configured in Kong

USER kong

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD kong health || exit 1