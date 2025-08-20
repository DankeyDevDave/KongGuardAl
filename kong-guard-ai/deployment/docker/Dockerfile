# Kong Guard AI Production Dockerfile
# Production-ready Kong Gateway with Kong Guard AI plugin

FROM kong:3.4.2-alpine

# Metadata
LABEL maintainer="Kong Guard AI Team"
LABEL version="1.0.0"
LABEL description="Kong Gateway with Kong Guard AI security plugin"

# Switch to root for installation
USER root

# Install required packages
RUN apk add --no-cache \
    curl \
    jq \
    openssl \
    ca-certificates \
    luarocks \
    git \
    build-base \
    linux-headers

# Install Lua dependencies
RUN luarocks install lua-resty-http \
    && luarocks install lua-resty-jwt \
    && luarocks install lua-cjson \
    && luarocks install luasocket \
    && luarocks install luasec

# Create plugin directory
RUN mkdir -p /usr/local/share/lua/5.1/kong/plugins/kong-guard-ai

# Copy Kong Guard AI plugin files
COPY kong/plugins/kong-guard-ai/ /usr/local/share/lua/5.1/kong/plugins/kong-guard-ai/

# Copy plugin rock spec
COPY kong-plugin-kong-guard-ai-0.1.0-1.rockspec /tmp/

# Install the plugin
RUN cd /tmp && luarocks make kong-plugin-kong-guard-ai-0.1.0-1.rockspec

# Copy configuration files
COPY deployment/docker/kong.conf /etc/kong/kong.conf
COPY deployment/docker/kong-declarative.yml /etc/kong/kong-declarative.yml

# Create directories for logs and data
RUN mkdir -p /var/log/kong \
    && mkdir -p /var/lib/kong \
    && mkdir -p /etc/kong/certs

# Set ownership
RUN chown -R kong:kong /var/log/kong \
    && chown -R kong:kong /var/lib/kong \
    && chown -R kong:kong /etc/kong

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8001/status || exit 1

# Switch back to kong user
USER kong

# Expose ports
EXPOSE 8000 8001 8443 8444

# Default command
CMD ["kong", "start", "--vv"]