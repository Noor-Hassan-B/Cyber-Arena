# =========================================================================
# Multi-Stage Dockerfile for React SOC Frontend
# Stage 1: Build static assets with Node.js
# Stage 2: Serve with ultra-lightweight Alpine Nginx
# =========================================================================

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies with caching layer
COPY package.json ./
RUN npm install

# Copy application source code
COPY . .

# Compile optimized production bundle
RUN npm run build

# Stage 2: Production Nginx Runtime
FROM nginx:1.27-alpine AS production

LABEL maintainer="AegisHunt Platform Engineering <security@aegishunt.io>"
LABEL description="React Frontend Dashboard Container for Cyber Threat Hunting"

# Copy compiled static assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Add healthcheck instruction
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:80/healthz || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
