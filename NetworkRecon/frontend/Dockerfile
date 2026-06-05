# ===========================================
# Frontend Dockerfile - Nginx Alpine
# ===========================================

FROM nginx:alpine AS production

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/

# Copy static files
COPY src/ /usr/share/nginx/html/

# Set proper permissions
RUN chown -R nginx:nginx /usr/share/nginx/html/ && \
    chown -R nginx:nginx /var/cache/nginx/ && \
    chown -R nginx:nginx /var/log/nginx/ && \
    chown -R nginx:nginx /etc/nginx/conf.d/ && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid

# Expose ports
EXPOSE 80

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:80/ || exit 1

# Run nginx in foreground
CMD ["nginx", "-g", "daemon off;"]
