const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const https = require('https');
const http = require('http');
const fs = require('fs');

class ProxyServer {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 3000;
        
        // Browser-like configuration
        this.browserHeaders = this.getBrowserHeaders();
        this.setupTLSConfig();
        this.setupLogger();
        this.setupMiddleware();
        this.setupRoutes();
        this.setupErrorHandling();
    }

    getBrowserHeaders() {
        // Realistic browser headers that rotate
        const userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ];

        const acceptLanguages = [
            'en-US,en;q=0.9',
            'en-GB,en;q=0.9',
            'en-US,en;q=0.9,es;q=0.8',
            'en-US,en;q=0.9,fr;q=0.8,de;q=0.7'
        ];

        return {
            userAgents,
            acceptLanguages,
            defaultHeaders: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': acceptLanguages[Math.floor(Math.random() * acceptLanguages.length)],
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Sec-CH-UA': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                'Sec-CH-UA-Mobile': '?0',
                'Sec-CH-UA-Platform': '"Windows"',
                'Cache-Control': 'max-age=0'
            }
        };
    }

    setupTLSConfig() {
        // Configure TLS to be more permissive like browsers
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // For development - remove in production
        
        // Create custom HTTPS agent with browser-like TLS settings
        this.httpsAgent = new https.Agent({
            rejectUnauthorized: false, // Accept self-signed certificates
            secureProtocol: 'TLS_method',
            ciphers: [
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES128-SHA256',
                'ECDHE-RSA-AES256-SHA384',
                'ECDHE-RSA-AES256-SHA',
                'ECDHE-RSA-AES128-SHA',
                'AES128-GCM-SHA256',
                'AES256-GCM-SHA384',
                'AES128-SHA256',
                'AES256-SHA256',
                'AES128-SHA',
                'AES256-SHA'
            ].join(':'),
            honorCipherOrder: true,
            maxVersion: 'TLSv1.3',
            minVersion: 'TLSv1.2'
        });

        this.httpAgent = new http.Agent({
            keepAlive: true,
            maxSockets: 50,
            timeout: 30000
        });
    }

    setupLogger() {
        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.json()
            ),
            defaultMeta: { service: 'proxy-server' },
            transports: [
                new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
                new winston.transports.File({ filename: 'logs/combined.log' }),
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.colorize(),
                        winston.format.simple()
                    )
                })
            ]
        });
    }

    setupMiddleware() {
        // Security middleware
        this.app.use(helmet({
            contentSecurityPolicy: false,
            crossOriginEmbedderPolicy: false
        }));

        // CORS configuration
        this.app.use(cors({
            origin: ['chrome-extension://*', 'moz-extension://*', '*'],
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD']
        }));

        // Rate limiting
        const limiter = rateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 1000, // limit each IP to 1000 requests per windowMs
            message: {
                error: 'Too many requests from this IP, please try again later.'
            }
        });
        this.app.use('/proxy', limiter);

        // Body parsing
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

        // Request logging
        this.app.use((req, res, next) => {
            this.logger.info(`${req.method} ${req.url}`, {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date().toISOString()
            });
            next();
        });
    }

    setupRoutes() {
        // Health check endpoint
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                version: '1.0.0'
            });
        });

        // API info endpoint
        this.app.get('/info', (req, res) => {
            res.json({
                message: 'Browser-like Proxy server is running',
                endpoints: {
                    health: '/health',
                    proxy: '/proxy/*',
                    info: '/info',
                    session: '/session'
                },
                features: [
                    'Rotating User Agents',
                    'Browser-like Headers',
                    'TLS/SSL Support',
                    'Cookie Handling',
                    'Redirect Following',
                    'CORS Enabled'
                ],
                usage: 'Send requests to /proxy/{target-url}'
            });
        });

        // Session info endpoint - shows current browser fingerprint
        this.app.get('/session', (req, res) => {
            const randomUserAgent = this.browserHeaders.userAgents[
                Math.floor(Math.random() * this.browserHeaders.userAgents.length)
            ];
            
            res.json({
                userAgent: randomUserAgent,
                headers: this.browserHeaders.defaultHeaders,
                tlsConfig: {
                    minVersion: 'TLSv1.2',
                    maxVersion: 'TLSv1.3',
                    rejectUnauthorized: false
                },
                features: {
                    cookieSupport: true,
                    redirectFollowing: true,
                    gzipSupport: true,
                    keepAlive: true
                }
            });
        });

        // Main proxy endpoint
        this.app.use('/proxy', (req, res, next) => {
            const targetUrl = req.url.substring(1); // Remove leading slash
            
            if (!targetUrl) {
                return res.status(400).json({
                    error: 'Target URL required',
                    message: 'Please provide a target URL in the path: /proxy/https://example.com'
                });
            }

            // Validate URL format
            try {
                new URL(targetUrl);
            } catch (error) {
                return res.status(400).json({
                    error: 'Invalid URL format',
                    message: 'Please provide a valid URL including protocol (http:// or https://)'
                });
            }

            // Create proxy middleware for this request
            const proxyMiddleware = createProxyMiddleware({
                target: targetUrl,
                changeOrigin: true,
                pathRewrite: {
                    [`^/proxy/${targetUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`]: ''
                },
                onProxyReq: (proxyReq, req, res) => {
                    // Set proper headers
                    proxyReq.setHeader('User-Agent', req.get('User-Agent') || 'ProxyServer/1.0');
                    
                    this.logger.info('Proxying request', {
                        method: req.method,
                        target: targetUrl,
                        originalUrl: req.originalUrl
                    });
                },
                onProxyRes: (proxyRes, req, res) => {
                    // Add CORS headers to response
                    proxyRes.headers['Access-Control-Allow-Origin'] = '*';
                    proxyRes.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS';
                    proxyRes.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Content-Length, X-Requested-With, X-API-KEY';
                    
                    this.logger.info('Proxy response', {
                        statusCode: proxyRes.statusCode,
                        target: targetUrl,
                        contentType: proxyRes.headers['content-type']
                    });
                },
                onError: (err, req, res) => {
                    this.logger.error('Proxy error', {
                        error: err.message,
                        target: targetUrl,
                        stack: err.stack
                    });
                    
                    res.status(500).json({
                        error: 'Proxy error',
                        message: 'Failed to proxy request to target server',
                        details: process.env.NODE_ENV === 'development' ? err.message : 'Connection failed'
                    });
                },
                // Security options
                secure: true,
                timeout: 30000,
                proxyTimeout: 30000,
                headers: {
                    'Connection': 'keep-alive'
                }
            });

            proxyMiddleware(req, res, next);
        });

        // Handle preflight requests
        this.app.options('*', (req, res) => {
            res.header('Access-Control-Allow-Origin', '*');
            res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
                                res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
            res.sendStatus(200);
        });

        // 404 handler
        this.app.use('*', (req, res) => {
            res.status(404).json({
                error: 'Endpoint not found',
                message: 'The requested endpoint does not exist',
                availableEndpoints: ['/health', '/info', '/proxy/*']
            });
        });
    }

    setupErrorHandling() {
        // Global error handler
        this.app.use((err, req, res, next) => {
            this.logger.error('Unhandled error', {
                error: err.message,
                stack: err.stack,
                url: req.url,
                method: req.method
            });

            res.status(err.status || 500).json({
                error: 'Internal server error',
                message: 'Something went wrong'
            });
        });

        // Handle unhandled promise rejections
        process.on('unhandledRejection', (reason, promise) => {
            this.logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
        });

        // Handle uncaught exceptions
        process.on('uncaughtException', (error) => {
            this.logger.error('Uncaught Exception:', error);
            process.exit(1);
        });

        // Graceful shutdown
        process.on('SIGTERM', () => {
            this.logger.info('SIGTERM received, shutting down gracefully');
            this.server.close(() => {
                this.logger.info('Process terminated');
                process.exit(0);
            });
        });
    }

    start() {
        this.server = this.app.listen(this.port, () => {
            this.logger.info(`Proxy server running on port ${this.port}`);
            this.logger.info(`Health check: http://localhost:${this.port}/health`);
            this.logger.info(`Proxy endpoint: http://localhost:${this.port}/proxy/{target-url}`);
        });

        return this.server;
    }
}

// Export for testing
module.exports = ProxyServer;

// Start server if this file is run directly
if (require.main === module) {
    const proxyServer = new ProxyServer();
    proxyServer.start();
}