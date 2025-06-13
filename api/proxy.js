const { createProxyMiddleware } = require('http-proxy-middleware');
const { createServer } = require('http');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000
});
app.use('/proxy', limiter);

// Proxy
app.use('/proxy/:url(*)', (req, res, next) => {
  const target = req.params.url;

  if (!/^https?:\/\//.test(target)) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  return createProxyMiddleware({
    target,
    changeOrigin: true,
    pathRewrite: { [`^/api/proxy/${target}`]: '' },
    onProxyReq: (proxyReq, req) => {
      proxyReq.setHeader('User-Agent', req.headers['user-agent'] || 'Vercel-Proxy');
    }
  })(req, res, next);
});

// Vercel handler
module.exports = (req, res) => {
  return app(req, res);
};
