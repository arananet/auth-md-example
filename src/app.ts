import express from 'express';
import agentRoutes from './routes/agent';
import revokeRoutes from './routes/revoke';
import wellKnownRoutes from './routes/wellKnown';
import { authenticate } from './middleware/authenticate';
import { authenticatedLimiter } from './middleware/rateLimit';

const app = express();
app.use(express.json());

// Public discovery endpoints
app.use(wellKnownRoutes);

// Agentic registration (unauthenticated — rate-limited inside route)
app.use(agentRoutes);
app.use(revokeRoutes);

// Example protected resource endpoint
app.get('/api/resource', authenticate, authenticatedLimiter, (_req, res) => {
  res.json({ data: 'protected resource' });
});

export default app;
