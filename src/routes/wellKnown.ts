import { Router, Request, Response } from 'express';
import path from 'path';

const router = Router();
const publicDir = path.join(__dirname, '../../public');

router.get('/.well-known/oauth-protected-resource', (_req: Request, res: Response) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Cache-Control', 'public, max-age=300');
  res.set('Content-Type', 'application/json');
  res.sendFile(path.join(publicDir, '.well-known/oauth-protected-resource'));
});

router.get('/.well-known/oauth-authorization-server', (_req: Request, res: Response) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Cache-Control', 'public, max-age=300');
  res.set('Content-Type', 'application/json');
  res.sendFile(path.join(publicDir, '.well-known/oauth-authorization-server'));
});

router.get('/auth.md', (_req: Request, res: Response) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Cache-Control', 'public, max-age=300');
  res.set('Content-Type', 'text/markdown; charset=utf-8');
  res.sendFile(path.join(publicDir, 'auth.md'));
});

export default router;
