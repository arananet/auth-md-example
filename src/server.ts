import app from './app';
import { config } from './config';

app.listen(config.port, () => {
  console.log(`auth-md-example server running on port ${config.port}`);
});
