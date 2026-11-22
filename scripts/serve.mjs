// Local development server: node scripts/serve.mjs [port]
import { startServer } from './static-server.mjs';

const port = Number(process.argv[2] || process.env.PORT || 8000);
const { port: actual } = await startServer(port);
console.log(`STRIDE Threat Modeler on http://127.0.0.1:${actual}`);
