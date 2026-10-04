// An app's src/start.ts that left coffre's middleware out.
import { createStart } from '@tanstack/react-start';

export const startInstance = createStart(() => ({ requestMiddleware: [] }));
