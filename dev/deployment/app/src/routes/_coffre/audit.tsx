import { createFileRoute } from '@tanstack/react-router';
import { audit } from '@coffre/ui';
import { AuditPage } from '@coffre/ui/pages/audit';

export const Route = createFileRoute('/_coffre/audit')({ ...audit, component: AuditPage });
