import { createFileRoute } from '@tanstack/react-router';
import { approval } from '@coffre/ui';
import { ApprovalPage } from '@coffre/ui/pages/approval';

export const Route = createFileRoute('/_solo/approvals/$approval')({ ...approval, component: ApprovalPage });
