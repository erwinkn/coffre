import { createFileRoute } from '@tanstack/react-router';
import { unregistered } from '@coffre/ui';
import { UnregisteredPage } from '@coffre/ui/pages/unregistered';

export const Route = createFileRoute('/_solo/unregistered')({ ...unregistered, component: UnregisteredPage });
