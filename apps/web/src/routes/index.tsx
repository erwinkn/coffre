import { createFileRoute } from '@tanstack/react-router';
import { Console } from '../components/console';
export const Route = createFileRoute('/')({ validateSearch: (search: Record<string, unknown>) => ({ view: ['projects', 'secrets', 'environments', 'audit', 'access', 'settings'].includes(String(search.view)) ? String(search.view) : 'projects', project: typeof search.project === 'string' ? search.project : '', env: typeof search.env === 'string' ? search.env : '' }), component: Page });
function Page() { const search = Route.useSearch(); const navigate = Route.useNavigate(); return <Console search={search} navigate={(next) => void navigate({ search: { ...search, ...next } })} />; }
