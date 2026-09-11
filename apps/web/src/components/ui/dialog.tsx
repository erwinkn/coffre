import { Dialog as Primitive } from '@base-ui/react/dialog';
import { X } from 'lucide-react';
import type { ReactNode } from 'react';
import { Button } from './button';
export function Dialog({ open, onClose, title, description, children, drawer = false }: { open: boolean; onClose: () => void; title: string; description?: string; children: ReactNode; drawer?: boolean }) {
  return <Primitive.Root open={open} onOpenChange={value => { if (!value) onClose(); }}><Primitive.Portal><Primitive.Backdrop className="overlay" /><Primitive.Popup className={drawer ? 'drawer' : 'dialog'}><header className="dialog-header"><Primitive.Title>{title}</Primitive.Title><Primitive.Close render={<Button size="icon" variant="ghost" aria-label="Close dialog" />}><X size={16} /></Primitive.Close></header>{description && <Primitive.Description className="dialog-description">{description}</Primitive.Description>}<div className="dialog-body">{children}</div></Primitive.Popup></Primitive.Portal></Primitive.Root>;
}
