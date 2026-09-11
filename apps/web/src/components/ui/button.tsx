// Adapted from shadcn/ui's Base UI button (MIT), using Studio design tokens.
import { Button as ButtonPrimitive } from '@base-ui/react/button';
import { cva, type VariantProps } from 'class-variance-authority';
import { clsx } from 'clsx';
const buttonVariants = cva('button', { variants: { variant: { default: 'button-primary', outline: 'button-outline', ghost: 'button-ghost', destructive: 'button-danger' }, size: { default: '', sm: 'button-small', icon: 'icon-button' } }, defaultVariants: { variant: 'outline', size: 'default' } });
export function Button({ className, variant, size, ...props }: ButtonPrimitive.Props & VariantProps<typeof buttonVariants>) { return <ButtonPrimitive data-slot="button" className={clsx(buttonVariants({ variant, size }), className)} {...props} />; }
export { buttonVariants };
