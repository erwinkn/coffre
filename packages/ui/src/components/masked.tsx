import { useEffect, useState, type InputHTMLAttributes, type TextareaHTMLAttributes } from 'react';

/**
 * A text field whose contents are masked until asked, for secret values.
 *
 * Where the browser supports it, the mask is CSS on a text input rather than
 * `type="password"`: password fields invite password managers to offer to
 * save or fill them, and a secret being typed into coffre is neither.
 */
export function MaskedInput({
  masked,
  className = '',
  ...props
}: Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & { masked: boolean }) {
  const cssMask = useCssMask();
  return (
    <input
      {...props}
      type={masked && !cssMask ? 'password' : 'text'}
      className={`${className}${masked && cssMask ? ' is-masked' : ''}`}
      autoComplete="off"
      spellCheck={false}
      data-1p-ignore
      data-lpignore="true"
      data-bwignore
    />
  );
}

function useCssMask(): boolean {
  const [cssMask, setCssMask] = useState(false);
  useEffect(() => {
    setCssMask(typeof CSS !== 'undefined' && CSS.supports('-webkit-text-security', 'disc'));
  }, []);
  return cssMask;
}

/**
 * MaskedInput for a value with line breaks, which a text input would drop.
 * Without the CSS mask there is no password textarea, so masked text is
 * drawn transparent instead.
 */
export function MaskedTextarea({
  masked,
  className = '',
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement> & { masked: boolean }) {
  const cssMask = useCssMask();
  return (
    <textarea
      {...props}
      className={`${className}${masked ? (cssMask ? ' is-masked' : ' is-masked-fallback') : ''}`}
      autoComplete="off"
      spellCheck={false}
      data-1p-ignore
      data-lpignore="true"
      data-bwignore
    />
  );
}
