import { dateFromExpiry, expiryFromDate } from '../lib/access-plan';
import { X } from './icons';

/**
 * When one grant ends, as a date: access lasts through that day, UTC. Blank
 * reads "Never" where the browser lets the empty field be restyled.
 */
export function ExpiryField({
  label,
  expiresAt,
  onChange,
}: {
  label: string;
  expiresAt: string | null;
  onChange: (expiresAt: string | null) => void;
}) {
  const date = dateFromExpiry(expiresAt);
  return (
    <span className={`expiry${date === '' ? ' is-never' : ''}`}>
      <input
        className="input select-sm"
        type="date"
        aria-label={label}
        min={new Date().toISOString().slice(0, 10)}
        value={date}
        onChange={(event) => onChange(expiryFromDate(event.target.value))}
      />
      <span className="expiry-never" aria-hidden="true">
        Never
      </span>
      <button
        className="btn btn-quiet btn-sm btn-icon"
        type="button"
        aria-label={`${label}: never`}
        title="Never expires"
        onClick={() => onChange(null)}
      >
        <X size={12} />
      </button>
    </span>
  );
}
