import { useEffect, useId, useState } from 'react';
import {
  DEFAULT_RECIPE,
  ENCODINGS,
  encodedLength,
  generate,
  MAX_BYTES,
  MIN_BYTES,
  PAIRS,
  pairNameProblem,
  publicKeyName,
  type AesSize,
  type Encoding,
  type Generated,
  type Recipe,
} from '../lib/generate';
import type { Companion } from '../lib/secret-edit-batch';
import { secretKeyProblem } from '../lib/validation';
import { Eye, EyeOff, Shuffle } from './icons';
import { MaskedInput } from './masked';
import { ErrorLine, Modal } from './ui';

/**
 * What Use hands the row: its value, its name as the dialog left it (only a
 * new row's can change), and for a key pair the public key it saves with it.
 */
export type GeneratedUse = { value: string; name: string; companion?: Companion };

type Kind = Recipe['kind'];

const KINDS: { id: Kind; name: string }[] = [
  { id: 'random', name: 'Random value' },
  { id: 'aes', name: 'AES-GCM key' },
  { id: 'pair', name: 'Key pair' },
];

/**
 * Make a value for a secret's field, in the browser: Use fills the field, as
 * typing would, and the row saves it with the rest.
 *
 * The dialog's content unmounts as it closes, so each opening draws a new
 * value and nothing generated stays in memory behind a cancel.
 */
export function GenerateValue({
  open,
  onOpenChange,
  name,
  renamable,
  companion,
  onUse,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The row's name, which a key pair's private key keeps. */
  name: string;
  /** A new row's name can be set here; a saved secret's is renamed in its row. */
  renamable: boolean;
  /** The public key of a pair generated here before, which a new pair replaces. */
  companion: Companion | undefined;
  onUse: (use: GeneratedUse) => void;
}) {
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Generate a value" description="Made in this browser. It is sent only when you save the row.">
      <GenerateForm
        name={name}
        renamable={renamable}
        publicName={companion?.key}
        onCancel={() => onOpenChange(false)}
        onUse={(use) => {
          onUse(use);
          onOpenChange(false);
        }}
      />
    </Modal>
  );
}

function GenerateForm({
  name,
  renamable,
  publicName: pendingPublicName,
  onCancel,
  onUse,
}: {
  name: string;
  renamable: boolean;
  publicName?: string;
  onCancel: () => void;
  onUse: (use: GeneratedUse) => void;
}) {
  const id = useId();
  // Each kind keeps its own choices, so trying another and coming back finds them as left.
  // A row that already holds a generated pair opens on Key pair, to make another.
  const [kind, setKind] = useState<Kind>(pendingPublicName === undefined ? DEFAULT_RECIPE.kind : 'pair');
  const [encoding, setEncoding] = useState<Encoding>('base62');
  const [bytes, setBytes] = useState(32);
  // What the number field shows while a length is being typed, "" or "3" on the way to "300".
  const [bytesText, setBytesText] = useState('32');
  const [size, setSize] = useState<AesSize>(256);
  const [pair, setPair] = useState(0);
  const [round, setRound] = useState(0);
  const [generated, setGenerated] = useState<Generated | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [privateName, setPrivateName] = useState(name);
  // Follows the private key's name until it is typed in, or the row it replaces names it.
  const [publicName, setPublicName] = useState<string | null>(pendingPublicName ?? null);

  const recipe: Recipe =
    kind === 'random'
      ? { kind, encoding, bytes }
      : kind === 'aes'
        ? { kind, size }
        : { kind, ...PAIRS[pair]! };
  const recipeKey = JSON.stringify(recipe);

  useEffect(() => {
    let current = true;
    setGenerated(null);
    setError(null);
    generate(recipe).then(
      (made) => current && setGenerated(made),
      (failure: unknown) =>
        current && setError(failure instanceof Error ? failure.message : 'The browser made no value.'),
    );
    return () => {
      current = false;
    };
    // The recipe is a new object each render; its content is what counts.
  }, [recipeKey, round]);

  const publicKey = publicName ?? publicKeyName(privateName);
  const nameProblem = kind === 'pair' ? pairNameProblem(privateName, publicKey) : null;
  const ready = generated !== null && nameProblem === null;

  function use() {
    if (!ready) return;
    onUse(
      kind === 'pair' && generated.publicKey !== undefined
        ? {
            value: generated.value,
            name: privateName.trim(),
            companion: { key: publicKey.trim(), value: generated.publicKey },
          }
        : { value: generated.value, name },
    );
  }

  return (
    <form
      className="form generate"
      onSubmit={(event) => {
        event.preventDefault();
        use();
      }}
    >
      <div className="form-row">
        <label className="field">
          <span className="label">Type</span>
          <select className="select" value={kind} onChange={(event) => setKind(event.target.value as Kind)}>
            {KINDS.map((each) => (
              <option key={each.id} value={each.id}>
                {each.name}
              </option>
            ))}
          </select>
        </label>
        {kind === 'random' ? (
          <label className="field">
            <span className="label">Characters</span>
            <select
              className="select"
              value={encoding}
              onChange={(event) => setEncoding(event.target.value as Encoding)}
            >
              {ENCODINGS.map((each) => (
                <option key={each.id} value={each.id}>
                  {each.name}
                </option>
              ))}
            </select>
          </label>
        ) : kind === 'aes' ? (
          <label className="field">
            <span className="label">Size</span>
            <select
              className="select"
              value={size}
              onChange={(event) => setSize(Number(event.target.value) as AesSize)}
            >
              <option value={256}>256-bit</option>
              <option value={128}>128-bit</option>
            </select>
          </label>
        ) : (
          <label className="field">
            <span className="label">Algorithm</span>
            <select className="select" value={pair} onChange={(event) => setPair(Number(event.target.value))}>
              {PAIRS.map((each, index) => (
                <option key={index} value={index}>
                  {each.algorithm}, {each.curve}
                </option>
              ))}
            </select>
          </label>
        )}
      </div>

      {kind === 'random' && (
        <div className="field">
          <label className="label" htmlFor={`${id}-bytes`}>
            Length
          </label>
          <div className="generate-length">
            <input
              className="range"
              type="range"
              aria-label="Length in bytes"
              aria-valuetext={`${bytes} bytes`}
              min={MIN_BYTES}
              max={MAX_BYTES}
              value={bytes}
              onChange={(event) => {
                setBytes(Number(event.target.value));
                setBytesText(event.target.value);
              }}
            />
            <input
              id={`${id}-bytes`}
              className="input generate-bytes"
              type="number"
              inputMode="numeric"
              min={MIN_BYTES}
              max={MAX_BYTES}
              value={bytesText}
              aria-describedby={`${id}-entropy`}
              onChange={(event) => {
                setBytesText(event.target.value);
                const typed = Number(event.target.value);
                if (Number.isInteger(typed) && typed >= MIN_BYTES && typed <= MAX_BYTES) setBytes(typed);
              }}
              onBlur={() => setBytesText(String(bytes))}
            />
            <span className="generate-unit">bytes</span>
          </div>
          <p className="hint" id={`${id}-entropy`}>
            {encodedLength(encoding, bytes)} characters{encoding === 'base62' ? ', A–Z, a–z and 0–9' : ''}, {bytes * 8} bits of entropy.
          </p>
        </div>
      )}

      {kind === 'pair' ? (
        <>
          <NamedValue
            label="Private key"
            format="PKCS #8, base64"
            name={privateName}
            onName={renamable ? setPrivateName : undefined}
            value={generated?.value ?? null}
            describedBy={`${id}-names`}
          />
          <NamedValue
            label="Public key"
            format="raw, base64"
            name={publicKey}
            onName={setPublicName}
            value={generated?.publicKey ?? null}
            describedBy={`${id}-names`}
          />
          <p className="hint" id={`${id}-names`}>
            {nameProblem ?? 'The public key is saved with this row, as a secret of its own.'}
          </p>
        </>
      ) : (
        <NamedValue
          label="Value"
          format={kind === 'aes' ? `the raw key, base64, ${size === 256 ? 44 : 24} characters` : undefined}
          value={generated?.value ?? null}
        />
      )}

      <ErrorLine error={error} />

      <div className="dialog-actions generate-actions">
        <button className="btn btn-quiet" type="button" onClick={() => setRound((count) => count + 1)}>
          <Shuffle size={14} />
          Generate again
        </button>
        <button className="btn" type="button" onClick={onCancel}>
          Cancel
        </button>
        <button className="btn btn-primary" type="submit" disabled={!ready}>
          {kind === 'pair' ? 'Use keys' : 'Use value'}
        </button>
      </div>
    </form>
  );
}

/** A generated value, masked until shown, and for a key pair the name it is saved under. */
function NamedValue({
  label,
  format,
  name,
  onName,
  value,
  describedBy,
}: {
  label: string;
  format?: string;
  /** Only a key pair's two values carry a name. */
  name?: string;
  /** Without it, the name is shown but fixed: the row's own. */
  onName?: (name: string) => void;
  value: string | null;
  /** The line under both names that says what is wrong with them. */
  describedBy?: string;
}) {
  const id = useId();
  const [shown, setShown] = useState(false);
  const problem = name === undefined || name.trim() === '' ? null : secretKeyProblem(name.trim());
  return (
    <div className="field">
      <label className="label" htmlFor={`${id}-value`}>
        {label}
        {format !== undefined && <span className="label-note"> · {format}</span>}
      </label>
      {name !== undefined && (
        <input
          className="input input-mono"
          aria-label={`Name of the ${label.toLowerCase()}`}
          aria-invalid={problem !== null}
          aria-describedby={describedBy}
          placeholder="NAME_OF_SECRET"
          spellCheck={false}
          autoComplete="off"
          value={name}
          disabled={onName === undefined}
          onChange={(event) => onName?.(event.target.value)}
        />
      )}
      <div className="input-group">
        <MaskedInput
          id={`${id}-value`}
          className="input input-mono"
          masked={!shown}
          readOnly
          value={value ?? ''}
          placeholder={value === null ? 'Generating…' : undefined}
        />
        <button
          type="button"
          className="btn btn-quiet btn-sm btn-icon input-addon"
          aria-label={shown ? `Mask the ${label.toLowerCase()}` : `Show the ${label.toLowerCase()}`}
          aria-pressed={shown}
          onClick={() => setShown((current) => !current)}
        >
          {shown ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      </div>
    </div>
  );
}
