import { Lock } from './icons';
import { Toggletip } from './ui';

/**
 * An environment's protection, by its name (docs/design/roles.md): a tag
 * whose note says what it means, on a tap too.
 */
export function ProtectedTag() {
  return (
    <Toggletip label="Protected: each person here holds their role’s protected column, which an Owner sets in Settings › Roles. Service accounts hold their role as anywhere else.">
      <button type="button" className="tag tag-button">
        <Lock size={11} />
        Protected
      </button>
    </Toggletip>
  );
}
