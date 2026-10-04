import faviconPng from './assets/favicon-32.png?url';
import appleTouchIcon from './assets/apple-touch-icon.png?url';
import { markSvg } from './components/mark';
import globalsCss from './styles/globals.css?url';

/**
 * coffre's entries in the document's head, for the deployment's root:
 * `head: () => coffreHead()`. The meta tags a page needs, coffre's
 * stylesheet and its icons. A route below may set a title of its own.
 */
export function coffreHead() {
  return {
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { title: 'coffre' },
      { name: 'description', content: 'Secrets, with an audit log' },
    ],
    links: [
      { rel: 'stylesheet', href: globalsCss },
      { rel: 'icon', type: 'image/png', sizes: '32x32', href: faviconPng },
      { rel: 'icon', type: 'image/svg+xml', href: `data:image/svg+xml,${encodeURIComponent(markSvg(16, { adaptive: true }))}` },
      { rel: 'apple-touch-icon', href: appleTouchIcon },
    ],
  };
}
