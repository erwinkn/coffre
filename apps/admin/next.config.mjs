/** @type {import('next').NextConfig} */
export default {
  // The UI never talks to Postgres. Every read goes through the coffre API so
  // that it is authorised and written to the audit log. A UI that queried the
  // database directly would be an unaudited read path.
  poweredByHeader: false,

  // Dev-only. Next 16 blocks its own dev-time client bundle when the page is
  // reached over a host it does not treat as same-origin; the symptom is a page
  // that renders correctly but never hydrates, so every button silently does
  // nothing. No effect on a production build.
  allowedDevOrigins: ['127.0.0.1', 'localhost'],
};
