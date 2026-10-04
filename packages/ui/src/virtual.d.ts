// What coffre's Vite plugin serves (src/vite.ts).
declare module 'virtual:coffre/preloads' {
  const preloads: Record<string, string[]>;
  export default preloads;
}
