// Routeur minimal : chaque module de routes s'enregistre via route().

export const routes = new Map();

export function route(methods, pathname, handler, { auth = false } = {}) {
  for (const method of [].concat(methods)) {
    routes.set(`${method} ${pathname}`, { handler, auth });
  }
}
