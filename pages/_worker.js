// node_modules/hono/dist/utils/cookie.js
var parse = (cookie) => {
  const pairs = cookie.split(/;\s*/g);
  const parsedCookie = {};
  for (let i = 0, len = pairs.length; i < len; i++) {
    const pair = pairs[i].split(/\s*=\s*([^\s]+)/);
    parsedCookie[pair[0]] = decodeURIComponent(pair[1]);
  }
  return parsedCookie;
};
var serialize = (name, value, opt = {}) => {
  value = encodeURIComponent(value);
  let cookie = `${name}=${value}`;
  if (opt.maxAge) {
    cookie += `; Max-Age=${Math.floor(opt.maxAge)}`;
  }
  if (opt.domain) {
    cookie += "; Domain=" + opt.domain;
  }
  if (opt.path) {
    cookie += "; Path=" + opt.path;
  }
  if (opt.expires) {
    cookie += "; Expires=" + opt.expires.toUTCString();
  }
  if (opt.httpOnly) {
    cookie += "; HttpOnly";
  }
  if (opt.secure) {
    cookie += "; Secure";
  }
  if (opt.sameSite) {
    cookie += `; SameSite=${opt.sameSite}`;
  }
  return cookie;
};

// node_modules/hono/dist/context.js
var HonoContext = class {
  constructor(req, env = void 0, executionCtx = void 0, notFoundHandler = () => new Response()) {
    this.error = void 0;
    this._status = 200;
    this._pretty = false;
    this._prettySpace = 2;
    this._executionCtx = executionCtx;
    this.req = req;
    this.env = env || {};
    this.notFoundHandler = notFoundHandler;
    this.finalized = false;
  }
  get event() {
    if (this._executionCtx instanceof FetchEvent) {
      return this._executionCtx;
    } else {
      throw Error("This context has no FetchEvent");
    }
  }
  get executionCtx() {
    if (this._executionCtx) {
      return this._executionCtx;
    } else {
      throw Error("This context has no ExecutionContext");
    }
  }
  get res() {
    return this._res || (this._res = new Response("404 Not Found", { status: 404 }));
  }
  set res(_res) {
    this._res = _res;
    this.finalized = true;
  }
  header(name, value, options) {
    this._headers || (this._headers = {});
    const key = name.toLowerCase();
    let shouldAppend = false;
    if (options && options.append) {
      const vAlreadySet = this._headers[key];
      if (vAlreadySet && vAlreadySet.length) {
        shouldAppend = true;
      }
    }
    if (shouldAppend) {
      this._headers[key].push(value);
    } else {
      this._headers[key] = [value];
    }
    if (this.finalized) {
      if (shouldAppend) {
        this.res.headers.append(name, value);
      } else {
        this.res.headers.set(name, value);
      }
    }
  }
  status(status) {
    this._status = status;
  }
  set(key, value) {
    this._map || (this._map = {});
    this._map[key] = value;
  }
  get(key) {
    if (!this._map) {
      return void 0;
    }
    return this._map[key];
  }
  pretty(prettyJSON, space = 2) {
    this._pretty = prettyJSON;
    this._prettySpace = space;
  }
  newResponse(data, status, headers = {}) {
    return new Response(data, {
      status: status || this._status || 200,
      headers: this._finalizeHeaders(headers)
    });
  }
  _finalizeHeaders(incomingHeaders) {
    const finalizedHeaders = [];
    const headersKv = this._headers || {};
    if (this._res) {
      this._res.headers.forEach((v, k) => {
        headersKv[k] = [v];
      });
    }
    for (const key of Object.keys(incomingHeaders)) {
      const value = incomingHeaders[key];
      if (typeof value === "string") {
        finalizedHeaders.push([key, value]);
      } else {
        for (const v of value) {
          finalizedHeaders.push([key, v]);
        }
      }
      delete headersKv[key];
    }
    for (const key of Object.keys(headersKv)) {
      for (const value of headersKv[key]) {
        const kv = [key, value];
        finalizedHeaders.push(kv);
      }
    }
    return finalizedHeaders;
  }
  body(data, status = this._status, headers = {}) {
    return this.newResponse(data, status, headers);
  }
  text(text, status = this._status, headers = {}) {
    headers["content-type"] = "text/plain; charset=UTF-8";
    return this.body(text, status, headers);
  }
  json(object, status = this._status, headers = {}) {
    const body = this._pretty ? JSON.stringify(object, null, this._prettySpace) : JSON.stringify(object);
    headers["content-type"] = "application/json; charset=UTF-8";
    return this.body(body, status, headers);
  }
  html(html, status = this._status, headers = {}) {
    headers["content-type"] = "text/html; charset=UTF-8";
    return this.body(html, status, headers);
  }
  redirect(location, status = 302) {
    return this.newResponse(null, status, {
      Location: location
    });
  }
  cookie(name, value, opt) {
    const cookie = serialize(name, value, opt);
    this.header("set-cookie", cookie, { append: true });
  }
  notFound() {
    return this.notFoundHandler(this);
  }
};

// node_modules/hono/dist/compose.js
var compose = (middleware, onNotFound, onError) => {
  const middlewareLength = middleware.length;
  return (context, next) => {
    let index = -1;
    return dispatch(0);
    function dispatch(i) {
      if (i <= index) {
        throw new Error("next() called multiple times");
      }
      let handler = middleware[i];
      index = i;
      if (i === middlewareLength && next)
        handler = next;
      let res;
      let isError = false;
      if (!handler) {
        if (context instanceof HonoContext && context.finalized === false && onNotFound) {
          res = onNotFound(context);
        }
      } else {
        try {
          res = handler(context, () => {
            const dispatchRes = dispatch(i + 1);
            return dispatchRes instanceof Promise ? dispatchRes : Promise.resolve(dispatchRes);
          });
        } catch (err) {
          if (err instanceof Error && context instanceof HonoContext && onError) {
            context.error = err;
            res = onError(err, context);
            isError = true;
          } else {
            throw err;
          }
        }
      }
      if (!(res instanceof Promise)) {
        if (res && (context.finalized === false || isError)) {
          context.res = res;
        }
        return context;
      } else {
        return res.then((res2) => {
          if (res2 && context.finalized === false) {
            context.res = res2;
          }
          return context;
        }).catch((err) => {
          if (err instanceof Error && context instanceof HonoContext && onError) {
            context.error = err;
            context.res = onError(err, context);
            return context;
          }
          throw err;
        });
      }
    }
  };
};

// node_modules/hono/dist/utils/body.js
async function parseBody(r) {
  let body = {};
  const contentType = r.headers.get("Content-Type");
  if (contentType && (contentType.startsWith("multipart/form-data") || contentType === "application/x-www-form-urlencoded")) {
    const form = {};
    body = [...await r.formData()].reduce((acc, cur) => {
      acc[cur[0]] = cur[1];
      return acc;
    }, form);
  }
  return body;
}

// node_modules/hono/dist/utils/url.js
var splitPath = (path) => {
  const paths = path.split(/\//);
  if (paths[0] === "") {
    paths.shift();
  }
  return paths;
};
var patternCache = {};
var getPattern = (label) => {
  if (label === "*") {
    return "*";
  }
  const match = label.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
  if (match) {
    if (!patternCache[label]) {
      if (match[2]) {
        patternCache[label] = [label, match[1], new RegExp("^" + match[2] + "$")];
      } else {
        patternCache[label] = [label, match[1], true];
      }
    }
    return patternCache[label];
  }
  return null;
};
var getPathFromURL = (url, strict = true) => {
  const queryIndex = url.indexOf("?");
  const result = url.substring(url.indexOf("/", 8), queryIndex === -1 ? url.length : queryIndex);
  if (strict === false && result.endsWith("/")) {
    return result.slice(0, -1);
  }
  return result;
};
var getQueryStringFromURL = (url) => {
  const queryIndex = url.indexOf("?");
  const result = queryIndex !== -1 ? url.substring(queryIndex) : "";
  return result;
};
var mergePath = (...paths) => {
  let p = "";
  let endsWithSlash = false;
  for (let path of paths) {
    if (p.endsWith("/")) {
      p = p.slice(0, -1);
      endsWithSlash = true;
    }
    if (!path.startsWith("/")) {
      path = `/${path}`;
    }
    if (path === "/" && endsWithSlash) {
      p = `${p}/`;
    } else if (path !== "/") {
      p = `${p}${path}`;
    }
    if (path === "/" && p === "") {
      p = "/";
    }
  }
  return p;
};
var checkOptionalParameter = (path) => {
  const match = path.match(/(^.+)(\/\:[^\/]+)\?$/);
  if (!match)
    return null;
  const base = match[1];
  const optional = base + match[2];
  return [base, optional];
};

// node_modules/hono/dist/request.js
function extendRequestPrototype() {
  if (!!Request.prototype.param) {
    return;
  }
  Request.prototype.param = function(key) {
    if (this.paramData) {
      if (key) {
        return this.paramData[key];
      } else {
        return this.paramData;
      }
    }
    return null;
  };
  Request.prototype.header = function(name) {
    if (!this.headerData) {
      this.headerData = {};
      for (const [key, value] of this.headers) {
        this.headerData[key] = value;
      }
    }
    if (name) {
      return this.headerData[name.toLowerCase()];
    } else {
      return this.headerData;
    }
  };
  Request.prototype.query = function(key) {
    const queryString = getQueryStringFromURL(this.url);
    const searchParams = new URLSearchParams(queryString);
    if (!this.queryData) {
      this.queryData = {};
      for (const key2 of searchParams.keys()) {
        this.queryData[key2] = searchParams.get(key2) || "";
      }
    }
    if (key) {
      return this.queryData[key];
    } else {
      return this.queryData;
    }
  };
  Request.prototype.queries = function(key) {
    const queryString = getQueryStringFromURL(this.url);
    const searchParams = new URLSearchParams(queryString);
    if (key) {
      return searchParams.getAll(key);
    } else {
      const result = {};
      for (const key2 of searchParams.keys()) {
        result[key2] = searchParams.getAll(key2);
      }
      return result;
    }
  };
  Request.prototype.cookie = function(key) {
    const cookie = this.headers.get("Cookie") || "";
    const obj = parse(cookie);
    if (key) {
      const value = obj[key];
      return value;
    } else {
      return obj;
    }
  };
  Request.prototype.parseBody = async function() {
    let body;
    if (!this.bodyData) {
      body = await parseBody(this);
      this.bodyData = body;
    } else {
      body = this.bodyData;
    }
    return body;
  };
  Request.prototype.json = async function() {
    let jsonData;
    if (!this.jsonData) {
      jsonData = JSON.parse(await this.text());
      this.jsonData = jsonData;
    } else {
      jsonData = this.jsonData;
    }
    return jsonData;
  };
  Request.prototype.valid = function(keys, value) {
    var _a;
    if (!this.data) {
      this.data = {};
    }
    if (keys !== void 0) {
      if (typeof keys === "string") {
        keys = [keys];
      }
      let data = this.data;
      for (let i = 0; i < keys.length - 1; i++) {
        data = data[_a = keys[i]] || (data[_a] = {});
      }
      data[keys[keys.length - 1]] = value;
    }
    return this.data;
  };
}

// node_modules/hono/dist/router.js
var METHOD_NAME_ALL = "ALL";
var METHOD_NAME_ALL_LOWERCASE = "all";
var METHODS = ["get", "post", "put", "delete", "head", "options", "patch"];
var UnsupportedPathError = class extends Error {
};

// node_modules/hono/dist/router/reg-exp-router/node.js
var LABEL_REG_EXP_STR = "[^/]+";
var ONLY_WILDCARD_REG_EXP_STR = ".*";
var TAIL_WILDCARD_REG_EXP_STR = "(?:|/.*)";
var PATH_ERROR = Symbol();
function compareKey(a, b) {
  if (a.length === 1) {
    return b.length === 1 ? a < b ? -1 : 1 : -1;
  }
  if (b.length === 1) {
    return 1;
  }
  if (a === ONLY_WILDCARD_REG_EXP_STR || a === TAIL_WILDCARD_REG_EXP_STR) {
    return 1;
  } else if (b === ONLY_WILDCARD_REG_EXP_STR || b === TAIL_WILDCARD_REG_EXP_STR) {
    return -1;
  }
  if (a === LABEL_REG_EXP_STR) {
    return 1;
  } else if (b === LABEL_REG_EXP_STR) {
    return -1;
  }
  return a.length === b.length ? a < b ? -1 : 1 : b.length - a.length;
}
var Node = class {
  constructor() {
    this.children = {};
  }
  insert(tokens, index, paramMap, context) {
    if (tokens.length === 0) {
      if (this.index !== void 0) {
        throw PATH_ERROR;
      }
      this.index = index;
      return;
    }
    const [token, ...restTokens] = tokens;
    const pattern = token === "*" ? restTokens.length === 0 ? ["", "", ONLY_WILDCARD_REG_EXP_STR] : ["", "", LABEL_REG_EXP_STR] : token === "/*" ? ["", "", TAIL_WILDCARD_REG_EXP_STR] : token.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
    let node;
    if (pattern) {
      const name = pattern[1];
      const regexpStr = pattern[2] || LABEL_REG_EXP_STR;
      node = this.children[regexpStr];
      if (!node) {
        if (Object.keys(this.children).some((k) => k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR)) {
          throw PATH_ERROR;
        }
        node = this.children[regexpStr] = new Node();
        if (name !== "") {
          node.varIndex = context.varIndex++;
        }
      }
      if (name !== "") {
        if (paramMap.some((p) => p[0] === name)) {
          throw new Error("Duplicate param name");
        }
        paramMap.push([name, node.varIndex]);
      }
    } else {
      node = this.children[token];
      if (!node) {
        if (Object.keys(this.children).some((k) => k.length > 1 && k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR)) {
          throw PATH_ERROR;
        }
        node = this.children[token] = new Node();
      }
    }
    node.insert(restTokens, index, paramMap, context);
  }
  buildRegExpStr() {
    const childKeys = Object.keys(this.children).sort(compareKey);
    const strList = childKeys.map((k) => {
      const c = this.children[k];
      return (typeof c.varIndex === "number" ? `(${k})@${c.varIndex}` : k) + c.buildRegExpStr();
    });
    if (typeof this.index === "number") {
      strList.unshift(`#${this.index}`);
    }
    if (strList.length === 0) {
      return "";
    }
    if (strList.length === 1) {
      return strList[0];
    }
    return "(?:" + strList.join("|") + ")";
  }
};

// node_modules/hono/dist/router/reg-exp-router/trie.js
var Trie = class {
  constructor() {
    this.context = { varIndex: 0 };
    this.root = new Node();
  }
  insert(path, index) {
    const paramMap = [];
    const tokens = path.match(/(?::[^\/]+)|(?:\/\*$)|./g);
    this.root.insert(tokens, index, paramMap, this.context);
    return paramMap;
  }
  buildRegExp() {
    let regexp = this.root.buildRegExpStr();
    let captureIndex = 0;
    const indexReplacementMap = [];
    const paramReplacementMap = [];
    regexp = regexp.replace(/#(\d+)|@(\d+)|\.\*\$/g, (_, handlerIndex, paramIndex) => {
      if (typeof handlerIndex !== "undefined") {
        indexReplacementMap[++captureIndex] = Number(handlerIndex);
        return "$()";
      }
      if (typeof paramIndex !== "undefined") {
        paramReplacementMap[Number(paramIndex)] = ++captureIndex;
        return "";
      }
      return "";
    });
    return [new RegExp(`^${regexp}`), indexReplacementMap, paramReplacementMap];
  }
};

// node_modules/hono/dist/router/reg-exp-router/router.js
var METHOD_NAMES = [METHOD_NAME_ALL, ...METHODS].map((method) => method.toUpperCase());
var emptyParam = {};
var nullMatcher = [/^$/, []];
function buildWildcardRegExp(path) {
  return new RegExp(path === "*" ? "" : `^${path.replace(/\/\*/, "(?:|/.*)")}$`);
}
function buildMatcherFromPreprocessedRoutes(routes) {
  const trie = new Trie();
  const handlers = [];
  if (routes.length === 0) {
    return nullMatcher;
  }
  for (let i = 0, len = routes.length; i < len; i++) {
    let paramMap;
    try {
      paramMap = trie.insert(routes[i][0], i);
    } catch (e) {
      throw e === PATH_ERROR ? new UnsupportedPathError(routes[i][0]) : e;
    }
    handlers[i] = [routes[i][1], paramMap.length !== 0 ? paramMap : null];
  }
  const [regexp, indexReplacementMap, paramReplacementMap] = trie.buildRegExp();
  for (let i = 0, len = handlers.length; i < len; i++) {
    const paramMap = handlers[i][1];
    if (paramMap) {
      for (let j = 0, len2 = paramMap.length; j < len2; j++) {
        paramMap[j][1] = paramReplacementMap[paramMap[j][1]];
      }
    }
  }
  const handlerMap = [];
  for (const i in indexReplacementMap) {
    handlerMap[i] = handlers[indexReplacementMap[i]];
  }
  return [regexp, handlerMap];
}
function findMiddleware(middleware, path) {
  if (!middleware) {
    return void 0;
  }
  for (const k of Object.keys(middleware).sort((a, b) => b.length - a.length)) {
    if (buildWildcardRegExp(k).test(path)) {
      return [...middleware[k]];
    }
  }
  return void 0;
}
var RegExpRouter = class {
  constructor() {
    this.middleware = { [METHOD_NAME_ALL]: {} };
    this.routes = { [METHOD_NAME_ALL]: {} };
  }
  add(method, path, handler) {
    var _a;
    const { middleware, routes } = this;
    if (!middleware || !routes) {
      throw new Error("Can not add a route since the matcher is already built.");
    }
    if (path === "/*") {
      path = "*";
    }
    if (/\*$/.test(path)) {
      middleware[method] || (middleware[method] = {});
      const re = buildWildcardRegExp(path);
      (_a = middleware[method])[path] || (_a[path] = findMiddleware(middleware[METHOD_NAME_ALL], path) || []);
      Object.keys(middleware).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(middleware[m]).forEach((p) => {
            ;
            (path === "*" || path === p) && middleware[m][p].push(handler);
          });
        }
      });
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(routes[m]).forEach((p) => (path === "*" || re.test(p)) && routes[m][p].push(handler));
        }
      });
      return;
    }
    const paths = checkOptionalParameter(path) || [path];
    for (let i = 0, len = paths.length; i < len; i++) {
      const path2 = paths[i];
      routes[method] || (routes[method] = {});
      Object.keys(routes).forEach((m) => {
        var _a2;
        if (method === METHOD_NAME_ALL || method === m) {
          (_a2 = routes[m])[path2] || (_a2[path2] = [
            ...routes[METHOD_NAME_ALL][path2] || findMiddleware(middleware[method], path2) || findMiddleware(middleware[METHOD_NAME_ALL], path2) || []
          ]);
          routes[m][path2].push(handler);
        }
      });
    }
  }
  match(method, path) {
    const matchers = this.buildAllMatchers();
    this.match = (method2, path2) => {
      const matcher = matchers[method2];
      const match = path2.match(matcher[0]);
      if (!match) {
        return null;
      }
      const index = match.indexOf("", 1);
      const [handlers, paramMap] = matcher[1][index];
      if (!paramMap) {
        return { handlers, params: emptyParam };
      }
      const params = {};
      for (let i = 0, len = paramMap.length; i < len; i++) {
        params[paramMap[i][0]] = match[paramMap[i][1]];
      }
      return { handlers, params };
    };
    return this.match(method, path);
  }
  buildAllMatchers() {
    const matchers = {};
    METHOD_NAMES.forEach((method) => {
      matchers[method] = this.buildMatcher(method) || matchers[METHOD_NAME_ALL];
    });
    this.middleware = this.routes = void 0;
    return matchers;
  }
  buildMatcher(method) {
    const routes = [];
    let hasOwnRoute = method === METHOD_NAME_ALL;
    [this.middleware, this.routes].forEach((r) => {
      const ownRoute = r[method] ? Object.keys(r[method]).map((path) => [path, r[method][path]]) : [];
      if (ownRoute.length !== 0) {
        hasOwnRoute || (hasOwnRoute = true);
        routes.push(...ownRoute);
      } else if (method !== METHOD_NAME_ALL) {
        routes.push(...Object.keys(r[METHOD_NAME_ALL]).map((path) => [path, r[METHOD_NAME_ALL][path]]));
      }
    });
    if (!hasOwnRoute) {
      return null;
    } else {
      return buildMatcherFromPreprocessedRoutes(routes);
    }
  }
};

// node_modules/hono/dist/router/smart-router/router.js
var SmartRouter = class {
  constructor(init) {
    this.routers = [];
    this.routes = [];
    Object.assign(this, init);
  }
  add(method, path, handler) {
    if (!this.routes) {
      throw new Error("Can not add a route since the matcher is already built.");
    }
    this.routes.push([method, path, handler]);
  }
  match(method, path) {
    if (!this.routes) {
      throw new Error("Fatal error");
    }
    const { routers, routes } = this;
    const len = routers.length;
    let i = 0;
    let res;
    for (; i < len; i++) {
      const router = routers[i];
      try {
        routes.forEach((args) => {
          router.add(...args);
        });
        res = router.match(method, path);
      } catch (e) {
        if (e instanceof UnsupportedPathError) {
          continue;
        }
        throw e;
      }
      this.match = router.match.bind(router);
      this.routers = [router];
      this.routes = void 0;
      break;
    }
    if (i === len) {
      throw new Error("Fatal error");
    }
    return res || null;
  }
  get activeRouter() {
    if (this.routes || this.routers.length !== 1) {
      throw new Error("No active router has been determined yet.");
    }
    return this.routers[0];
  }
};

// node_modules/hono/dist/router/static-router/router.js
var StaticRouter = class {
  constructor() {
    this.middleware = {};
    this.routes = {};
    [METHOD_NAME_ALL, ...METHODS].forEach((method) => {
      this.routes[method.toUpperCase()] = {};
    });
  }
  add(method, path, handler) {
    var _a;
    const { middleware, routes } = this;
    if (path === "/*") {
      path = "*";
    }
    if (path === "*") {
      if (method === METHOD_NAME_ALL) {
        middleware[METHOD_NAME_ALL] || (middleware[METHOD_NAME_ALL] = { handlers: [], params: {} });
        Object.keys(middleware).forEach((m) => {
          middleware[m].handlers.push(handler);
        });
        Object.keys(routes).forEach((m) => {
          Object.values(routes[m]).forEach((matchRes) => matchRes.handlers.push(handler));
        });
      } else {
        middleware[method] || (middleware[method] = {
          handlers: [...middleware[METHOD_NAME_ALL]?.handlers || []],
          params: {}
        });
        middleware[method].handlers.push(handler);
        if (routes[method]) {
          Object.values(routes[method]).forEach((matchRes) => matchRes.handlers.push(handler));
        }
      }
      return;
    }
    if (/\*|\/:/.test(path)) {
      throw new UnsupportedPathError(path);
    }
    (_a = routes[method])[path] || (_a[path] = {
      handlers: [
        ...routes[METHOD_NAME_ALL][path]?.handlers || middleware[method]?.handlers || middleware[METHOD_NAME_ALL]?.handlers || []
      ],
      params: {}
    });
    if (method === METHOD_NAME_ALL) {
      Object.keys(routes).forEach((m) => {
        routes[m][path]?.handlers?.push(handler);
      });
    } else {
      routes[method][path].handlers.push(handler);
    }
  }
  match(method, path) {
    const { routes, middleware } = this;
    this.match = (method2, path2) => routes[method2][path2] || routes[METHOD_NAME_ALL][path2] || middleware[method2] || middleware[METHOD_NAME_ALL] || null;
    return this.match(method, path);
  }
};

// node_modules/hono/dist/router/trie-router/node.js
function findParam(node, name) {
  for (let i = 0, len = node.patterns.length; i < len; i++) {
    if (typeof node.patterns[i] === "object" && node.patterns[i][1] === name) {
      return true;
    }
  }
  const nodes = Object.values(node.children);
  for (let i = 0, len = nodes.length; i < len; i++) {
    if (findParam(nodes[i], name)) {
      return true;
    }
  }
  return false;
}
var Node2 = class {
  constructor(method, handler, children) {
    this.order = 0;
    this.children = children || {};
    this.methods = [];
    this.name = "";
    if (method && handler) {
      const m = {};
      m[method] = { handler, score: 0, name: this.name };
      this.methods = [m];
    }
    this.patterns = [];
    this.handlerSetCache = {};
  }
  insert(method, path, handler) {
    this.name = `${method} ${path}`;
    this.order = ++this.order;
    let curNode = this;
    const parts = splitPath(path);
    const parentPatterns = [];
    const errorMessage = (name) => {
      return `Duplicate param name, use another name instead of '${name}' - ${method} ${path} <--- '${name}'`;
    };
    for (let i = 0, len = parts.length; i < len; i++) {
      const p = parts[i];
      if (Object.keys(curNode.children).includes(p)) {
        parentPatterns.push(...curNode.patterns);
        curNode = curNode.children[p];
        continue;
      }
      curNode.children[p] = new Node2();
      const pattern = getPattern(p);
      if (pattern) {
        if (typeof pattern === "object") {
          for (let j = 0, len2 = parentPatterns.length; j < len2; j++) {
            if (typeof parentPatterns[j] === "object" && parentPatterns[j][1] === pattern[1]) {
              throw new Error(errorMessage(pattern[1]));
            }
          }
          if (Object.values(curNode.children).some((n) => findParam(n, pattern[1]))) {
            throw new Error(errorMessage(pattern[1]));
          }
        }
        curNode.patterns.push(pattern);
        parentPatterns.push(...curNode.patterns);
      }
      parentPatterns.push(...curNode.patterns);
      curNode = curNode.children[p];
    }
    if (!curNode.methods.length) {
      curNode.methods = [];
    }
    const m = {};
    const handlerSet = { handler, name: this.name, score: this.order };
    m[method] = handlerSet;
    curNode.methods.push(m);
    return curNode;
  }
  getHandlerSets(node, method, wildcard) {
    var _a, _b;
    return (_a = node.handlerSetCache)[_b = `${method}:${wildcard ? "1" : "0"}`] || (_a[_b] = (() => {
      const handlerSets = [];
      for (let i = 0, len = node.methods.length; i < len; i++) {
        const m = node.methods[i];
        const handlerSet = m[method] || m[METHOD_NAME_ALL];
        if (handlerSet !== void 0) {
          handlerSets.push(handlerSet);
        }
      }
      return handlerSets;
    })());
  }
  search(method, path) {
    const handlerSets = [];
    const params = {};
    const curNode = this;
    let curNodes = [curNode];
    const parts = splitPath(path);
    for (let i = 0, len2 = parts.length; i < len2; i++) {
      const part = parts[i];
      const isLast = i === len2 - 1;
      const tempNodes = [];
      let matched = false;
      for (let j = 0, len22 = curNodes.length; j < len22; j++) {
        const node = curNodes[j];
        const nextNode = node.children[part];
        if (nextNode) {
          if (isLast === true) {
            if (nextNode.children["*"]) {
              handlerSets.push(...this.getHandlerSets(nextNode.children["*"], method, true));
            }
            handlerSets.push(...this.getHandlerSets(nextNode, method));
            matched = true;
          } else {
            tempNodes.push(nextNode);
          }
        }
        for (let k = 0, len3 = node.patterns.length; k < len3; k++) {
          const pattern = node.patterns[k];
          if (pattern === "*") {
            const astNode = node.children["*"];
            if (astNode) {
              handlerSets.push(...this.getHandlerSets(astNode, method));
              tempNodes.push(astNode);
            }
            continue;
          }
          if (part === "")
            continue;
          const [key, name, matcher] = pattern;
          if (matcher === true || matcher instanceof RegExp && matcher.test(part)) {
            if (typeof key === "string") {
              if (isLast === true) {
                handlerSets.push(...this.getHandlerSets(node.children[key], method));
              } else {
                tempNodes.push(node.children[key]);
              }
            }
            if (typeof name === "string" && !matched) {
              params[name] = part;
            }
          }
        }
      }
      curNodes = tempNodes;
    }
    const len = handlerSets.length;
    if (len === 0)
      return null;
    if (len === 1)
      return { handlers: [handlerSets[0].handler], params };
    const handlers = handlerSets.sort((a, b) => {
      return a.score - b.score;
    }).map((s) => {
      return s.handler;
    });
    return { handlers, params };
  }
};

// node_modules/hono/dist/router/trie-router/router.js
var TrieRouter = class {
  constructor() {
    this.node = new Node2();
  }
  add(method, path, handler) {
    const results = checkOptionalParameter(path);
    if (results) {
      for (const p of results) {
        this.node.insert(method, p, handler);
      }
      return;
    }
    this.node.insert(method, path, handler);
  }
  match(method, path) {
    return this.node.search(method, path);
  }
};

// node_modules/hono/dist/hono.js
function defineDynamicClass() {
  return class {
  };
}
var Hono = class extends defineDynamicClass() {
  constructor(init = {}) {
    super();
    this.router = new SmartRouter({
      routers: [new StaticRouter(), new RegExpRouter(), new TrieRouter()]
    });
    this.strict = true;
    this._tempPath = "";
    this.path = "/";
    this.routes = [];
    this.notFoundHandler = (c) => {
      return c.text("404 Not Found", 404);
    };
    this.errorHandler = (err, c) => {
      console.trace(err.message);
      const message = "Internal Server Error";
      return c.text(message, 500);
    };
    this.handleEvent = (event) => {
      return this.dispatch(event.request, event);
    };
    this.fetch = (request, Environment, executionCtx) => {
      return this.dispatch(request, executionCtx, Environment);
    };
    this.request = async (input, requestInit) => {
      const req = input instanceof Request ? input : new Request(input, requestInit);
      return await this.fetch(req);
    };
    extendRequestPrototype();
    const allMethods = [...METHODS, METHOD_NAME_ALL_LOWERCASE];
    allMethods.map((method) => {
      this[method] = (args1, ...args) => {
        if (typeof args1 === "string") {
          this.path = args1;
        } else {
          this.addRoute(method, this.path, args1);
        }
        args.map((handler) => {
          if (typeof handler !== "string") {
            this.addRoute(method, this.path, handler);
          }
        });
        return this;
      };
    });
    Object.assign(this, init);
  }
  route(path, app2) {
    this._tempPath = path;
    if (app2) {
      app2.routes.map((r) => {
        this.addRoute(r.method, r.path, r.handler);
      });
      this._tempPath = "";
    }
    return this;
  }
  use(arg1, ...handlers) {
    if (typeof arg1 === "string") {
      this.path = arg1;
    } else {
      handlers.unshift(arg1);
    }
    handlers.map((handler) => {
      this.addRoute(METHOD_NAME_ALL, this.path, handler);
    });
    return this;
  }
  onError(handler) {
    this.errorHandler = handler;
    return this;
  }
  notFound(handler) {
    this.notFoundHandler = handler;
    return this;
  }
  addRoute(method, path, handler) {
    method = method.toUpperCase();
    if (this._tempPath) {
      path = mergePath(this._tempPath, path);
    }
    this.router.add(method, path, handler);
    const r = { path, method, handler };
    this.routes.push(r);
  }
  matchRoute(method, path) {
    return this.router.match(method, path);
  }
  handleError(err, c) {
    if (err instanceof Error) {
      return this.errorHandler(err, c);
    }
    throw err;
  }
  dispatch(request, eventOrExecutionCtx, env) {
    const path = getPathFromURL(request.url, this.strict);
    const method = request.method;
    const result = this.matchRoute(method, path);
    request.paramData = result?.params;
    const c = new HonoContext(request, env, eventOrExecutionCtx, this.notFoundHandler);
    if (result && result.handlers.length === 1) {
      const handler = result.handlers[0];
      let res;
      try {
        res = handler(c, async () => {
        });
        if (!res)
          return this.notFoundHandler(c);
      } catch (err) {
        return this.handleError(err, c);
      }
      if (res instanceof Response)
        return res;
      return (async () => {
        let awaited;
        try {
          awaited = await res;
        } catch (err) {
          return this.handleError(err, c);
        }
        if (!awaited) {
          return this.notFoundHandler(c);
        }
        return awaited;
      })();
    }
    const handlers = result ? result.handlers : [this.notFoundHandler];
    const composed = compose(handlers, this.notFoundHandler, this.errorHandler);
    return (async () => {
      try {
        const tmp = composed(c);
        const context = tmp instanceof Promise ? await tmp : tmp;
        if (!context.finalized) {
          throw new Error("Context is not finalized. You may forget returning Response object or `await next()`");
        }
        return context.res;
      } catch (err) {
        return this.handleError(err, c);
      }
    })();
  }
};

// node_modules/hono/dist/index.js
Hono.prototype.fire = function() {
  addEventListener("fetch", (event) => {
    void event.respondWith(this.handleEvent(event));
  });
};

// node_modules/hono/dist/utils/crypto.js
var sha256 = async (data) => {
  const algorithm = { name: "SHA-256", alias: "sha256" };
  const hash = await createHash(data, algorithm);
  return hash;
};
var createHash = async (data, algorithm) => {
  let sourceBuffer;
  if (data instanceof ReadableStream) {
    let body = "";
    const reader = data.getReader();
    await reader?.read().then(async (chuck) => {
      const value = await createHash(chuck.value || "", algorithm);
      body += value;
    });
    return body;
  }
  if (ArrayBuffer.isView(data) || data instanceof ArrayBuffer) {
    sourceBuffer = data;
  } else {
    if (typeof data === "object") {
      data = JSON.stringify(data);
    }
    sourceBuffer = new TextEncoder().encode(String(data));
  }
  if (crypto && crypto.subtle) {
    const buffer = await crypto.subtle.digest({
      name: algorithm.name
    }, sourceBuffer);
    const hash = Array.prototype.map.call(new Uint8Array(buffer), (x) => ("00" + x.toString(16)).slice(-2)).join("");
    return hash;
  }
  return null;
};

// node_modules/hono/dist/utils/buffer.js
var timingSafeEqual = async (a, b, hashFunction) => {
  if (!hashFunction) {
    hashFunction = sha256;
  }
  const sa = await hashFunction(a);
  const sb = await hashFunction(b);
  return sa === sb && a === b;
};

// node_modules/hono/dist/utils/encode.js
var decodeBase64 = (str) => {
  if (str === null) {
    throw new TypeError('1st argument of "decodeBase64" should not be null.');
  }
  try {
    const text = atob(str);
    const bytes = new Uint8Array(text.split("").map((c) => c.charCodeAt(0)));
    const decoder = new TextDecoder();
    return decoder.decode(bytes);
  } catch {
  }
  try {
    return Buffer.from(str, "base64").toString();
  } catch (e) {
    console.error('If you want to do "decodeBase64", polyfill "buffer" module.');
    throw e;
  }
};

// node_modules/hono/dist/middleware/basic-auth/index.js
var CREDENTIALS_REGEXP = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$/;
var USER_PASS_REGEXP = /^([^:]*):(.*)$/;
var auth = (req) => {
  const match = CREDENTIALS_REGEXP.exec(req.headers.get("Authorization") || "");
  if (!match) {
    return void 0;
  }
  const userPass = USER_PASS_REGEXP.exec(decodeBase64(match[1]));
  if (!userPass) {
    return void 0;
  }
  return { username: userPass[1], password: userPass[2] };
};
var basicAuth = (options, ...users) => {
  if (!options) {
    throw new Error('basic auth middleware requires options for "username and password"');
  }
  if (!options.realm) {
    options.realm = "Secure Area";
  }
  users.unshift({ username: options.username, password: options.password });
  return async (ctx, next) => {
    const requestUser = auth(ctx.req);
    if (requestUser) {
      for (const user of users) {
        const usernameEqual = await timingSafeEqual(user.username, requestUser.username, options.hashFunction);
        const passwordEqual = await timingSafeEqual(user.password, requestUser.password, options.hashFunction);
        if (usernameEqual && passwordEqual) {
          await next();
          return;
        }
      }
    }
    ctx.res = new Response("Unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="' + options.realm?.replace(/"/g, '\\"') + '"'
      }
    });
    await next();
  };
};

// worker/index.ts
var api = new Hono();
var app = new Hono();
api.get("/message", (c) => {
  return c.json({
    message: "Hello Pages!! This is Hono!!"
  });
});
app.route("/api", api);
var username = "foo";
var password = "bar";
app.use("/foo", basicAuth({ username, password }));
app.get("*", async (c) => {
  const res = await c.env.ASSETS.fetch(c.req);
  return res;
});
var worker_default = app;
export {
  worker_default as default
};
