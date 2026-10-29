// Cloudflare Pages Functions 入口：所有请求交给 src/index.js
import worker from "../src/index.js";
export const onRequest = (ctx) => worker.fetch(ctx.request, ctx.env, ctx);
