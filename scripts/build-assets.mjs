// 把 agent.py / install.sh / uninstall.sh / panel.html 打包成 JS 字符串模块（Pages Functions 不支持 wrangler 的 Text rules）
import { readFileSync, writeFileSync } from "node:fs";
const f = (n) => readFileSync(new URL(`../src/${n}`, import.meta.url), "utf8");
const out =
  `// 自动生成，请勿手改：npm run build:assets\n` +
  `export const AGENT_PY = ${JSON.stringify(f("agent.py"))};\n` +
  `export const INSTALL_SH = ${JSON.stringify(f("install.sh"))};\n` +
  `export const UNINSTALL_SH = ${JSON.stringify(f("uninstall.sh"))};\n` +
  `export const PANEL_HTML = ${JSON.stringify(f("panel.html"))};\n`;
writeFileSync(new URL("../src/assets.js", import.meta.url), out);
console.log("src/assets.js 已生成");
