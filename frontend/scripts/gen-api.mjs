/**
 * 从 backend/openapi.json 生成 TypeScript API 类型。
 *
 * 链路: backend FastAPI(唯一事实源)
 *   → `python backend/tools/export_openapi.py` 产出 backend/openapi.json
 *   → 本脚本(openapi-typescript Node API) 产出 src/types/api-generated.ts
 *
 * CI 一致性门禁: api-contract job 重新生成并 `git diff --exit-code`,
 * 后端改了端点/模型而没重新导出 → PR 直接红。
 *
 * 实现注记: 走 openapiTS() 的 **JS 对象入参**(JSON.parse 后直接喂 ast),
 * 不传文件路径 —— 本项目目录名含中文, @redocly/openapi-core 的文件
 * resolver 会把路径 URL-encode 后再 lstat, 必 ENOENT(CLI 与 stdin 均中招)。
 *
 * 用法(项目根 frontend/):
 *   npm run gen:api
 */
import { existsSync, readFileSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import openapiTS, { astToString } from "openapi-typescript";

const root = resolve(import.meta.dirname, "..");
const repo = resolve(root, "..");
const openapiPath = resolve(repo, "backend", "openapi.json");
const outFile = resolve(root, "src", "types", "api-generated.ts");

if (!existsSync(openapiPath)) {
  console.error("[gen:api] backend/openapi.json 不存在 —— 先运行:");
  console.error("  python backend/tools/export_openapi.py");
  process.exit(1);
}

const ageMs = Date.now() - statSync(openapiPath).mtimeMs;
if (ageMs > 24 * 3600 * 1000) {
  console.warn("[gen:api] 警告: openapi.json 已超过 24 小时未重新导出, 建议先重跑 export_openapi.py");
}

const schema = JSON.parse(readFileSync(openapiPath, "utf-8"));
const ast = await openapiTS(schema, { enum: true });
mkdirSync(resolve(root, "src", "types"), { recursive: true });
writeFileSync(outFile, astToString(ast), "utf-8");
console.log(`[gen:api] 已生成 ${outFile} (${schema.paths ? Object.keys(schema.paths).length : 0} paths)`);
