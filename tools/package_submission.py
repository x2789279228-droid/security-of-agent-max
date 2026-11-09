#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""参赛提交打包脚本 —— 从干净 clone 生成提交 zip(2026-11-10 阶段7)。

用法: python tools/package_submission.py [输出目录]
产物: 守望-源代码-<date>.zip —— 结构上不可能包含 .env/.venv/node_modules/
      certs/config/ssh(git 干净克隆, 这些文件从未入库)。
"""
import datetime
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_URL = "https://github.com/x2789279228-droid/security-of-agent-max.git"


def main():
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    date = datetime.date.today().isoformat()
    zip_path = out_dir / f"守望-源代码-{date}.zip"

    with tempfile.TemporaryDirectory(prefix="soc-pkg-") as td:
        repo = Path(td) / "src"
        print(f"[1/3] clone {REPO_URL} ...")
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, str(repo)], check=True)
        # 干净 clone 本身不含未跟踪文件; 再显式核对敏感面为零
        for bad in [".env", "certs", "config/ssh", "node_modules", ".venv",
                    "config/nginx/flink.htpasswd", "config/nginx/flink-credentials.txt"]:
            assert not (repo / bad).exists(), f"敏感路径出现在克隆里: {bad}"
        print("[2/3] 敏感面核对通过(无 .env/certs/ssh/htpasswd/venv/node_modules)")

        print(f"[3/3] 打包 {zip_path} ...")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for p in repo.rglob("*"):
                if p.is_file():
                    z.write(p, p.relative_to(repo.parent))
    size_mb = zip_path.stat().st_size / 1024 / 1024
    print(f"完成: {zip_path} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
