"""进程停机阶段。

running 才接受新任务。进入 draining 后 HTTP 与审计提交都不再把工作放进
进程内存。stopped 表示连接已经开始关闭。
"""
from __future__ import annotations


class DrainController:
    def __init__(self) -> None:
        self.phase = "running"

    def begin(self) -> None:
        if self.phase == "running":
            self.phase = "draining"

    def mark_stopped(self) -> None:
        self.phase = "stopped"

    def reset(self) -> None:
        """测试复位。生产停机路径不调用。"""
        self.phase = "running"

    @property
    def accepting(self) -> bool:
        return self.phase == "running"

    @property
    def draining(self) -> bool:
        return self.phase != "running"


drain = DrainController()
