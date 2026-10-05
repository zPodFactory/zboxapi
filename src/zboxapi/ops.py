"""Multi-step host operations: named steps, run in order, rolled back on failure.

A response describes what happened in storage terms (step, target, detail, status). The
exact commands stay in the audit log, and come back in the response only with
`?verbose=true`. `?dry_run=true` returns the same steps with status `planned`.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable
from dataclasses import dataclass, field

from pydantic import BaseModel

from zboxapi import system

PLANNED, DONE, NOCHANGE, FAILED, SKIPPED = (
    "planned",
    "done",
    "nochange",
    "failed",
    "skipped",
)


class StepView(BaseModel):
    step: str
    target: str
    detail: str
    status: str
    command: str | None = None  # verbose only
    output: str | None = None  # verbose only


class OperationError(Exception):
    """A step failed; carries the steps run so far and the rollback performed."""

    def __init__(self, message: str, steps: list[StepView], rollback: list[StepView]):
        super().__init__(message)
        self.steps = steps
        self.rollback = rollback


@dataclass
class Step:
    step: str
    target: str
    detail: str
    argv: list[str] | None = None  # the command, when the step is one command
    stdin: str | None = None
    action: Callable[[], str | None] | None = (
        None  # python step; returns status or None
    )
    undo: Callable[[], None] | None = None  # how to revert, once done
    undo_argv: list[str] | None = None
    nochange_rc: int | None = None  # exit code meaning "nothing to do" (growpart: 1)
    status: str = PLANNED
    output: str = ""

    @property
    def command(self) -> str | None:
        if self.argv is None:
            return None
        text = shlex.join(self.argv)
        if self.stdin is not None:
            text += " <<< " + shlex.quote(self.stdin)
        return text

    def view(self, verbose: bool) -> StepView:
        return StepView(
            step=self.step,
            target=self.target,
            detail=self.detail,
            status=self.status,
            command=self.command if verbose else None,
            output=(self.output or None) if verbose else None,
        )


@dataclass
class Plan:
    name: str  # audit source, e.g. storage_create
    steps: list[Step] = field(default_factory=list)
    rollback: list[Step] = field(default_factory=list)

    def add(self, step: Step) -> Step:
        self.steps.append(step)
        return step

    def views(self, verbose: bool) -> list[StepView]:
        return [s.view(verbose) for s in self.steps]

    def rollback_views(self, verbose: bool) -> list[StepView]:
        return [s.view(verbose) for s in self.rollback]

    def execute(self, verbose: bool) -> list[StepView]:
        done: list[Step] = []
        for step in self.steps:
            try:
                self._run(step)
            except Exception as e:  # noqa: BLE001 - any failure triggers the rollback
                step.status = FAILED
                step.output = str(e)
                self._revert(done)
                raise OperationError(
                    f"{step.step} on {step.target} failed: {e}",
                    self.views(verbose),
                    self.rollback_views(verbose),
                ) from e
            done.append(step)
        return self.views(verbose)

    def _run(self, step: Step) -> None:
        if step.argv is not None:
            result = system.run(
                step.argv, check=False, input=step.stdin, source=self.name
            )
            step.output = (result.stdout or "").strip() or (result.stderr or "").strip()
            if result.returncode == 0:
                step.status = DONE
            elif step.nochange_rc is not None and result.returncode == step.nochange_rc:
                step.status = NOCHANGE
            else:
                raise system.CommandError(step.argv, result)
        elif step.action is not None:
            step.status = step.action() or DONE
        else:
            step.status = SKIPPED

    def _revert(self, done: list[Step]) -> None:
        for step in reversed(done):
            if step.status != DONE or (step.undo is None and step.undo_argv is None):
                continue  # nothing to undo for a no-op step such as settle or partx
            undo = Step(
                step=f"undo {step.step}",
                target=step.target,
                detail=f"revert: {step.detail}",
            )
            try:
                if step.undo_argv is not None:
                    undo.argv = step.undo_argv
                    result = system.run(step.undo_argv, check=False, source=self.name)
                    undo.output = (result.stderr or result.stdout or "").strip()
                    undo.status = DONE if result.returncode == 0 else FAILED
                else:
                    step.undo()
                    undo.status = DONE
            except Exception as e:  # noqa: BLE001 - keep reverting what we can
                undo.status = FAILED
                undo.output = str(e)
            self.rollback.append(undo)
