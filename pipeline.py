#!/usr/bin/env python3
"""
pipeline.py - Advanced Shell Simulation, Deliverable 4: Piping

Parsing
  A command line is tokenized with shlex so that quoted text stays one
  argument; the operators |, <, >, >>, and a trailing & are recognized only
  when they are NOT quoted, so  grep "|" file  searches for a literal bar.
  The tokens are split on | into stages, each stage keeping its own command
  and arguments, plus optional input (<) and output (> or >>) redirection.

Dataflow
  The shell runs the stages left to right. The text a stage writes to
  standard output becomes the next stage's standard input (a string model of
  a pipe). Error messages go to standard error and are NOT piped, as in Unix.

Filters
  Text-processing commands used as pipeline stages: grep, sort, uniq, wc,
  head, tail. Each takes input text and returns (output text, exit status).
"""

import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional

OPERATORS = {"|", "<", ">", ">>", "&"}


class PipelineSyntaxError(ValueError):
    pass


@dataclass
class Pipeline:
    stages: List[List[str]]
    stdin_file: Optional[str] = None
    stdout_file: Optional[str] = None
    append: bool = False
    background: bool = False
    text: str = ""

    @property
    def is_simple(self):
        """A single command with no redirection (handled like Deliverable 1)."""
        return len(self.stages) == 1 and not self.stdin_file and not self.stdout_file


def tokenize(line):
    """Return a list of (token, is_operator) pairs."""
    lex = shlex.shlex(line, posix=False, punctuation_chars="|&<>")
    lex.whitespace_split = True
    out = []
    try:
        for tok in lex:
            if tok in OPERATORS or set(tok) <= set("|&<>"):
                if tok not in OPERATORS:
                    raise PipelineSyntaxError(f"unsupported operator '{tok}'")
                out.append((tok, True))
            else:
                words = shlex.split(tok)           # remove quotes
                out.append((words[0] if words else "", False))
    except ValueError as e:
        raise PipelineSyntaxError(f"parse error: {e}")
    return out


def parse(line):
    tokens = tokenize(line)
    if not tokens:
        return None
    p = Pipeline(stages=[[]], text=line.strip())
    i = 0
    while i < len(tokens):
        tok, is_op = tokens[i]
        if not is_op:
            p.stages[-1].append(tok)
        elif tok == "|":
            if not p.stages[-1]:
                raise PipelineSyntaxError("syntax error near '|': empty command")
            if p.stdout_file:
                raise PipelineSyntaxError("output redirection must be on the last command")
            p.stages.append([])
        elif tok in ("<", ">", ">>"):
            if i + 1 >= len(tokens) or tokens[i + 1][1]:
                raise PipelineSyntaxError(f"syntax error: '{tok}' needs a file name")
            target = tokens[i + 1][0]
            if tok == "<":
                if len(p.stages) > 1:
                    raise PipelineSyntaxError("input redirection must be on the first command")
                p.stdin_file = target
            else:
                p.stdout_file, p.append = target, tok == ">>"
            i += 1
        elif tok == "&":
            if i != len(tokens) - 1:
                raise PipelineSyntaxError("syntax error near '&'")
            p.background = True
        i += 1
    if not p.stages[-1]:
        raise PipelineSyntaxError("syntax error: command expected after '|'"
                                  if len(p.stages) > 1 else "syntax error near '&'")
    if p.background and not p.is_simple:
        raise PipelineSyntaxError("background pipelines and redirections are not supported")
    return p


# ----------------------------------------------------------------------
# Filters
# ----------------------------------------------------------------------
class FilterError(ValueError):
    pass


def lines_of(text):
    return text.splitlines() if text else []


def joined(lines):
    return "".join(line + "\n" for line in lines)


def take_flags(args, allowed, with_value=()):
    """Parse short flags such as -i -v or -n 5; returns (flags, operands)."""
    flags, rest, i = {}, [], 0
    while i < len(args):
        a = args[i]
        if a.startswith("-") and len(a) > 1 and not a[1:].isdigit():
            for ch in a[1:]:
                if ch in with_value:
                    if i + 1 >= len(args):
                        raise FilterError(f"option -{ch} needs a value")
                    flags[ch] = args[i + 1]
                    i += 1
                    break
                if ch not in allowed:
                    raise FilterError(f"invalid option -{ch}")
                flags[ch] = True
        elif a.startswith("-") and a[1:].isdigit():     # head -5
            flags["n"] = a[1:]
        else:
            rest.append(a)
        i += 1
    return flags, rest


def grep(args, text):
    flags, rest = take_flags(args, "ivcn")
    if not rest:
        raise FilterError("usage: grep [-i] [-v] [-c] [-n] PATTERN [FILE ...]")
    try:
        rx = re.compile(rest[0], re.IGNORECASE if "i" in flags else 0)
    except re.error as e:
        raise FilterError(f"invalid pattern '{rest[0]}': {e}")
    hits = [(n, line) for n, line in enumerate(lines_of(text), 1)
            if bool(rx.search(line)) != ("v" in flags)]
    if "c" in flags:
        return f"{len(hits)}\n", 0 if hits else 1
    out = [f"{n}:{line}" if "n" in flags else line for n, line in hits]
    return joined(out), 0 if hits else 1


def sort(args, text):
    flags, rest = take_flags(args, "rnu")
    lines = lines_of(text)
    if "n" in flags:
        def key(s):
            m = re.match(r"\s*(-?\d+(\.\d+)?)", s)
            return (0, float(m.group(1)), s) if m else (1, 0.0, s)
        lines.sort(key=key, reverse="r" in flags)
    else:
        lines.sort(reverse="r" in flags)
    if "u" in flags:
        seen, uniq_lines = set(), []
        for line in lines:
            if line not in seen:
                seen.add(line)
                uniq_lines.append(line)
        lines = uniq_lines
    return joined(lines), 0


def uniq(args, text):
    flags, rest = take_flags(args, "c")
    out, prev, count = [], None, 0
    for line in lines_of(text) + [None]:
        if line == prev:
            count += 1
            continue
        if prev is not None:
            out.append(f"{count:>7} {prev}" if "c" in flags else prev)
        prev, count = line, 1
    return joined(out), 0


def wc(args, text):
    flags, rest = take_flags(args, "lwc")
    counts = {"l": text.count("\n"), "w": len(text.split()), "c": len(text.encode())}
    chosen = [k for k in "lwc" if k in flags] or ["l", "w", "c"]
    return " ".join(f"{counts[k]:>7}" for k in chosen).strip() + "\n", 0


def head(args, text, tail_mode=False):
    flags, rest = take_flags(args, "", with_value="n")
    try:
        n = int(flags.get("n", 10))
    except ValueError:
        raise FilterError("line count must be an integer")
    lines = lines_of(text)
    return joined(lines[-n:] if tail_mode and n else ([] if tail_mode else lines[:n])), 0


def tail(args, text):
    return head(args, text, tail_mode=True)


FILTERS = {"grep": grep, "sort": sort, "uniq": uniq, "wc": wc, "head": head, "tail": tail}
# Arguments after the flags that name input files (the rest are operands)
FILE_OPERAND_START = {"grep": 1, "sort": 0, "uniq": 0, "wc": 0, "head": 0, "tail": 0}
