#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
raw_to_json.py
Промежуточный шаг для workflow №2: превращает output/raw_servers.txt обратно
в raw_configs.json, чтобы прогнать тот же пайплайн ещё раз.
"""
import json
import os

IN_FILE = os.path.join("output", "raw_servers.txt")
OUT_FILE = "raw_configs.json"


def main():
    with open(IN_FILE, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(lines, f, ensure_ascii=False)

    print(f"Перенесено {len(lines)} строк из {IN_FILE} в {OUT_FILE}")


if __name__ == "__main__":
    main()
