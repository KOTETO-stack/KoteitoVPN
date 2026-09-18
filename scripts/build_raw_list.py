#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_raw_list.py
Финальный шаг workflow №1: пишет output/raw_servers.txt.
"""
import json
import os

IN_FILE = os.path.join(os.path.dirname(__file__), "..", "dns_checked_configs.json")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")
OUT_FILE = os.path.join(OUT_DIR, "raw_servers.txt")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(IN_FILE, "r", encoding="utf-8") as f:
        configs = json.load(f)

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for c in configs:
            f.write(c["raw"] + "\n")

    print(f"Записано {len(configs)} рабочих серверов в {OUT_FILE}")


if __name__ == "__main__":
    main()
