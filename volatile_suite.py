#!/usr/bin/env python3
import subprocess, argparse, os, shutil, time
name = "Volatile Suite"
ver = "0.1.0"
author = "LF1scher"
date = "2024-04-24"
"""
This script runs a suite of Volatility modules on a memory dump file.

Usage:
python3 volatile_suite.py <memory_dump_file> <profile>

Disclaimer:
This script is provided as-is and is not guaranteed to work in all environments. Use at your own risk.

License:
This script is licensed under the GPL License.
"""

def main():
    start_time = time.time()
    print(name + " - " + ver)
    print("Author: " + author)
    print("Date: " + date)   
    volatility = "volatility -f {} --profile={} --output-file=volatility_output/{} {}"
    parser = argparse.ArgumentParser(description=name + " - " + ver)
    parser.add_argument("file", help="Memory dump file")
    parser.add_argument("profile", help="Profile")
    args = parser.parse_args()
    volatility_windows_modules = [
    "pslist",
    "psscan",
    "pstree",
    "psxview",
    "sessions",
    "connections",
    "connscan",
    "sockets",
    "sockscan",
    "filescan",
    "modules",
    "modscan",
    "dlllist",
    "driverscan",
    "devicetree",
    "hivelist",
    "shimcache",
    "getsids",
    "envars",
    "vadinfo",
    "ldrmodules",
    "malfind",
    "mutantscan",
    "hashdump",
    "privs",
    "evtlogs",
    "iehistory",
    "clipboard",
    "desktops",
    "screenshots",
    "timeliner",
    "kdbgscan",
    "svcscan",
    "ssdt"
]
    if os.path.exists("volatility_output"):
        shutil.rmtree("volatility_output")
    os.makedirs("volatility_output", exist_ok=True)
    print("Running Volatility Suite...")
    for module in volatility_windows_modules:
        output_file = f"{module}_out.txt"
        command = volatility.format(args.file, args.profile, output_file, module)
        subprocess.run(command, shell=True)
        # TODO: Silence default outputs
    end_time = time.time()
    print(f"Ran {len(volatility_windows_modules)} in {end_time - start_time} seconds")
    print("Done!")


if __name__ == "__main__":
    main()