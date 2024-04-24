#!/usr/bin/env python3
# Volatile Suite - This script runs a suite of Volatility modules to automate memory analysis.
# Copyright (C) 2024 Lukas Fischer
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
@author:    Lukas Fischer
@license:   GNU General public License 3.0
@contact:   GitHub:https://github.com/LF1scher/volatileSuite

Disclaimer:
This script is provided as-is and is not guaranteed to work in all environments. Use at your own risk.
"""

import subprocess, argparse, os, shutil, time, re
from concurrent.futures import ProcessPoolExecutor

# Banner
name = "Volatile Suite"
ver = "0.1.0"
author = "Lukas Fischer"
date = "2024-04-24"

volatility_command = "volatility -f {file} --profile={profile} --output-file={output_file} {module}"
output_dir = "volatile_output"

def main():
    # Print banner
    start_time = time.time()
    print(f"{name} - {ver} ({date})")
    print("Copyright (C) 2024 Lukas Fischer\nThis program comes with ABSOLUTELY NO WARRANTY\nThis is free software, and you are welcome to redistribute it under certain conditions")

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
    
    parser = argparse.ArgumentParser(description=name + " - " + ver)
    parser.add_argument("file", help="Memory dump file")
    parser.add_argument("--profile", default="none", help="Profile, if not specified, a suggested profile will be used")
    args = parser.parse_args()
    imageinfo = []
    if args.profile == "none":
        result = subprocess.run(f"volatility -f {args.file} imageinfo", shell=True, text=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        imageinfo = result.stdout.splitlines()
        for line in imageinfo:
            if "Suggested Profile(s)" in line:
                pattern = r"Suggested Profile\(s\) :\s+([^,]+)"
                args.profile = re.search(pattern, line).group(1)
                break
    print(f"Using profile: {args.profile}")

    # Create output directory
    print("Creating output directory...")
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    with open(f"{output_dir}/imageinfo.txt", "w") as f:
        f.write("\n".join(imageinfo))
    
    # Run Volatility
    print("Running Volatility...")
    with ProcessPoolExecutor() as executor:
        results = list(executor.map(run_module, volatility_windows_modules, [args]*len(volatility_windows_modules)))
    end_time = time.time()
    print(f"Ran {len(volatility_windows_modules)} in {end_time - start_time} seconds")
 
def run_module(module, args):
    """Run a Volatility module."""
    output_file = f"{output_dir}/{module}_out.txt"
    command = volatility_command.format(file=args.file, profile=args.profile, output_file=output_file, module=module)
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Print output
    error_lines = result.stderr.splitlines()
    errors = [line for line in error_lines if 'Volatility Foundation Volatility Framework 2.6.1' not in line]
    if errors:
        print(f"\u2717 {module}")
        return

    #output_lines = result.stdout.splitlines()
    #filtered_lines = [line for line in output_lines if 'Volatility Foundation Volatility Framework 2.6.1' not in line]
    #for line in filtered_lines:
    #    print(line)
    print(f"\u2713 {module}")

if __name__ == "__main__":
    main()