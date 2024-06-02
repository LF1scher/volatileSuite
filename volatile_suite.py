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

import subprocess, argparse, os, shutil, time, re, logging
from concurrent.futures import ProcessPoolExecutor

# Banner
name = "Volatile Suite"
ver = "1.0.0"
author = "Lukas Fischer"
date = "2024-04-24"

# Edit these variables to match your environment
volatility_executable = "vol.py"

volatility_command = f"{volatility_executable} -f {{file}} --profile={{profile}} --output-file={{output_file}} {{module}}"
output_dir = "volatile_output"

def main():
    # Print banner
    start_time = time.time()
    print(f"{name} - {ver} ({date})")
    print("Copyright (C) 2024 Lukas Fischer\nThis program comes with ABSOLUTELY NO WARRANTY\nThis is free software, and you are welcome to redistribute it under certain conditions")

    # Categorized Windows modules
    windows_core_modules = {
    "image_identification": [
        # Not working: kdbgscan, kpcrscan
        # Already ran: imageinfo
    ],
    "processes_and_dlls": [
        # Not working: psdispscan, enumfunc
        "pslist", "pstree", "psscan", "dlllist", "dlldump",
        "handles", "getsids", "cmdscan", "consoles", "privs", "envars",
        "verinfo"
    ],
    "process_memory": [
        # Not working: memmap, memdump, procdump, vadinfo, vadwalk, vadtree
        "vaddump", "evtlogs", "iehistory"
    ],
    "kernel_memory_and_objects": [
        # Not working: procdump, dumpfiles
        "modules", "modscan", "moddump", "ssdt", "driverscan", "filescan",
        "mutantscan", "symlinkscan", "thrdscan", "unloadedmodules"
    ],
    "networking": [
        "connections", "connscan", "sockets", "sockscan", "netscan"
    ],
    "registry": [
        # Not working: printkey, hivedump, hashdump 
        "hivescan", "hivelist", "lsadump",
        "userassist", "shellbags", "shimcache", "getservicesids", "dumpregistry"
    ],
    "crash_dumps_hibernation_and_conversion": [
        # Not working: imagecopy, raw2dmp, hpakextract
        "crashinfo", "hibinfo", "vboxinfo", "vmwareinfo",
        "hpakinfo"
    ],
    "file_system": [
        "mbrparser", "mftparser"
    ],
    "miscellaneous": [
        # Not working: strings, volshell , patcher, pagecheck
        "bioskbd", "timeliner"
    ]
    }
    windows_gui_modules = [
        "sessions","wndscan","deskscan","atomscan","atoms","clipboard","eventhooks","gahti","messagehooks","userhandles","screenshot","gditimers","windows","wintree"
        ]
    windows_malware_modules = [
        # Not working: malfind, yarascan, impscan, apihooks, driverirp
        "vcscan","ldrmodules","idt","gdt","threads","callbacks","devicetree","psxview","timers"
        ]

    core_modules_list = [f"core/{subcategory}/{module}" for subcategory, modules in windows_core_modules.items() for module in modules]
    all_modules = (
        core_modules_list +
        [f"gui/{module}" for module in windows_gui_modules] +
        [f"malware/{module}" for module in windows_malware_modules]
    )


    # Parse arguments
    parser = argparse.ArgumentParser(description=name + " - " + ver)
    parser.add_argument("file", help="Memory dump file")
    parser.add_argument("--profile", default="none", help="Profile, if not specified, a suggested profile will be used")
    global output_dir
    parser.add_argument("--output-dir", default=output_dir, help="Output directory")
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    imageinfo = []

    logging.debug("Debugging enabled")
    logging.debug(f"Arguments: {args}")

    # Find profile if not specified
    if args.profile == "none":
        print("Searching for a profile...")
        result = subprocess.run(f"{volatility_executable} -f {args.file} imageinfo", shell=True, text=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        imageinfo = result.stdout.splitlines()
        for line in imageinfo:
            if "Suggested Profile(s)" in line:
                pattern = r"Suggested Profile\(s\) :\s+([^,]+)"
                args.profile = re.search(pattern, line).group(1)
                break
    print(f"Using profile: {args.profile}")

    # Create output directory
    print("Creating output directory...")
    output_dir = args.output_dir
    if os.path.exists(output_dir):
        print("Output directory already exists. Deleting...")
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    # Create subdirectories
    for subdir in windows_core_modules.keys():
        os.makedirs(f"{output_dir}/core/{subdir}", exist_ok=True)
    os.makedirs(f"{output_dir}/gui", exist_ok=True)
    os.makedirs(f"{output_dir}/malware", exist_ok=True)
    with open(f"{output_dir}/imageinfo.txt", "w") as f:
        f.write("\n".join(imageinfo))
    print("Output directory created")

    # Run Volatility
    print(f"Running {len(all_modules)} modules in Volatility...\nThis may take a while. You can check the output directory for results.")
    with ProcessPoolExecutor() as executor:
        results = list(executor.map(run_module, all_modules, [args]*len(all_modules)))
    end_time = time.time()
    print(f"Ran {len(all_modules)} in {round(end_time - start_time, 2)} seconds")


def run_module(module, args):
    """Run a Volatility module."""
    # Dissasemble the module
    category, module = module.rsplit("/",1)
    output_file = f"{output_dir}/{category}/{module}_out.txt"
    
    command = volatility_command.format(file=args.file, profile=args.profile, output_file=output_file, module=module)
    
    # Specify additional arguments for certain modules
    if module in ["dlldump", "vaddump","evtlogs", "moddump", "dumpregistry", "screenshot"]:
        # Module needs output dir
        module_dir = module + "_out_files"
        os.makedirs(f"{output_dir}/{category}/{module_dir}", exist_ok=True)
        command = command + f" --dump-dir=volatile_output/{module_dir}"
    if module in ["evtlogs"]:
        # Dump raw logs
        command = command + f" --save-evt"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Print output
    error_lines = result.stderr.splitlines()
    errors = [line for line in error_lines if 'Volatility Foundation Volatility Framework' not in line]
    if errors:
        print(f"\u2717 {module}")
        err_file = f"{output_dir}/{category}/{module}_err.txt"
        with open(err_file, "w") as f:
            f.write("\n".join(errors))
        logging.debug(f"Errors in {module}: {errors}")
        return

    # output_lines = result.stdout.splitlines()
    # filtered_lines = [line for line in output_lines if 'Volatility Foundation Volatility Framework 2.6.1' not in line]
    # for line in filtered_lines:
    #     print(line)
    print(f"\u2713 {module}")

if __name__ == "__main__":
    main()