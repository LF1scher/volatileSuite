# Volatile Suite

Automate running of multiple Volatility modules for forensic analysis

## Requirements:
- Volatility 2 (see https://github.com/volatilityfoundation/volatility)
- Python 2 (for Volatility to run properly. Keep in mind that Python 2 is no longer supported. Security risks may arise)
- Python 3

## Installation:
1. Install Requirements.
2. Clone the repository `git clone https://github.com/LF1scher/volatileSuite.git`.

## Usage
`./volatile_suite.py <dumpFile> --profile <profile> --output-dir <dir>`
`--profile` is optional, if not used, a suitable profile will be automatically determined.
`--output-dir`is optional, if not used, a directory `volatile_output` will be created in the current working directory.

## Disclaimer:
This script is provided as-is and is not guaranteed to work in all environments. Use at your own risk.

## License:
This script is licensed under the GPL License.

## Known Issues:
- Some modules do not work as they need additional parameters
- Currently only supports Windows profiles
- Only works with Volatility 2

## TODO:
- [ ] Enhance automatic profile determination
- [ ] Implement more complex modules
- [ ] Add support for Linux and Mac profiles
- [ ] Add better error handling for failed modules
- [ ] Enable module selection by category
- [ ] Add Volatility 3 support