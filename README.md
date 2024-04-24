# Volatile Suite

## Requirements:
- Volatility 2
- Python 3

## Installation:
1. Install Requirements
2. Clone the repository `git clone https://github.com/LF1scher/volatileSuite.git`

## Usage
`./volatile_suite.py <dumpFile> --profile <profile>`
`--profile` is optional, if not used, a profile will be automatically determined

## Output:
The output of each module is saved to a file in the volatility_output directory.

## Disclaimer:
This script is provided as-is and is not guaranteed to work in all environments. Use at your own risk.

## License:
This script is licensed under the GPL License.

## Known Issues:
- Some modules do not work
- Some modules need additional parameters
- Currently only supports Windows profiles

## TODO:
- [x] Silence default outputs
- [x] Remove non-working modules
- [ ] Categorize modules and their outputs
- [x] Automatically choose a suitable profile
- [ ] Enhance automatic profile determination
- [ ] Add other modules
- [ ] Add support for Linux profiles
- [ ] Add error handling for failed modules