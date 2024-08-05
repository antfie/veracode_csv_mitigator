#!/usr/bin/env bash

# Exit if any command fails
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

mkdir -p scan
rm -f -- scan/veracode-auto-pack-veracode_csv_mitigator-python.zip
rm -f -- scan/*.json


echo -e "\n${CYAN}Dependency check...${NC}"

# 65232 has no update
pipenv check -i 65232


echo -e "\n${CYAN}Downloading the Veracode CLI...${NC}"
cd scan
set +e # Ignore failure which happens if the CLI is the current latest version
curl -fsS https://tools.veracode.com/veracode-cli/install | sh
set -e
cd ..


echo -e "${CYAN}Packaging for SAST scanning...${NC}"
./scan/veracode package --trust --source . --output scan/


echo -e "\n${CYAN}SAST Scanning with Veracode...${NC}"
./scan/veracode static scan --baseline-file sast_baseline.json --results-file scan/sast_results.json scan/veracode-auto-pack-veracode_csv_mitigator-python.zip


echo -e "\n${CYAN}Generating SBOMs...${NC}"
./scan/veracode sbom --type archive --source scan/veracode-auto-pack-veracode_csv_mitigator-python.zip --output scan/src.sbom.json