#!/bin/bash

if [ -z "$1" ]; then
        echo "[*] Scanning multiple targets using IIS Short Name (8.3) Scanner by Soroush Dalili - @irsdl"
        echo "[*] Usage: $0 <scope file> <is_default_https (1=https)>"
		echo "[*] Example: $0 scope.txt 1"
        exit 0
fi

default_scheme="http"
if [ "$2" = "1" ]; then
	default_scheme="https"
fi
# current directory
CUR=`pwd`

# Load scope
if [ ! -f "$1" ]; then
    echo "File not found: $1"
	exit 1
fi
scope=`cat "$1"`



### IIS Shortname Scanner time!
resultDir="$CUR"/iis_shortname_results
mkdir "$resultDir"

uniquehostname=()
while read target; do
        if [[ "$target" =~ [\'\"]+ ]]; then
            echo "Error: an invalid character was found in $1"
            exit 1
        fi
        if [[ "$target" =~ ^[[:space:]]*$ ]]; then
            # the input is whitespace!
            myhostname=""
        else
            myhostname=`python -c "from urlparse import urlparse;url = urlparse('$target','$default_scheme');print url.scheme+'://'+url.netloc+url.path"`
            if [ -z "$myhostname" ]; then
                    # when target is not a url (ip address for example), python variable will be empty
                    myhostname="$target"
            fi
            uniquehostname+=("$myhostname")
        fi
done <<<"$scope"

# unique hosts only
uniquehostname=($(printf "%s\n" "${uniquehostname[@]}" | sort -u));


for myhostname in "${uniquehostname[@]}"; do
        targetFile=$(echo "$myhostname" | tr '[\/\\\:\000-\017\177\377]' '_')
        timeout 30 java -jar iis_shortname_scanner.jar 0 20 "$myhostname" > "$resultDir/iis_shortname_${targetFile}.txt"
done

