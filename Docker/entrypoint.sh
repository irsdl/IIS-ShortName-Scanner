#!/bin/bash

if [[ "$1" == "-f" ]];
then
   shift 1;
   ./multi_targets.sh "$@";
   exit;
fi

java -jar iis_shortname_scanner.jar "$@"
