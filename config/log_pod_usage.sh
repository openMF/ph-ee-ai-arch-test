#!/bin/bash
NAMESPACE="paymenthub"
OUTFILE="resource_usage_log.csv"
INTERVAL=30

echo "timestamp,pod,cpu,memory" > $OUTFILE

while true; do
  TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
  kubectl top pods -n $NAMESPACE --no-headers | while read pod cpu mem _; do
    echo "$TIMESTAMP,$pod,$cpu,$mem" >> $OUTFILE
  done
  sleep $INTERVAL
done
