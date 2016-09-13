#!/bin/bash

endpoints () {
	netstat -A inet -anp | awk '($6=="LISTEN"){print $4;}'
}

nc_it () {
	nc -vw1 ${ep/:/ } </dev/null
}

speaks_http () {
	nc_it "$1" 2>&1 | grep -q HTTP
}

curl_it () {
	local ep="$1"
	local file=$(echo "curl-$ep.txt"|tr : -)
	curl -v -o "$file" "http://$ep/"
}

for ep in $(endpoints); do
	echo "########## $ep ##########"
	if speaks_http "$ep"; then
		curl_it "$ep"
	fi
done

# EOF #
