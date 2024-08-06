#!/bin/env bash

# A sample script showing how to interface a bash script with
# the credentialfilter cli script
#

# should be read from HTTP_COOKIES or any other dedicated env variable
COOKIES="login=abc; other_cookie=87A9Er; cloudflare_bot=1305EFA13CB"
TARGET_URL="https://www.example.org/ab/cd/de?q=r2+y=24"
CONFIG_FILE="/tmp/py-http-handler/credentialfilter.conf.dist"

# due to limitations of bash (or my lack of experience) we have
# to remove all white space in the cookie
trimmed_cookies=${COOKIES//[[:blank:]]/}

RESULTX=$"$(./credentialfilter -cf ${CONFIG_FILE} \
			      -u  ${TARGET_URL} \
			      -c ${trimmed_cookies}; echo x$?)"

TARGET_HOST_TRUST_LEVEL=${RESULTX##*x}
FILTERED_COOKIES="${RESULTX%x*}"

echo "target host trust level: ${TARGET_HOST_TRUST_LEVEL}"
echo "#filtered cookies, output as HTTP Set-Cookie lines"

IFS=$'\n' readarray -t cookie_arr <<<"${FILTERED_COOKIES}"

# drop the extra \n the script outputs in the last line
unset cookie_arr[-1]

for i in "${cookie_arr[@]}"
do
   echo "Set-Cookie: $i"
done
