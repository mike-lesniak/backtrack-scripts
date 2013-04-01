#!/bin/bash
#
# By Lee Baird
# Feel free to contact me via chat or email with any feedback or suggestions that you may have:
# leebaird@gmail.com
#
# Special thanks to the following people:
#
# Jason Arnold - planning original concept, author of ssl-check and co-author of crack-wifi.
# Dave Klug - planning, testing and bug reports.
# Matt Banick - original development.
# Eric Milam - total re-write using functions.
# Martin Bos - IDS evasion techniques.
# Numerous people on freenode IRC - #bash and #sed (e36freak)

##############################################################################################################

# Variables
break="=================================================="
interface=$(ifconfig | grep -B10 'Loopback'| grep 'Ethernet' | cut -d ' ' -f1)
ip=$(ifconfig | grep -B10 'Loopback' | grep 'Bcast' | cut -d ':' -f2 | cut -d ' ' -f1)
user=$(whoami)

# Catch ctrl+c from user
trap f_Terminate 2

##############################################################################################################

f_Banner(){
echo
echo "______  ___ ______ ______  _____  _    _ ______  _____"
echo "|     \  |  |____  |      |     |  \  /  |_____ |____/"
echo "|_____/ _|_ _____| |_____ |_____|   \/   |_____ |    \_"
echo
echo "By Lee Baird"
echo
echo
}

##############################################################################################################

f_Error(){
echo
echo -e "\e[1;31m$break\e[0m"
echo
echo -e "\e[1;31m   *** Invalid choice or entry. ***\e[0m"
echo
echo -e "\e[1;31m$break\e[0m"
sleep 2
f_Main
}

##############################################################################################################

f_RunLocally(){
if [ -z $DISPLAY ]; then
     clear
     f_Banner
     echo
     echo $break
     echo
     echo "This option must be run locally, that is, in an X-Windows environment."
     echo
     read -p "Press <return> to continue."

     f_Main
fi
}

##############################################################################################################

f_Terminate(){
if [ -f tmp ]; then
     rm tmp*
fi

if [ -f $name ]; then
     rm -rf $name
fi

PID=$(ps -ef | grep 'discover.sh' | grep -v 'grep' | awk '{print $2}')
kill -9 $PID
}

##############################################################################################################

f_OSIG(){
f_RunLocally
clear
f_Banner
echo -e "\e[1;34mOpen Source Intelligence Gathering.\e[0m"
echo
echo "1.  Company"
echo "2.  Person"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     echo
     echo $break
     echo
     echo "Usage: target.com"
     echo
     echo -n "Domain: "
     read domain

     # Check for no answer
     if [ -z $domain ]; then
          f_Error
     fi

     echo
     echo $break
     echo
     echo "Gathering intel."

     # If folder doesn't exist, create it
     if [ ! -d /$user/$domain ]; then
          mkdir /$user/$domain
     fi

     wget -q https://www.deepmagic.com/ptrs/ptrs?search=$domain -O tmp
     sleep 15
     grep '<td>' tmp | cut -d '>' -f2 | cut -d '<' -f1 > tmp2
     # Break list into 2 columns
     paste -d ' ' - - < tmp2 > tmp3
     # Align second column
     column -t tmp3 > tmp4
     # Clean up and sort IPs
     grep "$domain$" tmp4 | sort -g > /$user/$domain/ptr-records.txt

     wget -q http://www.intodns.com/$domain
     sleep 5
     sed '/div id="master"/I,+12 d' $domain > tmp
     sed 's/ <a href="feedback\/?KeepThis=true&amp;TB_iframe=true&amp;height=300&amp;width=240" title="intoDNS feedback\" class=\"thickbox feedback\">send feedback<\/a>//' tmp > tmp2
     sed '/Processed in/I,+12 d' tmp2 > /$user/$domain/dns-health.htm

     # thanks to Jon Villanti for bug fix
     wget -q http://dns.robtex.com/$domain -O tmp
     sed '/<div id="xtail">/I,+16 d' tmp > /$user/$domain/dns.htm

     rm $domain tmp*

     echo
     printf 'The supporting data folder is located at \e[1;33m%s\e[0m\n' /$user/$domain/
     echo
     read -p "Press <return> to continue."

     firefox &
     sleep 2
     firefox -new-tab arin.net &
     sleep 1
     firefox -new-tab ipinfodb.com/ip_locator.php?ip=$domain &
     sleep 1
     firefox -new-tab toolbar.netcraft.com/site_report?url=http://www.$domain &
     sleep 1
     firefox -new-tab uptime.netcraft.com/up/graph?site=www.$domain &
     sleep 1
     # Jason - would like to d/l all results
     firefox -new-tab shodanhq.com/search?q=$domain &
     sleep 1
     # Jason - FreeTextSearch.xhtml?opCode=search&autoSuggested=true&freeText=$domain &
     firefox -new-tab jigsaw.com/ &
     sleep 1
     # Jason
     firefox -new-tab pastebin.com/ &
     sleep 1
     firefox -new-tab google.com/#q=filetype%3Axls+OR+filetype%3Axlsx+site%3A$domain &
     sleep 1
     firefox -new-tab google.com/#q=filetype%3Appt+OR+filetype%3Apptx+site%3A$domain &
     sleep 1
     firefox -new-tab google.com/#q=filetype%3Adoc+OR+filetype%3Adocx+site%3A$domain &
     sleep 1
     firefox -new-tab google.com/#q=filetype%3Apdf+site%3A$domain &
     sleep 1
     firefox -new-tab google.com/#q=filetype%3Atxt+site%3A$domain &
     sleep 1
     firefox -new-tab sec.gov/edgar/searchedgar/companysearch.html &
     sleep 1
     firefox -new-tab google.com/finance/
     ;;

     2)
     echo
     echo $break
     echo
     echo -n "First name: "
     read firstName

     # Check for no answer
     if [ -z $firstName ]; then
          f_Error
     fi

     echo
     echo -n "Last name: "
     read lastName

     # Check for no answer
     if [ -z $lastName ]; then
          f_Error
     fi

     firefox &
     sleep 2
     firefox -new-tab http://www.123people.com/s/$firstName+$lastName &
     sleep 1
     firefox -new-tab http://www.411.com/name/$firstName-$lastName/ &
     sleep 1
     firefox -new-tab http://www.cvgadget.com/person/$firstName/$lastName &
     sleep 1
     firefox -new-tab http://www.peekyou.com/$fireName_$lastName &
     sleep 1
     firefox -new-tab http://phonenumbers.addresses.com/people/$firstName+$lastName &
     sleep 1
     firefox -new-tab http://search.nndb.com/search/nndb.cgi?nndb=1&omenu=unspecified&query=$firstName+$lastName &
     sleep 1
     firefox -new-tab http://www.spokeo.com/search?q=$firstName+$lastName&s3=t24 &
     sleep 1
     firefox -new-tab http://www.zabasearch.com/query1_zaba.php?sname=$firstName%20$lastName&state=ALL&ref=$ref&se=$se&doby=&city=&name_style=1&tm=&tmr=
     ;;

     3) f_Main;;
     *) f_Error;;
esac
}

##############################################################################################################

f_Scrape(){
clear
f_Banner
echo -e "\e[1;34mScrape\e[0m"
echo
echo "1.  Passive"
echo "2.  Active"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     echo
     echo $break
     echo
     echo "Usage: target.com"
     echo
     echo -n "Domain: "
     read domain

     # Check for no answer
     if [ -z $domain ]; then
          f_Error
     fi

     echo
     echo $break
     echo

     # Number of tests
     total=20

     echo "goofile                   (1/$total)"
     /pentest/enumeration/google/goofile/goofile.py -d $domain -f xls > tmp
     /pentest/enumeration/google/goofile/goofile.py -d $domain -f xlsx >> tmp
     /pentest/enumeration/google/goofile/goofile.py -d $domain -f ppt >> tmp
     /pentest/enumeration/google/goofile/goofile.py -d $domain -f pptx >> tmp
     /pentest/enumeration/google/goofile/goofile.py -d $domain -f doc >> tmp
     /pentest/enumeration/google/goofile/goofile.py -d $domain -f docx >> tmp
     /pentest/enumeration/google/goofile/goofile.py -d $domain -f pdf >> tmp
     /pentest/enumeration/google/goofile/goofile.py -d $domain -f txt >> tmp

     grep $domain tmp | grep -v 'Searching in' | sort > tmp2

     grep '.xls' tmp2 > yxls
     grep '.ppt' tmp2 > yppt
     grep '.doc' tmp2 | egrep -v '(.pdf|.ppt|.xls)' > ydoc
     grep '.pdf' tmp2 > ypdf
     grep '.txt' tmp2 > ytxt

     echo
     echo "goog-mail                 (2/$total)"
     /opt/scripts/mods/goog-mail.py $domain | sort -u > tmp
     grep -Fv '..' tmp > tmp2
     # Remove lines that start with a number
     sed '/^[0-9]/d' tmp2 > tmp3
     # Change to lower case
     cat tmp3 | tr '[A-Z]' '[a-z]' > tmp4
     # Remove blank lines
     sed '/^$/d' tmp4 > zgoog-mail
     echo
     echo "goohost"
     echo "     IP                   (3/$total)"
     /pentest/enumeration/google/goohost/goohost.sh -t $domain -m ip > /dev/null
     echo "     Email                (4/$total)"
     /pentest/enumeration/google/goohost/goohost.sh -t $domain -m mail > /dev/null
     cat report-* > tmp
     # Move the second column to the first position
     grep $domain tmp | awk '{ print $2 " " $1 }' > tmp2
     column -t tmp2 > zgoohost
     rm *-$domain.txt
     echo
     echo "theHarvester"
     echo "     123people            (5/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b people123 > z123people
     echo "     Ask-mod              (6/$total)"
     /opt/scripts/mods/theHarvester2.py -d $domain -b ask > zask-mod
     echo "     Bing                 (7/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b bing > zbing
     echo "     Google               (8/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b google > zgoogle
     echo "     Google Profiles	  (9/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b google-profiles > zgoogle-profiles
     echo "     Jigsaw               (10/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b jigsaw > zjigsaw
     echo "     LinkedIn             (11/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b linkedin > zlinkedin
     echo "     Login-mod            (12/$total)"
     /opt/scripts/mods/theHarvester2.py -d $domain -b login > zlogin-mod
     echo "     PGP                  (13/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b pgp > zpgp
     echo "     Yahoo-mod            (14/$total)"
     /opt/scripts/mods/theHarvester2.py -d $domain -b yahoo > zyahoo-mod
     echo "     All                  (15/$total)"
     /pentest/enumeration/theharvester/theHarvester.py -d $domain -b all > zall
     echo
     echo "Metasploit                (16/$total)"
     /opt/metasploit/msf3/msfcli gather/search_email_collector DOMAIN=$domain E > tmp 2>/dev/null
     grep @$domain tmp | awk '{print $2}' | grep -v '%' | grep -Fv '...@' | sort -u > tmp2
     # Change to lower case
     cat tmp2 | tr '[A-Z]' '[a-z]' > tmp3
     # Remove blank lines
     sed '/^$/d' tmp3 > zmsf
     echo
     echo "URLCrazy                  (17/$total)"
	/pentest/enumeration/web/urlcrazy/urlcrazy $domain -o tmp
     # Clean up
     cat tmp | grep -v '?' | grep -v ':' | grep -v '#' | grep -v 'Typo Type' | grep -v 'URLCrazy' > tmp2
     # Remove lines that start with -
     grep -v '^-' tmp2 > tmp3
     # Remove blank lines
     sed '/^$/d' tmp3 > yurl2

     ##############################################################

     cat z* | egrep -v '(@|\*|-|=|\||;|:|"|<|>|/|\?)' > tmp
     # Remove blank lines
     sed '/^$/d' tmp > tmp2
     # Remove lines that contain a number
     sed '/[0-9]/d' tmp2 > tmp3
     # Remove lines that start with @ or .
     sed '/^\@\./d' tmp3 > tmp4
     # Remove trailing white space from each line
     sed 's/[ \t]*$//' tmp4 > tmp5
     # Substitute a space for a plus sign
     sed 's/+/ /g' tmp5 > tmp6
     # Change to lower case
     cat tmp6 | tr '[A-Z]' '[a-z]' > tmp7
     # Clean up
     egrep -v '(account|administrator|administrative|advanced|advertising|american|analyst|antivirus|apple seems|application|applications|article|asian|attorney|australia|automotive|banking|bbc|berlin|between|billion|biometrics|bizspark|breaches|broker|business|buyer|california|can i help|cannot|capital|career|carrying|certified|challenger|championship|change|chapter|charge|china|chinese|cloud|code|college|columbia|communications|community|company pages|competition|competitive|computer|concept|conference|config|connections|construction|consultant|contributor|controlling|coordinator|corporation|creative|croatia|crm|dallas|day care|death toll|department|designer|developer|developing|development|devine|diploma|director|disclosure|dispute|divisions|dos poc|download|drivers|during|economy|ecovillage|editor|education|effect|electronic|emails|embargo|empower|end user|energy|engineer|enterprise|entertainment|entreprises|entrepreneur|environmental|error page|ethical|example|excellence|executive|expertzone|exploit|facebook|faculty|fall edition|fast track|fatherhood|fbi|federal|filmmaker|finance|financial|forensic|found|freelance|from|frontiers in tax|full|germany|get control|global|google|government|graphic|greater|hackers|hacking|hardening|hawaii|hazing|headquarters|healthcare|history|homepage|hospital|house|hurricane|idc|in the news|index of|information|innovation|installation|insurers|integrated|international|internet|instructor|insurance|investigation|investment|investor|israel|japan|job|kelowna|laptops|letter|licensing|lighting|limitless|liveedu|llp|ltd|lsu|luscous|malware|managed|management|manager|managing|mastering|md|medical|meta tags|metro|microsoft|mitigation|money|monitoring|more coming|negative|network|networking|new user|newspaper|next page|nitrogen|nyc|occupied|office|online|outbreak|owners|partner|pathology|people|philippines|photo|places|planning|portfolio|preparatory|president|principal|print|private|producer|product|professional|professor|profile|project|publichealth|published|questions|redeeming|redirecting|register|regulation|remote|report|republic|research|rising|sales|satellite|save the date|school|scheduling|search|searching|secured|security|secretary|secrets|see more|selection|senior|service|services|software|solutions|source|special|statistics|strategy|student|superheroines|supervisor|support|switching|system|systems|targeted|technical|technology|tester|textoverflow|theater|tit for tat|toolbook|tools|traditions|trafficking|treasury|trojan|twitter|training|ts|types of scams|unclaimed|underground|university|untitled|view|Violent|virginia bar|voice|volume|wanted|web search|website|welcome|when the|whiskey|windows|workers|world|www|xbox)' tmp7 > tmp8
     # Remove leading and trailing whitespace from each line
     sed 's/^[ \t]*//;s/[ \t]*$//' tmp8 > tmp9
     # Remove lines that contain a single word
     sed '/[[:blank:]]/!d' tmp9 > tmp10
     # Clean up
     sed 's/\..../ /g' tmp10 > tmp11
     sed 's/\.../ /g' tmp11 > tmp12
     # Capitalize the first letter of every word
     sed "s/\b\(.\)/\u\1/g" tmp12 | sort -u > ynames

     cat z* | grep @$domain | grep -vF '...' | egrep -v '(\*|=|\+|\||;|:|"|<|>|/|\?)' > tmp
     # Remove trailing whitespace from each line
     sed 's/[ \t]*$//' tmp > tmp2
     # Change to lower case
     cat tmp2 | tr '[A-Z]' '[a-z]' > tmp3
     # Clean up
     grep -v 'web search' tmp3 | sort -u > yemails

     cat z* | sed '/^[0-9]/!d' | grep -v '@' > tmp
     # Substitute a space for a colon
     sed 's/:/ /g' tmp > tmp2
     # Move the second column to the first position
     awk '{ print $2 " " $1 }' tmp2 > tmp3
     column -t tmp3 > tmp4
     # Change to lower case
     cat tmp4 | tr '[A-Z]' '[a-z]' | sort -u > yurls

     ##############################################################

     echo "Nmap"
     echo "     Geolocation          (18/$total)"
     nmap -Pn -n -T4 --script ip-geolocation-geobytes $domain > tmp
     egrep -v '{/|geobytes|latency|Nmap|Other|results|SERVICE|shown|Starting}' tmp > tmp2
     sed 's/|//g' tmp2 > tmp3
     sed 's/_//g' tmp3 > tmp4
     # Remove blank lines
     sed '/^$/d' tmp4 > tmp5
     # Remove leading whitespace from each line
     sed 's/^[ \t]*//' tmp5 > zgeolocation


     ##############################################################

     echo
     echo "Whois"
     echo "     Domain               (19/$total)"
     whois -H $domain > tmp
     # Remove leading whitespace
     sed 's/^[ \t]*//' tmp > tmp2
     # Clean up
     egrep -v '(%|<a|=-=-=-=|Access may be|Additionally|Afilias except|and DNS Hosting|and limitations of|any use of|Be sure to|By submitting an|by the terms|can easily change|circumstances will|clientDeleteProhibited|clientTransferProhibited|clientUpdateProhibited|complaint will|contact information|Contact us|Copy and paste|currently set|database|data contained in|data presented in|date of|dissemination|Domaininfo AB|Domain Management|Domain names in|Domain status: ok|enable high|except as reasonably|failure to|facsimile of|for commercial purpose|for detailed information|For information for|for information purposes|for the sole|Get Noticed|Get a FREE|guarantee its|HREF|In Europe|In most cases|in obtaining|in the address|includes restrictions|including spam|information is provided|is not the|is providing|Learn how|Learn more|makes this information|MarkMonitor|mining this data|minute and one|modify existing|modify these terms|must be sent|name cannot|NamesBeyond|not to use|Note: This|NOTICE|obtaining information about|of Moniker|of this data|or hiding any|or otherwise support|other use of|own existing customers|Please be advised|Please note|policy|prior written consent|privacy is|Professional and|prohibited without|Promote your|protect the|Public Interest|queries or|Register your|Registrars|registration record|repackaging,|responsible for|See Business Registration|server at|solicitations via|sponsorship|Status|support the transmission|telephone, or facsimile|that apply to|that you will|the right| The data is|the transmission|The Trusted Partner|This listing is|This feature is|This information|This service is|to collect or|to entities|to report any|transmission of mass|UNITED STATES|United States|unsolicited advertising|Users may|Version 6|via e-mail|Visit AboutUs.org|while believed|will use this|with many different|with no guarantee|We reserve the|Whois|you agree|You may not)' tmp2 > tmp3
     # Remove lines starting with "*"
     sed '/^*/d' tmp3 > tmp4
     # Remove lines starting with "-"
     sed '/^-/d' tmp4 > tmp5
     # Remove lines starting with http
     sed '/^http/d' tmp5 > tmp6
     # Remove lines starting with US
     sed '/^US/d' tmp6 > tmp7
     # Clean up phone numbers
     sed 's/+1.//g' tmp7 > tmp8
     # Remove leading whitespace from file
     awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp8 > tmp9
     # Remove trailing whitespace from each line
     sed 's/[ \t]*$//' tmp9 > tmp10
     # Compress blank lines
     cat -s tmp10 > tmp11
     # Remove lines that end with various words then a colon or period(s)
     egrep -v '(2:$|3:$|Address.$|Address........$|Address.........$|Ext.:$|FAX:$|Fax............$|Fax.............$|Province:$|Server:$)' tmp11 > tmp12
     # Remove line after "Domain Servers:"
     sed -i '/^Domain Servers:/{n; /.*/d}' tmp12
     # Remove line after "Domain servers"
     sed -i '/^Domain servers/{n; /.*/d}' tmp12
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp12 > whois

     echo "     IP 		  (20/$total)"
     y=$(ping -c1 -w2 $domain | grep 'PING' | cut -d ')' -f1 | cut -d '(' -f2) ; whois -H $y > tmp
     # Remove leading whitespace
     sed 's/^[ \t]*//' tmp > tmp2
     # Remove trailing whitespace from each line
     sed 's/[ \t]*$//' tmp2 > tmp3
     # Clean up
     egrep -v '(\#|\%|\*|All reports|Comment|dynamic hosting|For fastest|For more|Found a referral|http|OriginAS:$|Parent:$|point in|RegDate:$|The activity|the correct|Without these)' tmp3 > tmp4
     # Remove leading whitespace from file
     awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp4 > tmp5
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp5 > tmp6
     # Compress blank lines
     cat -s tmp6 > tmp7
     # Clean up
     sed 's/+1-//g' tmp7 > whois-ip

     # Remove all empty files
     find -type f -empty -exec rm {} +

     ##############################################################

     echo "Passive Recon" > zreport
     echo $domain >> zreport
     date +%A" - "%B" "%d", "%Y >> zreport
     echo >> zreport
     echo >> zreport

     echo "Summary" >> zreport
     echo $break >> zreport

     echo > tmp

     if [ -f ynames ]; then
          namecount=$(wc -l ynames | cut -d ' ' -f1)
          echo "Names       $namecount" >> zreport
          echo "Names ($namecount)" >> tmp
          echo $break >> tmp
          cat ynames >> tmp
          echo >> tmp
     fi

     if [ -f yemails ]; then
          emailcount=$(wc -l yemails | cut -d ' ' -f1)
          echo "Emails      $emailcount" >> zreport
          echo "Emails ($emailcount)" >> tmp
          echo $break >> tmp
          cat yemails >> tmp
          echo >> tmp
     fi

     if [ -f yurls ]; then
          urlcount=$(wc -l yurls | cut -d ' ' -f1)
          echo "URLs        $urlcount" >> zreport
          echo "URLs ($urlcount)" >> tmp
          echo $break >> tmp
          cat yurls >> tmp
          echo >> tmp
     fi

     if [ -f yurl2 ]; then
          urlcount2=$(wc -l yurl2 | cut -d ' ' -f1)
          echo "Spoofed     $urlcount2" >> zreport
          echo "Spoofed ($urlcount2)" >> tmp
          echo $break >> tmp
          cat yurl2 >> tmp
          echo >> tmp
     fi

     if [ -f yxls ]; then
          xlscount=$(wc -l yxls | cut -d ' ' -f1)
          echo "Excel       $xlscount" >> zreport
          echo "Excel Files ($xlscount)" >> tmp
          echo $break >> tmp
          cat yxls >> tmp
          echo >> tmp
     fi

     if [ -f yppt ]; then
          pptcount=$(wc -l yppt | cut -d ' ' -f1)
          echo "PowerPoint  $pptcount" >> zreport
          echo "PowerPoint Files ($pptcount)" >> tmp
          echo $break >> tmp
          cat yppt >> tmp
          echo >> tmp
     fi

     if [ -f ydoc ]; then
          doccount=$(wc -l ydoc | cut -d ' ' -f1)
          echo "Word        $doccount" >> zreport
          echo "Word Files ($doccount)" >> tmp
          echo $break >> tmp
          cat ydoc >> tmp
          echo >> tmp
     fi

     if [ -f ypdf ]; then
          pdfcount=$(wc -l ypdf | cut -d ' ' -f1)
          echo "PDF         $pdfcount" >> zreport
          echo "PDF Files ($pdfcount)" >> tmp
          echo $break >> tmp
          cat ypdf >> tmp
          echo >> tmp
     fi

     if [ -f ytxt ]; then
          txtcount=$(wc -l ytxt | cut -d ' ' -f1)
          echo "Text        $txtcount" >> zreport
          echo "Text Files ($txtcount)" >> tmp
          echo $break >> tmp
          cat ytxt >> tmp
          echo >> tmp
     fi

     cat tmp >> zreport

     echo "Geolocation" >> zreport
     echo $break >> zreport
     cat zgeolocation >> zreport
     echo >> zreport
     echo "Whois Domain" >> zreport
     echo $break >> zreport
     cat whois >> zreport
     echo >> zreport
     echo "Whois IP" >> zreport
     echo $break >> zreport
     cat whois-ip >> zreport

     # If folder doesn't exist, create it
     if [ ! -d /$user/$domain ]; then
          mkdir /$user/$domain
     fi

     mv zreport /$user/$domain/passive-recon.txt

     rm tmp* whois* y* z*

     echo
     echo $break
     echo
     echo "***Scan complete.***"
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/$domain/passive-recon.txt
     echo
     echo
     exit
     ;;

     2)
     echo
     echo $break
     echo
     echo "Usage: target.com"
     echo
     echo -n "Domain: "
     read domain

     # Check for no answer
     if [ -z $domain ]; then
          f_Error
     fi

     echo
     echo $break
     echo

     # Number of tests
     total=10

     echo "Nmap"
     echo "     Email                (1/$total)"
     nmap -Pn -n -T4 -p80 --script http-email-harvest $domain > tmp
     grep '@' tmp | grep -v '%20' | grep -v 'jpg' | awk '{print $2}' | sort -u > zemail

     # Check if file is empty
     if [ ! -s zemail ]; then 
          rm zemail
     fi

     echo
     echo "dnsenum                   (2/$total)"
     /pentest/enumeration/dns/dnsenum/dnsenum.pl --noreverse --threads 10 $domain > tmp 2>/dev/null
     # Remove first 4 lines
     sed '1,4d' tmp > tmp2
     # Replace _ with =
     sed 's/_/=/g' tmp2 > tmp3
     # Find lines that start with =, and delete the following line
     sed '/^=/{n; /.*/d}' tmp3 > tmp4
     # Change discriptions
     sed 's/Trying Zone Transfers and getting Bind Versions/Zone Transfers/g' tmp4 > tmp5
     sed 's/Trying Zone Transfer for //g' tmp5 > tmp6
     cat tmp6 | grep -v '1;31m' | grep -v 'not specified' > tmp7
     sed '/=================================================/{n; /.*/d}' tmp7 > tmp8
     # Find lines that contain Bind Version, and delete the previous line
     printf '%s\n' 'g/Bind Version/-1d' w | ed -s tmp8
     # Clean up
     sed $'s/^\033...//' tmp8 > tmp9
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp9 > tmp10
     # Remove special character: ^Q
     tr -d '\021' < tmp10
     mv tmp10 zdnsenum

     echo
     echo "dnsrecon"
     echo "     Standard             (3/$total)"
     /pentest/enumeration/dns/dnsrecon/dnsrecon.py -d $domain -a > tmp
     egrep -v '(All queries will|Checking for|Could not|Enumerating SRV Records|Failed|filtered|It is resolving|not configured|NS Servers found|Performing General|Records Found|Removing any|Resolving|TCP Open|Trying NS|Wildcard)' tmp > tmp2
     # Remove first 4 characters from each line
     sed 's/^....//' tmp2 > tmp3
     # Remove leading whitespace from each line
     sed 's/^[ \t]*//' tmp3 | sort -u | awk '{print $2,$1,$3}' | column -t > zdnsrecon

     echo "     DNSSEC Zone Walk     (4/$total)"
     /pentest/enumeration/dns/dnsrecon/dnsrecon.py -d $domain -t zonewalk > tmp
     egrep -v '(Performing|Getting SOA|records found)' tmp > tmp2
     sed 's/will be used//g' tmp2 > tmp3
     sed 's/\[\*\] //g' tmp3 > zdnsrecon-walk

     echo "     Sub-domains (~5 min) (5/$total)"
     /pentest/enumeration/dns/dnsrecon/dnsrecon.py -d $domain -t brt -D /pentest/enumeration/dns/dnsrecon/namelist.txt -f > tmp
     sed 's/\[\*\] //g' tmp | egrep -v '(Performing host|Records Found)' > tmp2
     # Remove leading whitespace from each line
     sed 's/^[ \t]*//' tmp2 > tmp3
     # Move the second column to the first position
     awk '{print $2,$1,$3}' tmp3 > tmp4
     column -t tmp4 | sort -u > zdnsrecon-sub

     echo "     TLDs (~8 mim)        (6/$total)"
     /pentest/enumeration/dns/dnsrecon/dnsrecon.py -d $domain -t tld > tmp
     awk '{print $2,$3,$4}' tmp | egrep -v '(Performing|The operation|Records)' > tmp2
     # Move the second column to the first position
     awk '{print $2,$1,$3}' tmp2 > tmp3
     # Clean up
     column -t tmp3 | sort -u > zdnsrecon-tld

     echo
     echo "Traceroute"
     echo "     UDP                  (7/$total)"
     echo "UDP" > tmp
     traceroute $domain | awk -F" " '{print $1,$2,$3}' >> tmp
     echo >> tmp
     echo "ICMP ECHO" >> tmp
     echo "     ICMP ECHO            (8/$total)"
     traceroute -I $domain | awk -F" " '{print $1,$2,$3}' >> tmp
     echo >> tmp
     echo "TCP SYN" >> tmp
     echo "     TCP SYN              (9/$total)"
     traceroute -T $domain | awk -F" " '{print $1,$2,$3}' >> tmp
     grep -v 'traceroute' tmp > tmp2
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp2 > ztraceroute

     echo
     echo "Load Balancing Detector   (10/$total)"
     /pentest/enumeration/web/lbd/lbd.sh $domain > tmp 2>/dev/null
     egrep -v '(5.0_Pub|Apache|Checks|Microsoft-IIS|Might|Written)' tmp > tmp2
     # Remove leading whitespace from file
     awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp2 > tmp3
     # Remove leading whitespace from each line
     sed 's/^[ \t]*//' tmp3 > tmp4
     # Remove blank lines from end of file
     awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp4 > zlbd

     ##############################################################

     echo "Active Recon" > zreport
     echo $domain >> zreport
     date +%A" - "%B" "%d", "%Y >> zreport
     echo >> zreport

     if [ -f zemail ]; then
          echo "Email" >> zreport
          echo "==============================" >> zreport
          cat zemail >> zreport
     fi

     cat zdnsenum >> zreport
     echo >> zreport
     echo "Standard" >> zreport
     echo "==============================" >> zreport
     cat zdnsrecon >> zreport
     echo >> zreport
     echo "DNSSEC Zone Walk" >> zreport
     echo "==============================" >> zreport
     cat zdnsrecon-walk >> zreport
     echo >> zreport
     echo "Sub Domains" >> zreport
     echo "==============================" >> zreport
     cat zdnsrecon-sub >> zreport
     echo >> zreport
     echo "Top Level Domains" >> zreport
     echo "==============================" >> zreport
     cat zdnsrecon-tld >> zreport
     echo >> zreport
     echo "Traceroute" >> zreport
     echo "==============================" >> zreport
     cat ztraceroute >> zreport
     echo >> zreport
     echo "Load Balancing" >> zreport
     echo "==============================" >> zreport
     cat zlbd >> zreport

     # If folder doesn't exist, create it
     if [ ! -d /$user/$domain ]; then
          mkdir /$user/$domain
     fi

     mv zreport /$user/$domain/active-recon.txt

     rm tmp*
     rm z*

     echo
     echo $break
     echo
     echo "***Scan complete.***"
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/$domain/active-recon.txt
     echo
     echo
     exit
     ;;

     3) f_Main;;
     *) f_Error;;
esac
}

##############################################################################################################

f_TypeOfScan(){
echo -e "\e[1;34mType of scan: \e[0m"
echo
echo "1.  External"
echo "2.  Internal"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     echo
     echo -e "\e[1;33m[*] Setting source port to 53.\e[0m"
     sourceport=53
     echo
     echo $break
     echo
     ;;

     2)
     echo
     echo -e "\e[1;33m[*] Setting source port to 88.\e[0m"
     sourceport=88
     echo
     echo $break
     echo
     ;;

     3) f_Main;;
     *) f_Error;;
esac
}

##############################################################################################################

f_PingSweep(){
clear
f_Banner
f_TypeOfScan

echo -e "\e[1;34mType of input:\e[0m"
echo
echo "1.  List containing IPs, ranges and/or CIDRs."
echo "2.  Manual"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     echo
     echo -n "Enter the location of your list: "
     read location

     # Check for no answer
     if [ -z $location ]; then
          f_Error
     fi

     # Check for wrong answer
     if [ ! -f $location ]; then
          f_Error
     fi

     echo
     echo "Running an Nmap ping sweep for live hosts."
     nmap -iL $location -sn -T4 --stats-every 10s -g $sourceport > tmp
     ;;

     2)
     echo
     echo -n "Enter your targets: "
     read manual

     # Check for no answer
     if [ -z $manual ]; then
          f_Error
     fi

     echo
     echo "Running an Nmap ping sweep for live hosts."
     nmap -sn -T4 --stats-every 10s -g $sourceport $manual > tmp
     ;;

     *) f_Error;;
esac

# Thanks JK
grep -E '([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})' -o tmp > /$user/hosts.txt

rm tmp*

echo
echo $break
echo
echo "***Scan complete.***"
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/hosts.txt
echo
echo
exit
}

##############################################################################################################

f_ScanName(){
f_TypeOfScan

echo -n "Name of scan: "
read name

# Check for no answer
if [ -z $name ]; then
     f_Error
fi

mkdir -p $name
}

##############################################################################################################

f_Single(){
clear
f_Banner
f_ScanName

echo
echo -n "Single IP, URL or Range: "
read target

# Check for no answer
if [ -z $target ]; then
     rm -rf $name
     f_Error
fi

echo $target > tmp-list
location=tmp-list

START=$(date +%r\ %Z)

f_Discovery
f_NumHosts
f_Scan
f_Ports
f_Scripts
f_Metasploit
f_Report
}

##############################################################################################################

f_LAN(){
clear
f_Banner
f_ScanName

START=$(date +%r\ %Z)

arp-scan -localnet -interface $interface | egrep -v '(Ending|Interface|packets|Starting)' | awk '{print $1}' | sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 > tmp

# Remove blank lines
sed '/^$/d' tmp > $name/hosts.txt

# Check for zero hosts (empty file)
if [ ! -s $name/hosts.txt ]; then
     rm -rf "$name" tmp*
     echo
     echo $break
     echo
     echo "***Scan complete.***"
     echo
     echo -e "\e[1;33mNo hosts found with open ports.\e[0m"
     echo
     echo
     exit
fi

# Number of hosts
number=$(wc -l $name/hosts.txt | cut -d ' ' -f1)

if [ $number -eq 1 ]; then
     echo
     echo $break
     echo
     echo -e "\e[1;33mHost discovered.\e[0m"
else
     echo
     echo $break
     echo
     echo -e "\e[1;33m$number hosts discovered with open ports.\e[0m"
fi

f_Scan
f_Ports
f_Scripts
f_Metasploit
f_Report
}

##############################################################################################################

f_List(){
clear
f_Banner
f_ScanName

echo
echo -n "Enter the location of your list: "
read location

# Check for no answer
if [ -z $location ]; then
     rm -rf $name
     f_Error
fi

# Check for wrong answer
if [ ! -f $location ]; then
     rm -rf $name
     f_Error
fi

START=$(date +%r\ %Z)

f_Discovery
f_NumHosts
f_Scan
f_Ports
f_Scripts
f_Metasploit
f_Report
}

##############################################################################################################

f_CIDR(){
clear
f_Banner
f_ScanName

echo
echo Usage: 192.168.0.0/16
echo
echo -n "Enter CIDR notation: "
read cidr

# Check for no answer
if [ -z $cidr ]; then
     rm -rf $name
     f_Error
fi

# Check for wrong answer

sub=$(echo $cidr|cut -d '/' -f2)
max=32

if [ "$sub" -gt "$max" ]; then
     f_Error
fi

echo $cidr | grep '/' > /dev/null 2>&1

if [ $? -ne 0 ]; then
     f_Error
fi

echo $cidr | grep [[:alpha:]\|[,\\]] > /dev/null 2>&1

if [ $? -eq 0 ]; then
     f_Error
fi

echo $cidr > tmp-list
location=tmp-list

echo
echo -n "Do you have an exclusion list? (y/N) "
read ExFile

if [ -z $ExFile ]; then
     ExFile="n"
fi

ExFile="$(echo ${ExFile} | tr 'A-Z' 'a-z')"

if [ $ExFile == "y" ]; then
     echo -n "Enter the path to the exclude list file: "
     read excludefile

     START=$(date +%r\ %Z)

     if [ -z $excludefile ]; then
          f_Error
     fi

     if [ ! -f $excludefile ]; then
          f_Error
     fi

     f_DiscoveryExclude
else
     f_Discovery
fi

f_NumHosts
f_Scan
f_Ports
f_Scripts
f_Metasploit
f_Report
}

##############################################################################################################

f_Discovery(){
echo
echo $break
echo
echo -e "\e[1;34mHost discovery.\e[0m"

nmap -iL $location -PP -PE -PM -PI -PA20,53,80,113,443,5060,10043 -PS1,7,9,13,21-23,25,37,42,49,53,69,79-81,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,407,443,445,465,500,502,512-515,523,540,548,554,617,623,689,705,783,902,910,912,921,993,995,1000,1024,1030,1035,1090,1098-1103,1129,1158,1199,1220,1234,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1900,2000-2001,2049,2100,2103,2121,2199,2207,2222,2323,2380,2525,2533,2598,2638,2809,2947,2967,3000,3050,3057,3128,3273,3306,3389,3500,3628,3632,3690,3780,3790,4000,4444-4445,4659,4848,5038,5051,5060-5061,5093,5168,5250,5351,5353,5355,5400,5405,5432-5433,5520-5521,5554-5555,5560,5580,5631-5632,5800,5900-5910,5920,6000,6050,6060,6070,6080,6101,6106,6112,6379,6405,6502-6504,6660,6667,6905,7080,7144,7210,7510,7579-7580,7700,7777,7787,7800-7801,8000,8008,8014,8028,8030,8080-8081,8087,8090,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8880,8888-8890,8899,8901-8903,9000,9080-9081,9084,9090,9099,9111,9160,9152,9495,9809-9815,9999-10001,10008,10050,10098,10162,10202-10203,10443,10616,10628,11000,11099,11234,11333,12174,12203,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20031,20034,20101,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,31099,32913,34443,35871,37718,38080,38292,41025,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,50000-50004,50013,50500-50504,57772,62078,62514,65535 -PU59428 -p1,7,9,13,21-23,25,37,42,49,53,69,79-81,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,407,443,445,465,500,502,512-515,523,540,548,554,617,623,689,705,783,902,910,912,921,993,995,1000,1024,1030,1035,1090,1098-1103,1129,1158,1199,1220,1234,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1900,2000-2001,2049,2100,2103,2121,2199,2207,2222,2323,2380,2525,2533,2598,2638,2809,2947,2967,3000,3050,3057,3128,3273,3306,3389,3500,3628,3632,3690,3780,3790,4000,4444-4445,4659,4848,5038,5051,5060-5061,5093,5168,5250,5351,5353,5355,5400,5405,5432-5433,5520-5521,5554-5555,5560,5580,5631-5632,5800,5900-5910,5920,6000,6050,6060,6070,6080,6101,6106,6112,6379,6405,6502-6504,6660,6667,6905,7080,7144,7210,7510,7579-7580,7700,7777,7787,7800-7801,8000,8008,8014,8028,8030,8080-8081,8087,8090,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8880,8888-8890,8899,8901-8903,9000,9080-9081,9084,9090,9099,9111,9160,9152,9495,9809-9815,9999-10001,10008,10050,10098,10162,10202-10203,10443,10616,10628,11000,11099,11234,11333,12174,12203,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20031,20034,20101,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,31099,32913,34443,35871,37718,38080,38292,41025,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,50000-50004,50013,50500-50504,57772,62078,62514,65535 --host-timeout=10m --max-rtt-timeout=600ms --initial-rtt-timeout=300ms --min-rtt-timeout=300ms --max-retries=2 --min-rate=200 --stats-every 10s -g $sourceport -oN tmp
}

##############################################################################################################

f_DiscoveryExclude(){
echo
echo $break
echo
echo -e "\e[1;34mHost discovery.\e[0m"

nmap -iL $location --excludefile $excludefile -PP -PE -PM -PI -PA20,53,80,113,443,5060,10043 -PS1,7,9,13,21-23,25,37,42,49,53,69,79-81,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,407,443,445,465,500,502,512-515,523,540,548,554,617,623,689,705,783,902,910,912,921,993,995,1000,1024,1030,1035,1090,1098-1103,1129,1158,1199,1220,1234,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1900,2000-2001,2049,2100,2103,2121,2199,2207,2222,2323,2380,2525,2533,2598,2638,2809,2947,2967,3000,3050,3057,3128,3273,3306,3389,3500,3628,3632,3690,3780,3790,4000,4444-4445,4659,4848,5038,5051,5060-5061,5093,5168,5250,5351,5353,5355,5400,5405,5432-5433,5520-5521,5554-5555,5560,5580,5631-5632,5800,5900-5910,5920,6000,6050,6060,6070,6080,6101,6106,6112,6379,6405,6502-6504,6660,6667,6905,7080,7144,7210,7510,7579-7580,7700,7777,7787,7800-7801,8000,8008,8014,8028,8030,8080-8081,8087,8090,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8880,8888-8890,8899,8901-8903,9000,9080-9081,9084,9090,9099,9111,9160,9152,9495,9809-9815,9999-10001,10008,10050,10098,10162,10202-10203,10443,10616,10628,11000,11099,11234,11333,12174,12203,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20031,20034,20101,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,31099,32913,34443,35871,37718,38080,38292,41025,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,50000-50004,50013,50500-50504,57772,62078,62514,65535 -PU59428 -p1,7,9,13,21-23,25,37,42,49,53,69,79-81,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,407,443,445,465,500,502,512-515,523,540,548,554,617,623,689,705,783,902,910,912,921,993,995,1000,1024,1030,1035,1090,1098-1103,1129,1158,1199,1220,1234,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1900,2000-2001,2049,2100,2103,2121,2199,2207,2222,2323,2380,2525,2533,2598,2638,2809,2947,2967,3000,3050,3057,3128,3273,3306,3389,3500,3628,3632,3690,3780,3790,4000,4444-4445,4659,4848,5038,5051,5060-5061,5093,5168,5250,5351,5353,5355,5400,5405,5432-5433,5520-5521,5554-5555,5560,5580,5631-5632,5800,5900-5910,5920,6000,6050,6060,6070,6080,6101,6106,6112,6379,6405,6502-6504,6660,6667,6905,7080,7144,7210,7510,7579-7580,7700,7777,7787,7800-7801,8000,8008,8014,8028,8030,8080-8081,8087,8090,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8880,8888-8890,8899,8901-8903,9000,9080-9081,9084,9090,9099,9111,9160,9152,9495,9809-9815,9999-10001,10008,10050,10098,10162,10202-10203,10443,10616,10628,11000,11099,11234,11333,12174,12203,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20031,20034,20101,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,31099,32913,34443,35871,37718,38080,38292,41025,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,50000-50004,50013,50500-50504,57772,62078,62514,65535 --host-timeout=10m --max-rtt-timeout=600ms --initial-rtt-timeout=300ms --min-rtt-timeout=300ms --max-retries=2 --min-rate=200 --stats-every 10s -g $sourceport -oN tmp
}

##############################################################################################################

f_NumHosts(){
egrep -v '(close|filtered|initiated|latency|rDNS|seconds|STATE|Warning)' tmp | grep 'open' -B1 | grep 'Nmap' | cut -d '(' -f2 | cut -d ')' -f1 > tmp2
sed 's/Nmap scan report for //' tmp2 > tmp3

# Remove blank lines
sed '/^$/d' tmp3 > $name/hosts.txt

# Check for zero hosts (empty file)
if [ ! -s $name/hosts.txt ] ; then
     rm -rf "$name" tmp*
     echo
     echo $break
     echo
     echo "***Scan complete.***"
     echo
     echo -e "\e[1;33mNo hosts found with open ports.\e[0m"
     echo
     echo
     exit
fi

# Number of hosts
number=$(wc -l $name/hosts.txt | cut -d ' ' -f1)

if [ $number -eq 1 ]; then
     echo
     echo $break
     echo
     echo -e "\e[1;33mHost discovered.\e[0m"
else
     echo
     echo $break
     echo
     echo -e "\e[1;33m$number hosts discovered with open ports.\e[0m"
fi
}

##############################################################################################################

f_Scan(){
echo
echo $break
echo
echo -e "\e[1;34mRunning default nmap scan.\e[0m"

nmap -iL $name/hosts.txt -Pn -n -sSV -sUV -p U:53,67-69,111,123,135,137-139,161,162,445,500,514,520,523,631,998,1434,1701,1900,4500,5353,6481,17185,31337,49152,49154,T:13,21-23,25,37,42,49,53,67,69,79-81,88,105,109-111,113,123,135,137-139,143,161,179,222,384,389,407,443,445,465,500,512-515,523,524,540,548,554,617,623,631,689,705,783,873,910,912,921,993,995,1000,1024,1050,1080,1099,1100,1158,1220,1300,1311,1344,1352,1433-1435,1494,1521,1524,1533,1581-1582,1604,1720,1723,1755,1900,2000,2049,2100,2103,2121,2202,2207,2222,2323,2380,2525,2533,2598,2628,2638,2947,2967,3000,3031,3050,3057,3128,3260,3306,3389,3500,3628,3632,3690,3780,3790,4000,4369,4445,5019,5051,5060-5061,5093,5168,5250,5353,5400,5405,5432-5433,5554-5555,5666,5672,5800,5850,5900-5910,5984,6000-6005,6050,6060,6070,6080,6101,6106,6112,6379,6405,6502-6504,6660,6666-6667,6697,7080,7144,7210,7510,7634,7777,7787,8000,8008-8009,8028,8030,8080-8081,8090,8091,8180,8222,8300,8332-8333,8400,8443-8444,8787,8800,8880,8888,8899,9080-9081,9090,9100,9111,9152,9160,9999-10000,10050,10202-10203,10443,10616,10628,11000,11211,12174,12203,12345,13500,14330,17185,18881,19150,19300,19810,20031,20222,22222,25000,25025,26000,26122,27017,28222,30000,35871,38292,41025,41523-41524,41364,44334,48992,49663,50000-50004,50013,50030,50060,50070,50075,50090,57772,59034,60010,60030,62078,62514,65535 --open -O --osscan-guess --max-os-tries 1 --version-intensity 0 --host-timeout 5m --min-hostgroup 100 --max-rtt-timeout 600ms --initial-rtt-timeout=300ms --min-rtt-timeout 300ms --max-retries 3 --min-rate 150 --stats-every 10s -g $sourceport -oA $name/nmap

# Clean up nmap output
egrep -v '(1 hop|All|CPE|elapsed|filtered|fingerprint|guesses|GUESSING|hops|initiated|latency|matches|NEXT|Not|NSE|OS:|Please|remaining|RTTVAR|scanned|SF|Skipping|specialized|Starting|Timing|unrecognized|Warning|WARNING)' $name/nmap.nmap > tmp
sed 's/Nmap scan report for //' tmp > tmp2
sed '/^$/! b end; n; /^$/d; : end' tmp2 > $name/nmap.txt

rm $name/nmap.nmap

# Show open ports
grep 'open' $name/nmap.txt | awk '{print $1}' | sort -u | sort -n > $name/ports.txt
grep 'tcp' $name/ports.txt | cut -d '/' -f1 > $name/ports-tcp.txt
grep 'udp' $name/ports.txt | cut -d '/' -f1 > $name/ports-udp.txt

# Clean up and show banners
grep 'open' $name/nmap.txt | awk '{for (i=4;i<=NF;i++) {printf "%s%s",sep, $i;sep=" "}; printf "\n"}' | sort -u > tmp
sed 's/^ //' tmp | sort -u > tmp2

# Remove blank lines
sed '/^$/d' tmp2 > $name/banners.txt

# Remove all empty files
find $name/ -type f -empty -exec rm {} +
}

##############################################################################################################

f_Ports(){
echo
echo $break
echo
echo -e "\e[1;34mLocating high-value ports.\e[0m"
echo "     TCP"
TCP_PORTS="13 21 22 23 25 70 79 80 110 111 139 143 389 443 445 465 523 524 548 554 631 873 993 995 1050 1080 1099 1158 1344 1352 1433 1521 1720 1723 2202 2628 2947 3031 3260 3306 3389 3632 4369 5019 5432 5666 5672 5850 5900 5984 6000 6001 6002 6003 6004 6005 6379 6666 7210 7634 7777 8000 8009 8080 8081 8091 8222 8332 8333 8400 8443 9100 9160 9999 10000 11211 12345 19150 27017 35871 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $TCP_PORTS; do
     cat $name/nmap.gnmap | grep "\<$i/open/tcp\>" | cut -d ' ' -f2 > $name/$i.txt
done

if [ -f $name/523.txt ]; then
     mv $name/523.txt $name/523-tcp.txt
fi

echo "     UDP"
UDP_PORTS="53 67 69 123 137 161 500 523 1434 1604 3478 5353 6481 17185 31337"

for i in $UDP_PORTS; do
     cat $name/nmap.gnmap | grep "\<$i/open/udp\>" | cut -d ' ' -f2 > $name/$i.txt
done

if [ -f $name/523.txt ]; then
     mv $name/523.txt $name/523-udp.txt
fi

# Combine Apache HBase ports and sort
cat $name/60010.txt $name/60030.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/apache-hbase.txt

# Combine Bitcoin ports and sort
cat $name/8332.txt $name/8333.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/bitcoin.txt

# Combine DB2 ports and sort
cat $name/523-tcp.txt $name/523-udp.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/db2.txt

# Combine Hadoop ports and sort
cat $name/50030.txt $name/50060.txt $name/50070.txt $name/50075.txt $name/50090.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/hadoop.txt

# Combine SSL ports
echo > tmp

port="21 25 443 465 993 995 8443"

for i in $port; do
     if [ -f $name/$i.txt ]; then
          sed -e 's/$/:'$i'/' $name/$i.txt >> tmp
     fi
done

# Remove blank lines
sed '/^$/d' tmp > $name/ssl.txt

# Combine web ports and sort
cat $name/80.txt $name/443.txt $name/8000.txt $name/8080.txt $name/8443.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/web.txt

# Combine X11 ports and sort
cat $name/6000.txt $name/6001.txt $name/6002.txt $name/6003.txt $name/6004.txt $name/6005.txt > tmp
sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 tmp > $name/x11.txt

# Remove all empty files
find $name/ -type f -empty -exec rm {} +
}

##############################################################################################################

f_CleanUp(){
sed 's/Nmap scan report for //' tmp > tmp2

# Remove lines that start with |, and have various numbers of trailing spaces.
sed -i '/^| *$/d' tmp2

egrep -v '(0 of 100|afp-serverinfo:|ACCESS_DENIED|appears to be clean|cannot|close|closed|Compressors|Could not|Couldn|Denied|denied|Did not|DISABLED|dns-nsid:|dns-service-discovery:|Document Moved|doesn|eppc-enum-processes|error|Error|ERROR|failed|filtered|GET|hbase-region-info:|HEAD|Host is up|Host script results|impervious|incorrect|latency|ldap-rootdse:|LDAP Results|Likely CLEAN|nbstat:|No accounts left|No Allow|no banner|none|Nope.|not allowed|Not Found|Not Shown|not supported|NOT VULNERABLE|nrpe-enum:|ntp-info:|rdp-enum-encryption:|remaining|rpcinfo:|seconds|See http|Service Info|Skipping|smb-check-vulns|smb-mbenum:|sorry|Starting|telnet-encryption:|Telnet server does not|TIMEOUT|Unauthorized|uncompressed|unhandled|Unknown|viewed over a secure|vnc-info:|wdb-version:)' tmp2 > tmp3

grep -v "Can't" tmp3 > tmp4
}

##############################################################################################################

f_Scripts(){
echo
echo $break
echo
echo -e "\e[1;34mRunning nmap scripts.\e[0m"

# If the file for the corresponding port doesn't exist, skip
if [ -f $name/13.txt ]; then
	echo "     Daytime"
	nmap -iL $name/13.txt -Pn -n --open -p13 --script=daytime --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-13.txt
fi

if [ -f $name/21.txt ]; then
	echo "     FTP"
	nmap -iL $name/21.txt -Pn -n --open -p21 --script=banner,ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-21.txt
fi

if [ -f $name/22.txt ]; then
	echo "     SSH"
	nmap -iL $name/22.txt -Pn -n --open -p22 --script=ssh2-enum-algos,sshv1 --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-22.txt
fi

if [ -f $name/23.txt ]; then
	echo "     Telnet"
	nmap -iL $name/23.txt -Pn -n --open -p23 --script=banner,telnet-encryption --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-23.txt
fi

if [ -f $name/25.txt ]; then
	echo "     SMTP"
	nmap -iL $name/25.txt -Pn -n --open -p25 --script=banner,smtp-commands,smtp-open-relay,smtp-strangeport --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	printf '%s\n' 'g/NOT VULNERABLE/d\' '-d' w | ed -s tmp4
	mv tmp4 $name/script-25.txt
fi

if [ -f $name/53.txt ]; then
	echo "     DNS"
	nmap -iL $name/53.txt -Pn -n -sU --open -p53 --script=dns-cache-snoop,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-update,dns-zone-transfer --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-53.txt
fi

if [ -f $name/67.txt ]; then
	echo "     DHCP"
	nmap -iL $name/67.txt -Pn -n -sU --open -p67 --script=dhcp-discover --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-67.txt
fi

if [ -f $name/70.txt ]; then
	echo "     Gopher"
	nmap -iL $name/70.txt -Pn -n --open -p70 --script=gopher-ls --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-70.txt
fi

if [ -f $name/79.txt ]; then
	echo "     Finger"
	nmap -iL $name/79.txt -Pn -n --open -p79 --script=finger --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-79.txt
fi

if [ -f $name/110.txt ]; then
	echo "     POP3"
	nmap -iL $name/110.txt -Pn -n --open -p110 --script=banner,pop3-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-110.txt
fi

if [ -f $name/111.txt ]; then
	echo "     NFS"
	nmap -iL $name/111.txt -Pn -n --open -p111 --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-111.txt
fi

if [ -f $name/123.txt ]; then
	echo "     NTP"
	nmap -iL $name/123.txt -Pn -n -sU --open -p123 --script=ntp-info,ntp-monlist --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-123.txt
fi

if [ -f $name/137.txt ]; then
	echo "     NetBIOS"
	nmap -iL $name/137.txt -Pn -n -sU --open -p137 --script=nbstat --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	sed -i '/^MAC/{n; /.*/d}' tmp4		# Find lines that start with MAC, and delete the following line
	sed -i '/^137\/udp/{n; /.*/d}' tmp4	# Find lines that start with 137/udp, and delete the following line
	mv tmp4 $name/script-137.txt
fi

if [ -f $name/139.txt ]; then
     echo "     MS08-067"
     nmap -iL $name/139.txt -Pn -n --open -p139 --script=smb-check-vulns --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
     f_CleanUp
     egrep -v '(SERVICE|netbios)' tmp4 > tmp5
     sed '1N;N;/\(.*\n\)\{2\}.*VULNERABLE/P;$d;D' tmp5
     sed '/^$/d' tmp5 > tmp6
     grep -v '|' tmp6 > $name/script-ms08-067.txt
fi

if [ -f $name/143.txt ]; then
	echo "     IMAP"
	nmap -iL $name/143.txt -Pn -n --open -p143 --script=imap-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-143.txt
fi

if [ -f $name/161.txt ]; then
	echo "     SNMP"
	nmap -iL $name/161.txt -Pn -n -sU --open -p161 --script=snmp-hh3c-logins,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-161.txt
fi

if [ -f $name/389.txt ]; then
	echo "     LDAP"
	nmap -iL $name/389.txt -Pn -n --open -p389 --script=ldap-rootdse --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-389.txt
fi

if [ -f $name/445.txt ]; then
	echo "     SMB"
	nmap -iL $name/445.txt -Pn -n --open -p445 --script=msrpc-enum,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,smb-server-stats,smb-system-info,smbv2-enabled,stuxnet-detect --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	sed -i '/^445/{n; /.*/d}' tmp4		# Find lines that start with 445, and delete the following line
	mv tmp4 $name/script-445.txt
fi

if [ -f $name/465.txt ]; then
	echo "     SMTP/S"
	nmap -iL $name/465.txt -Pn -n --open -p465 --script=banner,smtp-commands,smtp-open-relay,smtp-strangeport,smtp-enum-users --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	printf '%s\n' 'g/NOT VULNERABLE/d\' '-d' w | ed -s tmp4
	mv tmp4 $name/script-465.txt
fi

if [ -f $name/500.txt ]; then
	echo "     Ike"
	nmap -iL $name/500.txt -Pn -n -sS -sU --open -p500 --script=ike-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-500.txt
fi

if [ -f $name/db2.txt ]; then
	echo "     DB2"
	nmap -iL $name/db2.txt -Pn -n -sS -sU --open -p523 --script=db2-das-info,db2-discover --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-523.txt
fi

if [ -f $name/524.txt ]; then
	echo "     Novell NetWare Core Protocol"
	nmap -iL $name/524.txt -Pn -n --open -p524 --script=ncp-enum-users,ncp-serverinfo --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-524.txt
fi

if [ -f $name/548.txt ]; then
	echo "     AFP"
	nmap -iL $name/548.txt -Pn -n --open -p548 --script=afp-ls,afp-path-vuln,afp-serverinfo,afp-showmount --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-548.txt
fi

if [ -f $name/554.txt ]; then
	echo "     RTSP"
	nmap -iL $name/554.txt -Pn -n --open -p554 --script=rtsp-methods --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-554.txt
fi

if [ -f $name/631.txt ]; then
	echo "     CUPS"
	nmap -iL $name/631.txt -Pn -n --open -p631 --script=cups-info,cups-queue-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-631.txt
fi

if [ -f $name/873.txt ]; then
	echo "     rsync"
	nmap -iL $name/873.txt -Pn -n --open -p873 --script=rsync-list-modules --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-873.txt
fi

if [ -f $name/993.txt ]; then
	echo "     IMAP/S"
	nmap -iL $name/993.txt -Pn -n --open -p993 --script=banner,sslv2,imap-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-993.txt
fi

if [ -f $name/995.txt ]; then
	echo "     POP3/S"
	nmap -iL $name/995.txt -Pn -n --open -p995 --script=banner,sslv2,pop3-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-995.txt
fi

if [ -f $name/1050.txt ]; then
	echo "     COBRA"
	nmap -iL $name/1050.txt -Pn -n --open -p1050 --script=giop-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-1050.txt
fi

if [ -f $name/1080.txt ]; then
	echo "     SOCKS"
	nmap -iL $name/1080.txt -Pn -n --open -p1080 --script=socks-auth-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-1080.txt
fi

if [ -f $name/1099.txt ]; then
	echo "     RMI Registry"
	nmap -iL $name/1099.txt -Pn -n --open -p1099 --script=rmi-dumpregistry --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-1099.txt
fi

if [ -f $name/1344.txt ]; then
	echo "     ICAP"
	nmap -iL $name/1344.txt -Pn -n --open -p1344 --script=icap-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-1344.txt
fi

if [ -f $name/1352.txt ]; then
	echo "     Lotus Domino"
	nmap -iL $name/1352.txt -Pn -n --open -p1352 --script=domino-enum-users --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-1352.txt
fi

if [ -f $name/1433.txt ]; then
	echo "     MS-SQL"
	nmap -iL $name/1433.txt -Pn -n --open -p1433 --script=ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-1433.txt
fi

if [ -f $name/1434.txt ]; then
	echo "     MS-SQL UDP"
	nmap -iL $name/1434.txt -Pn -n -sU --open -p1434 --script=ms-sql-dac --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-1434.txt
fi

if [ -f $name/1521.txt ]; then
	echo "     Oracle"
	nmap -iL $name/1521.txt -Pn -n --open -p1521 --script=oracle-sid-brute --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-1521.txt
fi

if [ -f $name/1604.txt ]; then
	echo "     Citrix"
	nmap -iL $name/1604.txt -Pn -n -sU --open -p1604 --script=citrix-enum-apps,citrix-enum-servers --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-1604.txt
fi

if [ -f $name/1723.txt ]; then
	echo "     PPTP"
	nmap -iL $name/1723.txt -Pn -n --open -p1723 --script=pptp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-1723.txt
fi

if [ -f $name/2202.txt ]; then
	echo "     ACARS"
	nmap -iL $name/2202.txt -Pn -n --open -p2202 --script=acarsd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-2202.txt
fi

if [ -f $name/2628.txt ]; then
	echo "     DICT"
	nmap -iL $name/2628.txt -Pn -n --open -p2628 --script=dict-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-2628.txt
fi

if [ -f $name/2947.txt ]; then
	echo "     GPS"
	nmap -iL $name/2947.txt -Pn -n --open -p2947 --script=gpsd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-2947.txt
fi

if [ -f $name/3031.txt ]; then
	echo "     Apple Remote Event"
	nmap -iL $name/3031.txt -Pn -n --open -p3031 --script=eppc-enum-processes --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-3031.txt
fi

if [ -f $name/3260.txt ]; then
	echo "     iSCSI"
	nmap -iL $name/3260.txt -Pn -n --open -p3260 --script=iscsi-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-3260.txt
fi

if [ -f $name/3306.txt ]; then
	echo "     MySQL"
	nmap -iL $name/3306.txt -Pn -n --open -p3306 --script=mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-3306.txt
fi

if [ -f $name/3389.txt ]; then
	echo "     Remote Desktop"
	nmap -iL $name/3389.txt -Pn -n --open -p3389 --script=rdp-vuln-ms12-020,rdp-enum-encryption --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	egrep -v '(attackers|Description|Disclosure|http|References|Risk factor)' tmp4 > $name/script-3389.txt
fi

if [ -f $name/3478.txt ]; then
	echo "     STUN"
	nmap -iL $name/3478.txt -Pn -n -sU --open -p3478 --script=stun-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-3478.txt
fi

if [ -f $name/3632.txt ]; then
	echo "     Distributed Compiler Daemon"
	nmap -iL $name/3632.txt -Pn -n --open -p3632 --script=distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'" --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
     egrep -v '(IDs|Risk factor|Description|Allows|earlier|Disclosure|Extra|References|http)' tmp4 > $name/script-3632.txt
fi

if [ -f $name/4369.txt ]; then
	echo "     Erlang Port Mapper"
	nmap -iL $name/4369.txt -Pn -n --open -p4369 --script=epmd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-4369.txt
fi

if [ -f $name/5019.txt ]; then
	echo "     Versant"
	nmap -iL $name/5019.txt -Pn -n --open -p5019 --script=versant-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-5019.txt
fi

if [ -f $name/5353.txt ]; then
	echo "     DNS Service Discovery"
	nmap -iL $name/5353.txt -Pn -n -sU --open -p5353 --script=dns-service-discovery --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-5353.txt
fi

if [ -f $name/5666.txt ]; then
	echo "     Nagios"
	nmap -iL $name/5666.txt -Pn -n --open -p5666 --script=nrpe-enum --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-5666.txt
fi

if [ -f $name/5672.txt ]; then
	echo "     AMQP"
	nmap -iL $name/5672.txt -Pn -n --open -p5672 --script=amqp-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-5672.txt
fi

if [ -f $name/5850.txt ]; then
	echo "     OpenLookup"
	nmap -iL $name/5850.txt -Pn -n --open -p5850 --script=openlookup-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-5850.txt
fi

if [ -f $name/5900.txt ]; then
	echo "     VNC"
	nmap -iL $name/5900.txt -Pn -n --open -p5900 --script=realvnc-auth-bypass,vnc-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-5900.txt
fi

if [ -f $name/5984.txt ]; then
	echo "     CouchDB"
	nmap -iL $name/5984.txt -Pn -n --open -p5984 --script=couchdb-databases,couchdb-stats --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-5984.txt
fi

if [ -f $name/x11.txt ]; then
	echo "     X11"
	nmap -iL $name/x11.txt -Pn -n --open -p6000-6005 --script=x11-access --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-x11.txt
fi

if [ -f $name/6379.txt ]; then
	echo "     Redis"
	nmap -iL $name/6379.txt -Pn -n --open -p6379 --script=redis-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-6379.txt
fi

if [ -f $name/6481.txt ]; then
	echo "     Sun Service Tags"
	nmap -iL $name/6481.txt -Pn -n -sU --open -p6481 --script=servicetags --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-6481.txt
fi

if [ -f $name/6666.txt ]; then
	echo "     Voldemort"
	nmap -iL $name/6666.txt -Pn -n --open -p6666 --script=voldemort-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-6666.txt
fi

if [ -f $name/7210.txt ]; then
	echo "     Max DB"
	nmap -iL $name/7210.txt -Pn -n --open -p7210 --script=maxdb-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-7210.txt
fi

if [ -f $name/7634.txt ]; then
	echo "     Hard Disk Info"
	nmap -iL $name/7634.txt -Pn -n --open -p7634 --script=hddtemp-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-7634.txt
fi

#if [ -f $name/8009.txt ]; then
#	echo "     AJP"
#	nmap -iL $name/8009.txt -Pn -n --open -p8009 --script=ajp-methods,ajp-request --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
#	f_CleanUp
#	mv tmp4 $name/script-8009.txt
#fi

if [ -f $name/8081.txt ]; then
	echo "     McAfee ePO"
	nmap -iL $name/8081.txt -Pn -n --open -p8081 --script=mcafee-epo-agent --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-8081.txt
fi

if [ -f $name/8091.txt ]; then
	echo "     CouchBase Web Administration"
	nmap -iL $name/8091.txt -Pn -n --open -p8091 --script=membase-http-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-8091.txt
fi

if [ -f $name/bitcoin.txt ]; then
	echo "     Bitcoin"
	nmap -iL $name/bitcoin.txt -Pn -n --open -p8332,8333 --script=bitcoin-getaddr,bitcoin-info,bitcoinrpc-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-bitcoin.txt
fi

if [ -f $name/9100.txt ]; then
	echo "     Lexmark"
	nmap -iL $name/9100.txt -Pn -n --open -p9100 --script=lexmark-config --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-9100.txt
fi

if [ -f $name/9160.txt ]; then
	echo "     Cassandra"
	nmap -iL $name/9160.txt -Pn -n --open -p9160 --script=cassandra-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-9160.txt
fi

if [ -f $name/9999.txt ]; then
	echo "     Java Debug Wire Protocol"
	nmap -iL $name/9999.txt -Pn -n --open -p9999 --script=jdwp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-9999.txt
fi

if [ -f $name/10000.txt ]; then
	echo "     Network Data Management"
	nmap -iL $name/10000.txt -Pn -n --open -p10000 --script=ndmp-fs-info,ndmp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-10000.txt
fi

if [ -f $name/11211.txt ]; then
	echo "     Memory Object Caching"
	nmap -iL $name/11211.txt -Pn -n --open -p11211 --script=memcached-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-11211.txt
fi

if [ -f $name/12345.txt ]; then
	echo "     NetBus"
	nmap -iL $name/12345.txt -Pn -n --open -p12345 --script=netbus-auth-bypass,netbus-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-12345.txt
fi

if [ -f $name/17185.txt ]; then
	echo "     VxWorks"
	nmap -iL $name/17185.txt -Pn -n -sU --open -p17185 --script=wdb-version --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-17185.txt
fi

if [ -f $name/19150.txt ]; then
	echo "     GKRellM"
	nmap -iL $name/19150.txt -Pn -n --open -p19150 --script=gkrellm-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-19150.txt
fi

if [ -f $name/27017.txt ]; then
	echo "     MongoDB"
	nmap -iL $name/27017.txt -Pn -n --open -p27017 --script=mongodb-databases,mongodb-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-27017.txt
fi

if [ -f $name/31337.txt ]; then
	echo "     BackOrifice"
	nmap -iL $name/31337.txt -Pn -n -sU --open -p31337 --script=backorifice-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-31337.txt
fi

if [ -f $name/35871.txt ]; then
	echo "     Flume"
	nmap -iL $name/35871.txt -Pn -n --open -p35871 --script=flume-master-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-35871.txt
fi

if [ -f $name/50000.txt ]; then
	echo "     DRDA"
	nmap -iL $name/50000.txt -Pn -n --open -p50000 --script=drda-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-50000.txt
fi

if [ -f $name/hadoop.txt ]; then
	echo "     Hadoop"
	nmap -iL $name/hadoop.txt -Pn -n --open -p50030,50060,50070,50075,50090 --script=hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-hadoop.txt
fi

if [ -f $name/apache-hbase.txt ]; then
	echo "     Apache HBase"
	nmap -iL $name/apache-hbase.txt -Pn -n --open -p60010,60030 --script=hbase-master-info,hbase-region-info --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	mv tmp4 $name/script-apache-hbase.txt
fi

if [ -f $name/web.txt ]; then
	echo "     Web"
	nmap -iL $name/web.txt -Pn -n --open -p80,443,8000,8080,8443 --script=http-methods --host-timeout 5m --min-hostgroup 100 -g $sourceport > tmp
	f_CleanUp
	egrep -v '(html|No Allow|Potentially)' tmp4 > $name/script-web.txt
fi

rm tmp*

for x in $name/./script*; do
     if grep '|' $x > /dev/null 2>&1; then
          echo > /dev/null 2>&1
     else
          rm $x > /dev/null 2>&1
     fi
done
}

##############################################################################################################

f_Metasploit(){
echo
echo $break
echo
echo -ne "\e[1;33mRun matching Metasploit auxilaries? (y/N) \e[0m"
read msf

if [ -z $msf ]; then
     msf="n"
fi

msf="$(echo ${msf} | tr 'A-Z' 'a-z')"

if [ $msf == "y" ]; then
     f_RunMSF
else
     f_Report
fi
}

##############################################################################################################

f_RunMSF(){
echo
echo -e "\e[1;34mStarting Metasploit, this takes about 15 sec.\e[0m"

echo workspace -a $name > $name/master.rc

# If the file for the corresponding port doesn't exist, skip
if [ -f $name/21.txt ]; then
     echo "     FTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/21.txt/g" /opt/scripts/resource/ftp.rc
     cat resource/ftp.rc >> $name/master.rc
fi

if [ -f $name/22.txt ]; then
     echo "     SSH"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/22.txt/g" /opt/scripts/resource/ssh.rc
     cat resource/ssh.rc >> $name/master.rc
fi

if [ -f $name/23.txt ]; then
     echo "     Telnet"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/23.txt/g" /opt/scripts/resource/telnet.rc
     cat resource/telnet.rc >> $name/master.rc
fi

if [ -f $name/25.txt ]; then
     echo "     SMTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/25.txt/g" /opt/scripts/resource/smtp.rc
     cat resource/smtp.rc >> $name/master.rc
fi

if [ -f $name/69.txt ]; then
     echo "     TFTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/69.txt/g" /opt/scripts/resource/tftp.rc
     cat resource/tftp.rc >> $name/master.rc
fi

if [ -f $name/79.txt ]; then
     echo "     Finger"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/79.txt/g" /opt/scripts/resource/finger.rc
     cat resource/finger.rc >> $name/master.rc
fi

if [ -f $name/110.txt ]; then
     echo "     POP3"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/110.txt/g" /opt/scripts/resource/pop3.rc
     cat resource/pop3.rc >> $name/master.rc
fi

if [ -f $name/111.txt ]; then
     echo "     NFS"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/111.txt/g" /opt/scripts/resource/nfs.rc
     cat resource/nfs.rc >> $name/master.rc
fi

if [ -f $name/123.txt ]; then
     echo "     NTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/123.txt/g" /opt/scripts/resource/ntp.rc
     cat resource/ntp.rc >> $name/master.rc
fi

if [ -f $name/137.txt ]; then
     echo "     NetBIOS"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/137.txt/g" /opt/scripts/resource/netbios.rc
     cat resource/netbios.rc >> $name/master.rc
fi

if [ -f $name/143.txt ]; then
     echo "     IMAP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/143.txt/g" /opt/scripts/resource/imap.rc
     cat resource/imap.rc >> $name/master.rc
fi

if [ -f $name/161.txt ]; then
     echo "     SNMP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/161.txt/g" /opt/scripts/resource/snmp.rc
     cat resource/snmp.rc >> $name/master.rc
fi

if [ -f $name/445.txt ]; then
     echo "     SMB"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/445.txt/g" /opt/scripts/resource/smb.rc
     cat resource/smb.rc >> $name/master.rc
fi

if [ -f $name/465.txt ]; then
     echo "     SMTP/S"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/465.txt/g" /opt/scripts/resource/smtp-s.rc
     cat resource/smtp-s.rc >> $name/master.rc
fi

if [ -f $name/523.txt ]; then
     echo "     db2"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/523.txt/g" /opt/scripts/resource/db2.rc
     cat resource/db2.rc >> $name/master.rc
fi

if [ -f $name/548.txt ]; then
     echo "     AFP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/548.txt/g" /opt/scripts/resource/afp.rc
     cat resource/afp.rc >> $name/master.rc
fi

if [ -f $name/1099.txt ]; then
     echo "     RMI Registery"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1099.txt/g" /opt/scripts/resource/rmi.rc
     cat resource/rmi.rc >> $name/master.rc
fi

if [ -f $name/1158.txt ]; then
     echo "     Oracle"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1158.txt/g" /opt/scripts/resource/oracle.rc
     cat resource/oracle.rc >> $name/master.rc
fi

if [ -f $name/1433.txt ]; then
     echo "     MS-SQL"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1433.txt/g" /opt/scripts/resource/mssql.rc
     cat resource/mssql.rc >> $name/master.rc
fi

if [ -f $name/1521.txt ]; then
     echo "     Oracle 2"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1521.txt/g" /opt/scripts/resource/oracle2.rc
     cat resource/oracle2.rc >> $name/master.rc
fi

if [ -f $name/1604.txt ]; then
     echo "     Citrix"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1604.txt/g" /opt/scripts/resource/citrix.rc
     cat resource/citrix.rc >> $name/master.rc
fi

if [ -f $name/1720.txt ]; then
     echo "     H323"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/1720.txt/g" /opt/scripts/resource/h323.rc
     cat resource/h323.rc >> $name/master.rc
fi

if [ -f $name/3306.txt ]; then
     echo "     MySQL"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/3306.txt/g" /opt/scripts/resource/mysql.rc
     cat resource/mysql.rc >> $name/master.rc
fi

if [ -f $name/5432.txt ]; then
     echo "     Postgres"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/5432.txt/g" /opt/scripts/resource/postgres.rc
     cat resource/postgres.rc >> $name/master.rc
fi

if [ -f $name/5900.txt ]; then
     echo "     VNC"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/5900.txt/g" /opt/scripts/resource/vnc.rc
     cat resource/vnc.rc >> $name/master.rc
fi

if [ -f $name/x11.txt ]; then
     echo "     x11"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/x11.txt/g" /opt/scripts/resource/x11.rc
     cat resource/x11.rc >> $name/master.rc
fi

if [ -f $name/7777.txt ]; then
     echo "     Energizer Duo"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/7777.txt/g" /opt/scripts/resource/energizer-duo.rc
     cat resource/energizer-duo.rc >> $name/master.rc
fi

if [ -f $name/8080.txt ]; then
     echo "     Tomcat"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/8080.txt/g" /opt/scripts/resource/tomcat.rc
     cat resource/tomcat.rc >> $name/master.rc
fi

if [ -f $name/8222.txt ]; then
     echo "     VMware"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/8222.txt/g" /opt/scripts/resource/vmware.rc
     cat resource/vmware.rc >> $name/master.rc
fi

if [ -f $name/8400.txt ]; then
     echo "     Adobe"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/8400.txt/g" /opt/scripts/resource/adobe.rc
     cat resource/adobe.rc >> $name/master.rc
fi

if [ -f $name/9999.txt ]; then
     echo "     Telnet 2"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/9999.txt/g" /opt/scripts/resource/telnet2.rc
     cat resource/telnet2.rc >> $name/master.rc
fi

if [ -f $name/17185.txt ]; then
     echo "     VxWorks"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/17185.txt/g" /opt/scripts/resource/vxworks.rc
     cat resource/vxworks.rc >> $name/master.rc
fi

if [ -f $name/50000.txt ]; then
     echo "     db2 version"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/50000.txt/g" /opt/scripts/resource/db2-version.rc
     cat resource/db2-version.rc >> $name/master.rc
fi

if [ -f $name/web.txt ]; then
     echo "     HTTP"
     sed -i "s/^setg RHOSTS.*/setg RHOSTS file:\/opt\/scripts\/$name\/web.txt/g" /opt/scripts/resource/http-short.rc
     cat resource/http-short.rc >> $name/master.rc
fi

# services -c port,proto,name,info -o /root/test.csv
# hosts -c address,name,os_name,os_flavor,os_sp -o /root/test2.csv

echo db_export -f xml -a $name/metasploit.xml >> $name/master.rc
echo db_import $name/nmap.xml >> $name/master.rc
echo exit >> $name/master.rc

x=$(wc -l $name/master.rc | cut -d ' ' -f1)

if [ $x -eq 3 ]; then
     rm $name/master.rc
else
     msfconsole -r /opt/scripts/$name/master.rc
     rm $name/master.rc
fi

f_Report
}

##############################################################################################################

f_Report(){
END=$(date +%r\ %Z)
filename=$name/report.txt
host=$(wc -l $name/hosts.txt | cut -d ' ' -f1)

echo "Discover Report" > $filename
echo "$name" >> $filename
date +%A" - "%B" "%d", "%Y >> $filename
echo >> $filename
echo "Start time - $START" >> $filename
echo "Finish time - $END" >> $filename
echo "Scanner IP - $ip" >> $filename
nmap -V | grep 'version' | cut -d ' ' -f1-3 >> $filename
echo >> $filename
echo $break >> $filename
echo >> $filename

if [ -f $name/script-ms08-067.txt ]; then
     echo "May be vulnerable to MS08-067." >> $filename
     echo >> $filename
     cat $name/script-ms08-067.txt >> $filename
     echo >> $filename
     echo $break >> $filename
     echo >> $filename
fi

if [ $host -eq 1 ]; then
     echo "1 host discovered." >> $filename
     echo >> $filename
     echo $break >> $filename
     echo >> $filename
     cat $name/nmap.txt >> $filename
     echo $break >> $filename
     echo $break >> $filename
     echo >> $filename
     echo "Nmap Scripts" >> $filename

     SCRIPTS="script-13 script-21 script-22 script-23 script-25 script-53 script-67 script-70 script-79 script-110 script-111 script-123 script-137 script-143 script-161 script-389 script-445 script-465 script-500 script-523 script-524 script-548 script-554 script-631 script-873 script-993 script-995 script-1050 script-1080 script-1099 script-1344 script-1352 script-1433 script-1434 script-1521 script-1604 script-1723 script-2202 script-2628 script-2947 script-3031 script-3260 script-3306 script-3389 script-3478 script-3632 script-4369 script-5019 script-5353 script-5666 script-5672 script-5850 script-5900 script-5984 script-x11 script-6379 script-6481 script-6666 script-7210 script-7634 script-8009 script-8081 script-8091 script-bitcoin script-9100 script-9160 script-9999 script-10000 script-11211 script-12345 script-17185 script-19150 script-27017 script-31337 script-35871 script-50000 script-hadoop script-apache-hbase script-web"

     for i in $SCRIPTS; do
          if [ -f $name/"$i.txt" ]; then
               cat $name/"$i.txt" >> $filename
               echo $break >> $filename
          fi
     done

     mv $name /$user/

     START=0
     END=0

     echo
	echo $break
	echo
     echo "***Scan complete.***"
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/$name/report.txt
     echo
     echo
     exit
fi

echo "Hosts Discovered ($host)" >> $filename
echo >> $filename
cat $name/hosts.txt >> $filename
echo >> $filename

if [ ! -s $name/ports.txt ]; then
     echo
     echo $break
     echo
     echo "***Scan complete.***"
     echo
     echo -e "\e[1;33mNo hosts found with open ports.\e[0m"
     echo
     echo
     exit
else
     ports=$(wc -l $name/ports.txt | cut -d ' ' -f1)
fi

echo $break >> $filename
echo >> $filename
echo "Open Ports ($ports)" >> $filename
echo >> $filename

if [ -s $name/ports-tcp.txt ]; then
     echo "TCP Ports" >> $filename
     cat $name/ports-tcp.txt >> $filename
     echo >> $filename
fi

if [ -s $name/ports-udp.txt ]; then
     echo "UDP Ports" >> $filename
     cat $name/ports-udp.txt >> $filename
     echo >> $filename
fi

echo $break >> $filename

if [ -f $name/banners.txt ]; then
     banners=$(wc -l $name/banners.txt | cut -d ' ' -f1)
     echo >> $filename
     echo "Banners ($banners)" >> $filename
     echo >> $filename
     cat $name/banners.txt >> $filename
     echo >> $filename
     echo $break >> $filename
fi

echo >> $filename
echo "High Value Hosts by Port" >> $filename
echo >> $filename

HVPORTS="13 21 22 23 25 53 67 69 70 79 80 110 111 123 137 139 143 161 389 443 445 465 500 523 524 548 554 631 873 993 995 1050 1080 1099 1158 1344 1352 1433 1434 1521 1604 1720 1723 2202 2628 2947 3031 3260 3306 3389 3478 3632 4369 5019 5353 5432 5666 5672 5850 5900 5984 6000 6001 6002 6003 6004 6005 6379 6481 6666 7210 7634 7777 8000 8009 8080 8081 8091 8222 8332 8333 8400 8443 9100 9160 9999 10000 11211 12345 17185 19150 27017 31337 35871 50000 50030 50060 50070 50075 50090 60010 60030"

for i in $HVPORTS; do
     if [ -f $name/$i.txt ]; then
          echo "Port $i" >> $filename
          cat $name/$i.txt >> $filename
          echo >> $filename
     fi
done

echo $break >> $filename
echo >> $filename
cat $name/nmap.txt >> $filename
echo $break >> $filename
echo $break >> $filename
echo >> $filename
echo "Nmap Scripts" >> $filename

SCRIPTS="script-13 script-21 script-22 script-23 script-25 script-53 script-67 script-70 script-79 script-110 script-111 script-123 script-137 script-143 script-161 script-389 script-445 script-465 script-500 script-523 script-524 script-548 script-554 script-631 script-873 script-993 script-995 script-1050 script-1080 script-1099 script-1344 script-1352 script-1433 script-1434 script-1521 script-1604 script-1723 script-2202 script-2628 script-2947 script-3031 script-3260 script-3306 script-3389 script-3478 script-3632 script-4369 script-5019 script-5353 script-5666 script-5672 script-5850 script-5900 script-5984 script-x11 script-6379 script-6481 script-6666 script-7210 script-7634 script-8009 script-8081 script-8091 script-bitcoin script-9100 script-9160 script-9999 script-10000 script-11211 script-12345 script-17185 script-19150 script-27017 script-31337 script-35871 script-50000 script-hadoop script-apache-hbase script-web"

for i in $SCRIPTS; do
     if [ -f $name/"$i.txt" ]; then
          cat $name/"$i.txt" >> $filename
          echo $break >> $filename
     fi
done

echo >> $filename

mv $name /$user/

START=0
END=0

echo
echo $break
echo
echo "***Scan complete.***"
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/$name/report.txt
echo
echo
exit
}

##############################################################################################################

f_MultiTabsFirefox(){
f_RunLocally
clear
f_Banner

echo -e "\e[1;34mOpen multiple tabs in Firefox with:\e[0m"
echo
echo "1.  List containing IPs and/or URLs."
echo "2.  Directories from a domain's robot.txt."
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     echo
     echo -n "Enter the location of your list: "
     read location

     # Check for no answer
     if [ -z $location ]; then
          f_Error
     fi

     # Check for wrong answer
     if [ ! -f $location ]; then
          f_Error
     fi

     echo -n "Port (default 80): "
     read port

     # Check if port number is actually a number
     echo "$port" | grep -E "^[0-9]+$" > /dev/null
     isnum=$?

     if [ $isnum -ne 0 ] && [ ${#port} -gt 0 ]; then
          f_Error
     fi

     if [ ${#port} -eq 0 ]; then
          port=80
     fi

     if [ $port -lt 1 ] || [ $port -gt 65535 ]; then
          f_Error
     fi

     firefox &
     sleep 2

     if [ $port -eq 21 ]; then
          for i in $(cat $location); do
               firefox -new-tab ftp://$i &
               sleep 1
          done
     elif [ $port -eq 80 ]; then
          for i in $(cat $location); do
               firefox -new-tab $i &
               sleep 1
          done
     elif [ $port -eq 443 ]; then
          for i in $(cat $location); do
               firefox -new-tab https://$i &
               sleep 1
          done
     else
          for i in $(cat $location); do
               firefox -new-tab $i:$port &
               sleep 1
          done
     fi
     ;;

     2)
     echo
     echo $break
     echo
     echo "Usage: target.com or target-IP"
     echo
     echo -n "Domain: "
     read domain

     # Check for no answer
     if [ -z $domain ]; then
          f_Error
     fi

     wget -q $domain/robots.txt

     grep 'Disallow' robots.txt | awk '{print $2}' > /$user/$domain-robots.txt
     rm robots.txt

     firefox &
     sleep 2

     for i in $(cat /$user/$domain-robots.txt); do
          firefox -new-tab $domain$i &
          sleep 1
     done

     echo
     echo $break
     echo
     echo "***Scan complete.***"
     echo
     printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/$domain-robots.txt
     echo
     echo
     exit
     ;;

     3) f_Main;;
     *) f_Error;;
esac
}

##############################################################################################################

f_Nikto(){
f_RunLocally
clear
f_Banner

echo -e "\e[1;34mRun multiple instances of Nikto in parallel against a list of IP addresses.\e[0m"
echo -e "\e[1;34mAs scans complete, the tabs will close.\e[0m"
echo
echo "1.  List of IPs."
echo "2.  List of IP:port."
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     echo
     echo -n "Enter the location of your list: "
     read location

     # Check for no answer
     if [ -z $location ]; then
          f_Error
     fi

     # Check for wrong answer
     if [ ! -f $location ]; then
          f_Error
     fi

     echo
     echo -n "Port (default 80): "
     read port
     echo

     # Check if port number is actually a number
     echo "$port" | grep -E "^[0-9]+$" > /dev/null
     isnum=$?

     if [ $isnum -ne 0 ] && [ ${#port} -gt 0 ]; then
          f_Error
     fi

     if [ ${#port} -eq 0 ]; then
          port=80
     fi

     if [ $port -lt 1 ] || [ $port -gt 65535 ]; then
          f_Error
     fi

     mkdir /$user/nikto

     while read -r line; do
          xdotool key ctrl+shift+t
          sleep 1
          xdotool type "cd /pentest/web/nikto/program/ && ./nikto.pl -h $line -port $port -Format htm --output /$user/nikto/$line.htm ; exit"
          xdotool key Return
     done < "$location"
     ;;

     2)
     echo
     echo -n "Enter the location of your list: "
     read location

     # Check for no answer
     if [ -z $location ]; then
          f_Error
     fi

     # Check for wrong answer
     if [ ! -f $location ]; then
          f_Error
     fi

     mkdir /$user/nikto

     while IFS=: read -r host port; do
          xdotool key ctrl+shift+t
          sleep 1
          xdotool type "cd /pentest/web/nikto/program/ && ./nikto.pl -h $host -port $port -Format htm --output /root/nikto/$host-$port.htm ; exit"
          xdotool key Return
     done < "$location"
     ;;

     3) f_Main;;
     *) f_Error;;
esac

echo
echo $break
echo
echo "***Scan complete.***"
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/nikto/
echo
echo
exit
}

##############################################################################################################
# Jason
# Need a better way to see if a host is live and has an SSL port open. Try using nmap -p 443.
# Need a better way to locate hosts running SSL on alternate ports. Try using the nmap.grep file.

f_SSLcheck(){
clear
f_Banner

echo -e "\e[1;34mCheck for SSL certificate issues.\e[0m"
echo 
echo -n "Enter the location of your list: "
read location

# Check for no answer (an empty response)
if [ -z $location ]; then
     f_Error
fi

# Check for wrong answer
if [ ! -f $location ]; then
     f_Error
fi

date2stamp(){
date --utc --date "$1" +%s
}

stamp2date(){
date --utc --date "1970-01-01 $1 sec" "+%Y-%m-%d %T"
}

dateDiff(){
case $1 in
     -s) sec=1; shift;;
     -m) sec=60; shift;;
     -h) sec=3600; shift;;
     -d) sec=86400; shift;;
     *)  sec=86400;;
esac

dte1=$(date2stamp $1)
dte2=$(date2stamp $2)
diffSec=$((dte2-dte1))

if ((diffSec < 0)); then
     abs=-1
else
     abs=1
fi

echo $((diffSec/sec*abs))
}

monthConv(){
if [ "$1" == "Jan" ]; then monthnum="01"; fi
if [ "$1" == "Feb" ]; then monthnum="02"; fi
if [ "$1" == "Mar" ]; then monthnum="03"; fi
if [ "$1" == "Apr" ]; then monthnum="04"; fi
if [ "$1" == "May" ]; then monthnum="05"; fi
if [ "$1" == "Jun" ]; then monthnum="06"; fi
if [ "$1" == "Jul" ]; then monthnum="07"; fi
if [ "$1" == "Aug" ]; then monthnum="08"; fi
if [ "$1" == "Sep" ]; then monthnum="09"; fi
if [ "$1" == "Oct" ]; then monthnum="10"; fi
if [ "$1" == "Nov" ]; then monthnum="11"; fi
if [ "$1" == "Dec" ]; then monthnum="12"; fi
}

# Number of hosts
number=$(wc -l $location | cut -d ' ' -f1)
N=0

echo
echo "Scanning $number IP addresses."
echo

echo > tmp-report
echo >> tmp-report
echo "SSL Report" >> tmp-report
reportdate=$(date +%A" - "%B" "%d", "%Y)
echo $reportdate >> tmp-report
echo sslscan $(sslscan | grep 'Version' | awk '{print $2}') >> tmp-report
echo >> tmp-report
echo $break >> tmp-report
echo >> tmp-report

while read -r line; do

     # Initialize ssl_$line.txt file
     echo "$line" > ssl_$line.txt
     N=$((N+1))
     sslscan --no-failed $line > ssltmp_$line & pid=$!

     # echo "pid = $pid"  # debug statement
     echo -n "$line  [$N/$number]  "; sleep 40
     echo >> ssl_$line.txt

     if [ -s ssltmp_$line ]; then
          ERRORCHECK=$(cat ssltmp_$line | grep 'ERROR:')
          if [[ ! $ERRORCHECK ]]; then

               ISSUER=$(cat ssltmp_$line | grep 'Issuer:')
               if [[ $ISSUER ]]; then
                    echo [INFO] Certificate Issuer >> ssl_$line.txt
                    cat ssltmp_$line | grep 'Issuer:' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               else
                    echo [INFO] Certificate Issuer >> ssl_$line.txt
                    echo "Issuer information not available for this certificate. Look into this!" >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               SUBJECT=$(cat ssltmp_$line | grep 'Subject:')
               if [[ $SUBJECT ]]; then
                    echo [INFO] Certificate Subject >> ssl_$line.txt
                    cat ssltmp_$line | grep 'Subject:' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               else
                    echo [INFO] Certificate Subject >> ssl_$line.txt
                    echo "Certificate subject information not available. Look into this!" >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               DNS=$(cat ssltmp_$line | grep 'DNS:')
               if [[ $DNS ]]; then
                    echo [INFO] Certificate DNS Names >> ssl_$line.txt
                    cat ssltmp_$line | grep 'DNS:' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               A=$(cat ssltmp_$line | grep -i 'MD5WithRSAEncryption')
               if [[ $A ]]; then
                    echo [*] MD5-based Signature in TLS/SSL Server X.509 Certificate >> ssl_$line.txt
                    cat ssltmp_$line | grep -i 'MD5WithRSAEncryption' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               B=$(cat ssltmp_$line | grep 'NULL')
               if [[ $B ]]; then
                    echo [*] NULL Ciphers >> ssl_$line.txt
                    cat ssltmp_$line | grep 'NULL' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               C=$(cat ssltmp_$line | grep 'SSLv2')
               if [[ $C ]]; then
                    echo [*] TLS/SSL Server Supports SSLv2 >> ssl_$line.txt
                    cat ssltmp_$line | grep 'SSLv2' > ssltmp2_$line
                    sed '/^    SSL/d' ssltmp2_$line >> ssl_$line.txt
                    echo >> ssl_$line.txt
                    rm ssltmp2_$line
               fi

               D=$(cat ssltmp_$line | grep ' 40 bits')
               D2=$(cat ssltmp_$line | grep ' 56 bits')

               if [[ $D || $D2 ]]; then
                    echo [*] TLS/SSL Server Supports Weak Cipher Algorithms >> ssl_$line.txt
                    cat ssltmp_$line | grep ' 40 bits' >> ssl_$line.txt
                    cat ssltmp_$line | grep ' 56 bits' >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               datenow=$(date +%F)
               # echo datenow=$datenow
               datenowstamp=$(date2stamp "$datenow")
               # echo datenowstamp=$datenowstamp
               monthConv $(grep "Not valid after:" ssltmp_$line | awk -F" " {'print $4'})
               # echo monthnum=$monthnum
               expyear=$(grep "Not valid after:" ssltmp_$line | awk -F" " {'print $7'})
               # echo expyear=$expyear
               expday=$(grep "Not valid after:" ssltmp_$line | awk -F" " {'print $5'})
               # echo expday=$expday
               expdate=$(echo "$expyear-$monthnum-$expday")
               # echo expdate=$expdate
               expdatestamp=$(date2stamp "$expdate")
               # echo expdatestamp=$expdatestamp
               numdaysdiff=$(dateDiff $datenow $expdate)
               # echo numdaysdiff=$numdaysdiff

               if (($expdatestamp < $datenowstamp)); then
                    echo [*] X.509 Server Certificate is Invalid/Expired >> ssl_$line.txt
                    echo "    Cert Expire Date: $expdate" >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               E=$(cat ssltmp_$line | grep 'Authority Information Access:')
               if [[ ! $E ]]; then
                    echo [*] Self-signed TLS/SSL certificate >> ssl_$line.txt
                    echo >> ssl_$line.txt
               fi

               # re-evaluate the logic of/need for this test
               #F=$(wget --no-check-certificate https://$line -O tmp > /dev/null 2>&1 | sleep 3 | if [ -f tmp ]; then cat tmp | grep 'Unable to locally verify'; fi)
               #if [[ $F ]]; then
               #     echo [*] Untrusted TLS/SSL server X.509 certificate >> ssl_$line.txt
               #     echo >> ssl_$line.txt
               #     rm tmp
               #fi

               echo $break >> ssl_$line.txt
               echo >> ssl_$line.txt
               echo
               # echo "kill $pid process test"
               (sleep 5 && kill -9 $pid 2>/dev/null) &

               # Add current data to tmp-report
               cat ssl_$line.txt >> tmp-report
          else
               echo -e "\e[1;31mCould not open a connection.\e[0m"
               echo $ERRORCHECK >> ssl_$line.txt
               echo >> ssl_$line.txt
               echo $break >> ssl_$line.txt
               cat ssl_$line.txt >> tmp-report
          fi
     else
          echo -e "\e[1;31mNo response.\e[0m"
          echo "[*] No response." >> ssl_$line.txt
          echo >> ssl_$line.txt
          echo $break >> ssl_$line.txt

          # Add current data to tmp-report
          cat ssl_$line.txt >> tmp-report
     fi
done < "$location"

mv tmp-report /$user/ssl-report.txt
rm ssltmp_* ssl_*.txt 2>/dev/null

echo
echo $break
echo
echo "***Scan complete.***"
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/ssl-report.txt
echo
echo
exit
}

##############################################################################################################

f_Updates(){
# Remove entire script categories
if [ -d /root/nmap-svn ]; then
     ls -l /root/nmap-svn/scripts | awk '{print $8}' | cut -d '.' -f1 | egrep -v '(broadcast|brute|discover|http|ip-|ssl|targets)' > tmp
else
     ls -l /usr/local/share/nmap/scripts | awk '{print $8}' | cut -d '.' -f1 | egrep -v '(broadcast|brute|discover|http|ip-|ssl|targets)' > tmp
fi

# Remove Nmap scripts that take too many arguments, DOS or not relevant
egrep -v '(address-info|ajp-auth|ajp-headers|asn-query|auth-owners|auth-spoof|cccam-version|citrix-enum-apps-xml|citrix-enum-servers-xml|creds-summary|daap-get-library|dns-blacklist|dns-check-zone|dns-client-subnet-scan|dns-fuzz|dns-ip6-arpa-scan|dns-nsec3-enum|dns-nsec-enum|dns-srv-enum|dns-zeustracker|domcon-cmd|duplicates|eap-info|firewalk|firewall-bypass|ftp-libopie|ganglia-info|ftp-vuln-cve2010-4221|hostmap-bfk|hostmap-robtex|iax2-version|informix-query|informix-tables|ipidseq|ipv6-node-info|ipv6-ra-flood|irc-botnet-channels|irc-info|irc-unrealircd-backdoor|isns-info|jdwp-exec|jdwp-info|jdwp-inject|krb5-enum-users|ldap-novell-getpass|ldap-search|llmnr-resolve|metasploit-info|mmouse-exec|ms-sql-config|mrinfo|ms-sql-hasdbaccess|ms-sql-query|ms-sql-tables|ms-sql-xp-cmdshell|mtrace|murmur-version|mysql-audit|mysql-enum|mysql-dump-hashes|mysql-query|mysql-vuln-cve2012-2122|nat-pmp-info|nat-pmp-mapport|netbus-info|omp2-enum-targets|oracle-enum-users|ovs-agent-version|p2p-conficker|path-mtu|pjl-ready-message|quake3-info|quake3-master-getservers|qscan|resolveall|reverse-index|rpc-grind|rpcap-info|samba-vuln-cve-2012-1182|script|sip-enum-users|skypev2-version|smb-flood|smb-ls|smb-print-text|smb-psexec|smb-vuln-ms10-054|smb-vuln-ms10-061|smtp-vuln-cve2010-4344|smtp-vuln-cve2011-1720|smtp-vuln-cve2011-1764|sniffer-detect|snmp-ios-config|socks-open-proxy|sql-injection|ssh-hostkey|ssh2-enum-algos|sshv1|stun-info|tftp-enum|tls-nextprotoneg|traceroute-geolocation|unusual-port|upnp-info|url-snarf|ventrilo-info|vuze-dht-info|whois|xmpp-info)' tmp > tmp-all

grep 'script=' discover.sh | egrep -v '(discover.sh|22.txt|smtp.txt|web.txt)' > tmp
cat tmp | cut -d '=' -f2- | cut -d ' ' -f1 | tr ',' '\n' | egrep -v '(db2-discover|dhcp-discover|dns-service-discovery|membase-http-info|oracle-sid-brute|smb-os-discovery|sslv2)' | sort -u > tmp-used

echo "New Modules" > tmp-updates
echo >> tmp-updates
echo "Nmap scripts" >> tmp-updates
echo "==============================" >> tmp-updates

diff tmp-all tmp-used | egrep '^[<>]' | awk '{print $2}' >> tmp-updates

rm tmp

echo >> tmp-updates
echo "Metasploit auxiliary/scanners" >> tmp-updates
echo "==============================" >> tmp-updates

categories="afp backdoor db2 finger ftp h323 http imap lotus mongodb motorola mssql mysql netbios nfs ntp oracle pcanywhere pop3 postgres rservices scada sip smb smtp snmp ssh telnet tftp upnp vmware vnc vxworks winrm x11"

for i in $categories; do
     ls -l /opt/metasploit/msf3/modules/auxiliary/scanner/$i | awk '{print $8}' | cut -d '.' -f1 >> tmp
done

sed '/^$/d' tmp > tmp2

# Remove brute force and misc
egrep -v '(afp_login|anonymous|axis_login|brute_dirs|cisco_upload_file|crawler|db2_auth|dolibarr_login|ektron_cms400net|enum_delicious|enum_wayback|file_same_name_dir|ftp_login|httpbl_lookup|isqlplus_login|isqlplus_sidbrute|lotus_domino_hashes|lotus_domino_login|lucky_punch|mongodb_login|mysql_hashdump|mysql_login|mysql_schemadump|oracle_hashdump|oracle_login|owa_login|pop3_login|postgres_hashdump|postgres_login|postgres_schemadump|postgres_version|prev_dir_same_name_file|rexec_login|rlogin_login|rsh_login|sid_brute|smb_login|snmp_login|snmp_set|squid_pivot_scanning|ssh_identify_pubkeys|ssh_login|ssh_login_pubkey|sybase_easerver_traversal|telnet_encrypt_overflow|telnet_login|tftpbrute|vcms_login|vhost_scanner|vnc_login|web_vulndb|xdb_sid|xdb_sid_brute|xpath)' tmp2 | sort > tmp-msf-all

cat resource/*.rc | grep 'use' > tmp

# Print from the last /, to the end of the line
sed -e 's:.*/\(.*\):\1:g' tmp > tmp-msf-used

grep -v -f tmp-msf-used tmp-msf-all >> tmp-updates

mv tmp-updates /$user/updates
rm tmp*

echo
echo $break
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/updates
echo
echo
exit
}

##############################################################################################################

f_Listener(){
clear
echo
echo
echo "Starting a Metasploit listener on port 443."
echo "Type - Windows meterpreter reverse TCP."
echo
echo "This takes about 20 seconds."
echo
msfconsole -r /opt/scripts/resource/listener.rc
}

##############################################################################################################

f_Reinstall_nmap(){
clear
echo
echo
echo -e "\e[1;34mRemoving nmap files and folders.\e[0m"

rm -rf /root/.zenmap/
rm -rf /root/nmap-svn/
rm -rf /usr/local/share/ncat/
rm -rf /usr/local/share/nmap/
rm -rf /usr/local/share/zenmap/

rm /usr/local/bin/ncat
rm /usr/local/bin/ndiff
rm /usr/local/bin/nmap
rm /usr/local/bin/nmap-update
rm /usr/local/bin/nmapfe
rm /usr/local/bin/nping
rm /usr/local/bin/uninstall_zenmap
rm /usr/local/bin/xnmap
rm /usr/local/bin/zenmap

rm /usr/local/share/nmap
rm /usr/local/share/zenmap

apt-get remove nmap

echo
echo -e "\e[1;34mInstalling nmap from svn.\e[0m"
svn co https://svn.nmap.org/nmap/ /root/nmap-svn/
cd /root/nmap-svn/
./configure && make && make install

echo
echo -e "\e[1;34mUpdating locate db.\e[0m"
updatedb

echo
echo
read -p "Press <return> to continue."
}

##############################################################################################################

# Loop forever
while :
do

clear
f_Banner
f_Main

f_Main(){
clear
f_Banner

echo -e "\e[1;34mRECON\e[0m" "- Names, emails, URLs, whois, DNS, traceroute and load balancing."
echo "1.  Open Source Intelligence Gathering"
echo "2.  Scrape"
echo
echo -e "\e[1;34mDISCOVER\e[0m" "- Host discovery, port scanning, service enumeration and OS"
echo "identification using Nmap, Nmap scripts and Metasploit scanners."
echo "3.  Ping Sweep"
echo "4.  Single IP, URL or Range"
echo "5.  Local Area Network"
echo "6.  List"
echo "7.  CIDR Notation"
echo
echo -e "\e[1;34mWEB\e[0m"
echo "8.  Open multiple tabs in Firefox"
echo "9.  Nikto"
echo "10. SSL Check"
echo
echo -e "\e[1;34mMISC\e[0m"
echo "11. Crack WiFi"
echo "12. Reinstall nmap"
echo "13. Start a Metasploit listener"
echo "14. Exit"
echo
echo -n "Choice: "
read choice

case $choice in
     1) f_OSIG;;
     2) f_Scrape;;
     3) f_PingSweep;;
     4) f_Single;;
     5) f_LAN;;
     6) f_List;;
     7) f_CIDR;;
     8) f_MultiTabsFirefox;;
     9) f_Nikto;;
     10) f_SSLcheck;;
     11) ./crack-wifi.sh;;
     12) f_Reinstall_nmap;;
     13) f_Listener;;
     14) clear && exit;;
     99) f_Updates;;
     *) f_Error;;
esac
}

done

