import sys
import argparse
import pydig
import platform
import smtplib
import os
from email.mime.text import MIMEText


sistema = format(platform.system())

if (sistema == "Linux"):
	# Text colors
	normal_color = "\33[00m"
	info_color = "\033[1;33m"
	red_color = "\033[1;31m"
	green_color = "\033[1;32m"
	whiteB_color = "\033[1;37m"
	detect_color = "\033[1;34m"
	banner_color="\033[1;33;40m"
	end_banner_color="\33[00m"
elif (sistema == "Windows"):
	normal_color = ""
	info_color = ""
	red_color = ""
	green_color = ""
	whiteB_color = ""
	detect_color = ""
	banner_color=""
	end_banner_color=""

def banner():
    print (banner_color + "                                                                                           " + end_banner_color)
    print (banner_color + "M   M   A    GGG  III  CCC         SSSS PPPP   OOO   OOO  FFFFF       M   M   A   III L    " + end_banner_color)     
    print (banner_color + "MM MM  A A  G      I  C   C       S     P   P O   O O   O F           MM MM  A A   I  L    " + end_banner_color)
    print (banner_color + "M M M AAAAA G GG   I  C            SSS  PPPP  O   O O   O FFFF        M M M AAAAA  I  L    " + end_banner_color)
    print (banner_color + "M   M A   A G   G  I  C   C           S P     O   O O   O F           M   M A   A  I  L    " + end_banner_color)
    print (banner_color + "M   M A   A  GGG  III  CCC        SSSS  P      OOO   OOO  F           M   M A   A III LLLLL" + end_banner_color)
    print (banner_color + "                                                                                           " + end_banner_color)
    print (" ")

######### Check Arguments
def checkArgs():
    parser = argparse.ArgumentParser()
    parser = argparse.ArgumentParser(description=red_color + 'Magic Spoof Mail 1.0\n' + info_color)
    parser.add_argument('-f', "--file", action="store",dest='file',help="File with a list of domains to check.")
    parser.add_argument('-d', "--domain", action="store",dest='domain',help="Single domain to check.")
    parser.add_argument('-c', "--common", action="store_true",dest='common',help="Common TLD")
    parser.add_argument('-t', "--test", action="store_true",dest='test',help="Send an email test")
    parser.add_argument('-e', "--email", action="store",dest='email',help="Send an email to this receiver address in order to test the spoofing mail from address.")

    args = parser.parse_args()
    if (len(sys.argv)==1) or (args.file==False and args.domain == False):
        parser.print_help(sys.stderr)
        sys.exit(1)

    return args




def start(domain):
    print (whiteB_color + " ---------------------------------- Analyzing " + domain + " ----------------------------------------")


def check_spf(domain):

    spf = pydig.query(domain, 'TXT')
    flag_spf = 0 

    for line in spf:
        if ("spf" in line):
            flag_spf = 1
            print (green_color + "[+]" + whiteB_color + " SPF is present")
            break
    
    if (flag_spf == 0):
        print (green_color + "[" + red_color + "-" + green_color + "]" + red_color + " This domain hasn't SPF config yet")

    return flag_spf

def check_dmarc(domain):

    dmarc = pydig.query('_dmarc.'+domain, 'TXT')
    flag_dmarc = 0


    for line in dmarc:    
        if ("DMARC" in line):
            flag_dmarc = 1
            print (green_color + "[+]" + whiteB_color + " DMARC is present")
            break
    
    if (flag_dmarc == 0):
        print (green_color + "[" + red_color + "-" + green_color + "]" + red_color + " This domain hasn't DMARC register")

    return flag_dmarc

def spoof(domain, you):
    #Cambiar el sender dentro del postfix.
    os.system("sudo sed -ri 's/(myhostname) = (.*)/\\1 = "+domain+"/g' /etc/postfix/main.cf")

    #Reload postfix
    os.system("systemctl restart postfix")

    me = "test@" + domain

    msg = MIMEText("Aquesta prova es la bona")

    msg['Subject'] = "Mail test from " + me
    msg['From'] = me
    msg['To'] = you

    s = smtplib.SMTP('127.0.0.1')
    s.sendmail(me, [you], msg.as_string())
    s.quit()

    print (green_color + "[+]" + whiteB_color + " Email sended successfully as " + green_color + me)


########## Main function #################3
if __name__ == "__main__":
    args = checkArgs()
    banner()

    if (args.domain):
        dominio = args.domain
        if (args.common):
            tlds = ['es','com','fr','it','co.uk','cat','de','be','au','xyz']
            inicio = dominio.find(".")
            if (inicio != -1):
                for tld in tlds:
                    nombre = dominio[0:inicio]
                    dominiotld = nombre + "." + tld
                    start(dominiotld)
                    flag_spf = check_spf(dominiotld)
                    flag_dmarc = check_dmarc(dominiotld)

                    if (flag_spf == 0 and flag_dmarc == 0):
                        print (red_color + "[!] You can spoof this domain! ")
                        if (args.test):
                            if (args.email):
                                spoof(dominiotld, args.email)

                    print (" ")
            else:
                for tld in tlds:
                    dominiotld = dominio + "." + tld
                    start(dominiotld)
                    flag_spf = check_spf(dominiotld)
                    flag_dmarc = check_dmarc(dominiotld)

                    if (flag_spf == 0 and flag_dmarc == 0):
                        print (red_color + "[!] You can spoof this domain! ")
                        if (args.test):
                            if (args.email):
                                spoof(dominiotld, args.email)

                    print (" ")    
        else:
            start(args.domain)
            flag_spf = check_spf(args.domain)
            flag_dmarc = check_dmarc(args.domain)

            if (flag_spf == 0 and flag_dmarc == 0):
                print (red_color + "[!] You can spoof this domain! ")
                if (args.test):
                    if (args.email):
                        spoof(args.domain, args.email)

        print (" ")

    if (args.file):
        fichero = open(args.file, "r")
        lineas = fichero.readlines()

        for dominio in lineas:
            dominio = dominio[0:len(dominio)-1]
            start(dominio)
            flag_spf = check_spf(dominio)
            flag_dmarc = check_dmarc(dominio)

            if (flag_spf == 0 and flag_dmarc == 0):
                print (red_color + "[!] You can spoof this domain! ")
                if (args.test):
                    if (args.email):
                        spoof(dominio, args.email)

            print (" ")


