import sys
import apt
import argparse
import pydig
import platform
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import dkim
from socket import error as socket_error
from email.mime.multipart import MIMEMultipart

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
    parser.add_argument('-s', "--smtp", action="store",dest='smtp',help="Use custom SMTP server to send a test email. By default: 127.0.0.1")
    parser.add_argument('-a', "--attachment", action="store",dest='attachment',help="Path to the file to attach with email")
    #Templates + subject.
    parser.add_argument("--subject", action="store",dest='subject',help="Subject of the email message")
    parser.add_argument("--template", action="store",dest='template',help="HTML template for body message")

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

def spoof(domain, you, smtp):
    #Cambiar el sender dentro del postfix.
    os.system("sudo sed -ri 's/(myhostname) = (.*)/\\1 = "+domain+"/g' /etc/postfix/main.cf")

    #Reload postfix
    os.system("systemctl start postfix ; systemctl restart postfix")

    me = "test@" + domain

    msg = MIMEText("test")

    msg['Subject'] = "Mail test from " + me
    msg['From'] = me
    msg['To'] = you

    s = smtplib.SMTP(smtp)
    s.sendmail(me, [you], msg.as_string())
    s.quit()

    print (green_color + "[+]" + whiteB_color + " Email sended successfully as " + green_color + me)

def send_email(domain,destination,smtp,dkim_private_key_path="dkimprivatekey.pem",dkim_selector="s1"):
    #check if postfix is installed.
    cache = apt.Cache()
    if cache['postfix'].is_installed:
        if (args.smtp is None):
            #Cambiar el sender dentro del postfix.
            os.system("sudo sed -ri 's/(myhostname) = (.*)/\\1 = "+domain+"/g' /etc/postfix/main.cf")

            #Reload postfix
            os.system("systemctl start postfix ; systemctl restart postfix")

    sender = "test@" + domain
    if (args.subject):
        subject=args.subject
    else:
        subject="Test"
        
        
    message_text="Test"
    if (args.template):
        fileopen = open(args.template, "r")
        fileread = fileopen.readlines()
        html=""
        for line in fileread:
        	html = html + line
        message_html = html
    else:
        message_html="""
            <html>
		<body>
		   <h3>Test</h3>
		   <br />
		   <p>Test magicspoofing</p>
		</body>
	    </html>
        """

    #Generate DKIM Certs
    os.system("rm -rf dkimprivatekey.pem public.pem 2> /dev/null")
    os.system("openssl genrsa -out dkimprivatekey.pem 1024 2> /dev/null")
    os.system("openssl rsa -in dkimprivatekey.pem -out public.pem -pubout 2> /dev/null")

    if isinstance(message_text, bytes):
        # needed for Python 3.
        message_text = message_text.decode()

    if isinstance(message_html, bytes):
        # needed for Python 3.
        message_html = message_html.decode()

    sender_domain = sender.split("@")[-1]
    msg = MIMEMultipart("alternative")
    msg.attach(MIMEText(message_text, "plain"))
    msg.attach(MIMEText(message_html, "html"))
    msg["To"] = destination
    msg["From"] = sender
    msg["Subject"] = subject

    if (args.attachment):
        #Attachment.
        attach_file_name = 'test.txt'
        attach_file = open(attach_file_name, 'rb') # Open the file as binary mode
        payload = MIMEBase('application', 'octate-stream')
        payload.set_payload((attach_file).read())
        encoders.encode_base64(payload) #encode the attachment

        payload.add_header('content-disposition', 'attachment', filename=attach_file_name)

        msg.attach(payload)

    try:
        # Python 3 libraries expect bytes.
        msg_data = msg.as_bytes()
    except:
        # Python 2 libraries expect strings.
        msg_data = msg.as_string()

    if dkim_private_key_path and dkim_selector:
        with open(dkim_private_key_path) as fh:
            dkim_private_key = fh.read()
        headers = [b"To", b"From", b"Subject"]
        sig = dkim.sign(message=msg_data,selector=str(dkim_selector).encode(),domain=sender_domain.encode(),privkey=dkim_private_key.encode(),include_headers=headers)
        msg["DKIM-Signature"] = sig[len("DKIM-Signature: ") :].decode()

        try:
            # Python 3 libraries expect bytes.
            msg_data = msg.as_bytes()
        except:
            # Python 2 libraries expect strings.
            msg_data = msg.as_string()

    #Change hostname from machine before send email
    existhost = os.popen('grep "'+domain+'" /etc/hosts').read()
    if (existhost==""):
        hostname = os.popen('hostname ; echo "127.0.0.1 ' + domain + '" >> /etc/hosts').read()
    else:
        hostname = os.popen('hostname').read()

    os.popen('hostnamectl set-hostname '+domain+' 2>&1 > /dev/null')

    s = smtplib.SMTP(smtp)
    s.sendmail(sender, [destination], msg_data)
    s.quit()

    print (green_color + "[+]" + whiteB_color + " Email sended successfully as " + green_color + sender)
    os.system("rm -rf dkimprivatekey.pem public.pem 2> /dev/null")

    #Change hostname to the original.
    os.popen('hostnamectl set-hostname '+hostname+' 2>&1 > /dev/null')

    return msg



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
                                if (args.smtp):
                                    smtp = args.smtp
                                    #spoof(dominiotld, args.email, smtp)
                                    send_email(dominiotld, args.email, smtp)
                                else:
                                    smtp = "127.0.0.1"
                                    #spoof(dominiotld, args.email, smtp)
                                    send_email(dominiotld, args.email, smtp)

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
                                if (args.smtp):
                                    smtp = args.smtp
                                    #spoof(dominiotld, args.email, smtp)
                                    send_email(dominiotld, args.email, smtp)
                                else:
                                    smtp = "127.0.0.1"
                                    #spoof(dominiotld, args.email, smtp)
                                    send_email(dominiotld, args.email, smtp)

                    print (" ")
        else:
            start(args.domain)
            flag_spf = check_spf(args.domain)
            flag_dmarc = check_dmarc(args.domain)

            if (flag_spf == 0 and flag_dmarc == 0):
                print (red_color + "[!] You can spoof this domain! ")
                if (args.test):
                    if (args.email):
                        if (args.smtp):
                            smtp = args.smtp
                            #spoof(args.domain, args.email, smtp)
                            send_email(args.domain, args.email, smtp)
                        else:
                            smtp = "127.0.0.1"
                            #spoof(args.domain, args.email, smtp)
                            send_email(args.domain, args.email, smtp)

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
                        if (args.smtp):
                            smtp = args.smtp
                            #spoof(dominio, args.email, smtp)
                            send_email(dominio, args.email, smtp)
                        else:
                            smtp = "127.0.0.1"
                            #spoof(dominio, args.email, smtp)
                            send_email(dominio, args.email, smtp)

            print (" ")
