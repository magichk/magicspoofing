## **MagicSpoofing**

### Project description
A python3 script for search possible misconfiguration in a DNS related to security protections of email service from the domain name. This project is for educational use, we are not responsible for its misuse.

### Dependencies
You can install the python3 dependencies using the requeriments.txt file:
```pip3 install -r requirements.txt```

Also, by default needs postfix service because MagicSpoofMail uses 127.0.0.1 address to send an email. Optionally, you can change this with -s or --smtp parameter. To install in a debian environment for example use this and make all the config by default:
```sudo apt-get install postfix```

### Checks
    - Check SPF record in a domain name.
    - Check DMARC record in a domain name.
    - In case that SPF & DMARC is not configured, send a test email 

### Available options

![alt text](https://raw.githubusercontent.com/magichk/magicspoofing/master/images/help.png "MagicSpoofing - Help")

### Check a domain name

![alt text](https://raw.githubusercontent.com/magichk/magicspoofing/master/images/check_domain.png "MagicSpoofing - Check domain name")

### Check & test domain name

![alt text](https://raw.githubusercontent.com/magichk/magicspoofing/master/images/check_and_test.png "MagicSpoofing - Check and test domain name")

### Search from a name some TLD's

![alt text](https://raw.githubusercontent.com/magichk/magicspoofing/master/images/check_tlds.png "MagicSpoofing - Check some tld's from a name")

Note: You can add more TLD's editing the script file.
