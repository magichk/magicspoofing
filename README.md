## **MagicSpoofing**

### Project description
A python3 script for search possible misconfiguration in a DNS related to security protections of email service from the domain name. This project is for educational use, we are not responsible for its misuse.

### Dependencies
You can install the python3 dependencies using the requeriments.txt file:
```pip3 install -r requirements.txt```

Also, needs postfix service. To install in a debian environment for example use this and make all the config by default:
```sudo apt-get install postfix```

### Checks
    - Check SPF record in a domain name.
    - Check DMARC record in a domain name.
    - In case that SPF & DMARC is not configured, send a test email 

