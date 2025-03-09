import os
import smtplib
import platform
import subprocess
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email import encoders
import dkim

def is_postfix_installed():
    """
    Checks if Postfix is installed on the system
    
    Returns:
        bool: True if Postfix is installed, False otherwise
    """
    system = platform.system()
    
    if system == "Linux":
        try:
            # Try to execute the postfix command
            result = subprocess.run(["which", "postfix"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        except Exception:
            return False
    elif system == "Darwin":  # macOS
        try:
            # On macOS, check if the service is installed
            result = subprocess.run(["which", "postfix"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        except Exception:
            return False
    elif system == "Windows":
        # Postfix is not common on Windows
        return False
    
    return False

def configure_postfix(domain):
    """
    Configures Postfix for the specified domain
    
    Args:
        domain (str): The domain to configure
        
    Returns:
        bool: True if configured correctly, False otherwise
    """
    system = platform.system()
    
    if system == "Linux":
        try:
            # Change the sender within postfix
            os.system(f"sudo sed -ri 's/(myhostname) = (.*)/\\1 = {domain}/g' /etc/postfix/main.cf")
            # Reload postfix
            os.system("systemctl start postfix ; systemctl restart postfix")
            return True
        except Exception:
            return False
    elif system == "Darwin":  # macOS
        try:
            # On macOS, the configuration file is in a different location
            os.system(f"sudo sed -i '' 's/myhostname = .*/myhostname = {domain}/g' /etc/postfix/main.cf")
            # Restart postfix on macOS
            os.system("sudo postfix stop && sudo postfix start")
            return True
        except Exception:
            return False
    
    return False

def spoof(domain, destination, smtp, colors):
    """
    Simple function to send a test email (legacy)
    
    Args:
        domain (str): The domain from which the email will be sent
        destination (str): The destination email address
        smtp (str): The SMTP server to use
        colors (dict): Dictionary with colors for output
    """
    # Configure Postfix if necessary
    if smtp == "127.0.0.1" and is_postfix_installed():
        configure_postfix(domain)

    sender = "test@" + domain

    msg = MIMEText("test")
    msg['Subject'] = "Mail test from " + sender
    msg['From'] = sender
    msg['To'] = destination

    try:
        s = smtplib.SMTP(smtp)
        s.sendmail(sender, [destination], msg.as_string())
        s.quit()
        print(colors["green"] + "[+]" + colors["white_bold"] + " Email sent successfully as " + colors["green"] + sender)
    except Exception as e:
        print(colors["red"] + f"[!] Error sending email: {e}")

def send_email(domain, destination, smtp, colors, sender=None, subject=None, 
               template=None, attachment=None, dkim_private_key_path="dkimprivatekey.pem", 
               dkim_selector="s1"):
    """
    Sends an email with advanced options
    
    Args:
        domain (str): The domain from which the email will be sent
        destination (str): The destination email address
        smtp (str): The SMTP server to use
        colors (dict): Dictionary with colors for output
        sender (str, optional): Sender email address. Default "test@{domain}"
        subject (str, optional): Email subject. Default "Test"
        template (str, optional): Path to an HTML template for the message body
        attachment (str, optional): Path to the file to attach
        dkim_private_key_path (str, optional): Path to the DKIM private key
        dkim_selector (str, optional): DKIM selector
    """
    # Configure Postfix if necessary
    if smtp == "127.0.0.1" and is_postfix_installed():
        configure_postfix(domain)

    # Configure sender
    if sender is None:
        sender = "test@" + domain

    # Configure subject
    if subject is None:
        subject = "Test"
        
    # Configure text message
    message_text = "Test"
    
    # Configure HTML message
    if template:
        try:
            with open(template, "r") as fileopen:
                html = "".join(fileopen.readlines())
            message_html = html
        except Exception as e:
            print(f"Error reading template: {e}")
            message_html = """
                <html>
                    <body>
                       <h3>Test</h3>
                       <br />
                       <p>Test magicspoofing</p>
                    </body>
                </html>
            """
    else:
        message_html = """
            <html>
                <body>
                   <h3>Test</h3>
                   <br />
                   <p>Test magicspoofing</p>
                </body>
            </html>
        """

    # Generate DKIM certificates
    try:
        os.system("rm -rf dkimprivatekey.pem public.pem 2> /dev/null")
        os.system("openssl genrsa -out dkimprivatekey.pem 1024 2> /dev/null")
        os.system("openssl rsa -in dkimprivatekey.pem -out public.pem -pubout 2> /dev/null")
    except Exception as e:
        print(f"Error generating DKIM certificates: {e}")

    # Ensure messages are strings (for Python 3)
    if isinstance(message_text, bytes):
        message_text = message_text.decode()

    if isinstance(message_html, bytes):
        message_html = message_html.decode()

    # Configure the message
    sender_domain = sender.split("@")[-1]
    msg = MIMEMultipart("alternative")
    msg.attach(MIMEText(message_text, "plain"))
    msg.attach(MIMEText(message_html, "html"))
    msg["To"] = destination
    msg["From"] = sender
    msg["Subject"] = subject

    # Attach file if specified
    if attachment:
        try:
            with open(attachment, 'rb') as attach_file:
                payload = MIMEBase('application', 'octate-stream')
                payload.set_payload(attach_file.read())
                encoders.encode_base64(payload)
                payload.add_header('content-disposition', 'attachment', filename=os.path.basename(attachment))
                msg.attach(payload)
        except Exception as e:
            print(f"Error attaching file: {e}")

    # Convert the message to bytes or string as needed
    try:
        # Python 3 libraries expect bytes
        msg_data = msg.as_bytes()
    except:
        # Python 2 libraries expect strings
        msg_data = msg.as_string()

    # Sign with DKIM if key is provided
    if dkim_private_key_path and dkim_selector:
        try:
            with open(dkim_private_key_path) as fh:
                dkim_private_key = fh.read()
            headers = [b"To", b"From", b"Subject"]
            sig = dkim.sign(
                message=msg_data,
                selector=str(dkim_selector).encode(),
                domain=sender_domain.encode(),
                privkey=dkim_private_key.encode(),
                include_headers=headers
            )
            msg["DKIM-Signature"] = sig[len("DKIM-Signature: "):].decode()

            # Update msg_data with the signature
            try:
                msg_data = msg.as_bytes()
            except:
                msg_data = msg.as_string()
        except Exception as e:
            print(f"Error signing with DKIM: {e}")

    # Send the email
    try:
        s = smtplib.SMTP(smtp)
        s.sendmail(sender, [destination], msg_data)
        s.quit()
        print(colors["green"] + "[+]" + colors["white_bold"] + " Email sent successfully as " + colors["green"] + sender)
    except Exception as e:
        print(colors["red"] + f"[!] Error sending email: {e}")
    finally:
        # Clean up temporary files
        try:
            os.system("rm -rf dkimprivatekey.pem public.pem 2> /dev/null")
        except Exception:
            pass 