# import smtplib 
# # from Email.Message import email_message
# from email.message import EmailMessage
# def sendmail(to,subject,body):
#     server=smtplib.SMTP_SSL('smtp.gmail.com',465)
#     server.login('taneemk14@gmail.com','glzm sdsd efvt ipzv')
#     msg=EmailMessage()
#     msg['FROM']='taneemk14@gmail.com'
#     msg['TO']=to
#     msg['SUBJECT']=subject
#     msg.set_content(body)
#     server.send_message(msg) 
#     server.close()   

import smtplib
from email.message import EmailMessage
from datetime import datetime

def sendmail(to, subject, body, otp_data=None):
    """
    Enhanced email sending function with OTP support
    Args:
        to: Recipient email
        subject: Email subject
        body: Main email content
        otp_data: Optional dict with:
            - code: The OTP code
            - expires_at: Expiration datetime
            - purpose: Description of OTP use
    """
    try:
        # Configure server (replace with your actual credentials)
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login('taneemk14@gmail.com','glzm sdsd efvt ipzv')  # Use app-specific password
        
        msg = EmailMessage()
        msg['From'] = 'taneemk14@gmail.com'  # Your verified sender email
        msg['To'] = to
        msg['Subject'] = subject
        
        # Enhanced email body for OTP messages
        if otp_data:
            expires_at = otp_data['expires_at']
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            
            body = f"""
            {body}
            
            Your verification code: {otp_data['code']}
            
            This code is valid until: {expires_at.strftime('%Y-%m-%d %H:%M %Z')}
            ({otp_data.get('purpose', 'for account verification')})
            
            If you didn't request this, please ignore this email.
            """
        
        msg.set_content(body.strip())
        
        server.send_message(msg)
        server.close()
        return True
    
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False