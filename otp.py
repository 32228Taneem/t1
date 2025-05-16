# import random
# def genotp():
#     otp=''
#     for i in range(2):
#         otp=otp+random.choice([chr(i) for i in range(ord('A'),ord('Z')+1)])
#         otp=otp+random.choice([chr(i) for i in range(ord('a'),ord('z')+1)])
#         otp=otp+str(random.randint(0,9))
#     print(otp)
#     return otp

# otp.py
import random
from datetime import datetime, timedelta

def genotp(valid_minutes=10):
    """
    Simple OTP generator with time limit
    Args:
        valid_minutes: OTP validity in minutes (default: 10)
    Returns:
        tuple: (otp_code, expiration_time)
    """
    # Generate 6-digit numeric OTP (simpler version)
    otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    # Set expiration time
    expires_at = datetime.now() + timedelta(minutes=valid_minutes)
    
    print(f"Generated OTP: {otp}")
    return otp, expires_at