
def otp_cache_key(phone, purpose):
    return f"otp:{purpose}:{phone}"

def pwd_token_cache_key(token):
    """Generate cache key for password token"""
    return f"pwd_token:{token}"
