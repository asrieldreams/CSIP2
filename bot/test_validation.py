from commands import validate_url, validate_phone, validate_email, sanitise_text, detect_indicator_type

print("=== URL VALIDATION ===")
print(validate_url("http://fake-dbs.com"))        # True
print(validate_url("not-a-url"))                  # False
print(validate_url("ftp://wrong.com"))            # False

print("\n=== PHONE VALIDATION ===")
print(validate_phone("+65 9123 4567"))            # True
print(validate_phone("91234567"))                 # True
print(validate_phone("abc123"))                   # False

print("\n=== EMAIL VALIDATION ===")
print(validate_email("scam@fake-bank.com"))       # True
print(validate_email("notanemail"))               # False

print("\n=== SANITISE TEXT ===")
print(sanitise_text("<script>alert('xss')</script>hello"))  # strips tags
print(sanitise_text("Normal description text"))             # unchanged

print("\n=== AUTO DETECT TYPE ===")
print(detect_indicator_type("http://scam.com"))   # url
print(detect_indicator_type("+6591234567"))       # phone
print(detect_indicator_type("scam@fake.com"))     # email
print(detect_indicator_type("random message"))    # message