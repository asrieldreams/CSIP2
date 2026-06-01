from commands import is_rate_limited

user_id = 12345

for i in range(7):
    result = is_rate_limited(user_id)
    print(f"Attempt {i+1}: Rate limited = {result}")

