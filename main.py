import secrets

symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_+-="

a = secrets.randbelow(15) + 20

while True:
    myPassword = ""

    for i in range(a):
        myPassword += secrets.choice(symbols)

    has_capital = any(char.isupper() for char in myPassword)
    has_special = any(char in "!@#$%^&*_+-=" for char in myPassword)

    if has_capital and has_special:
        break

print(myPassword)