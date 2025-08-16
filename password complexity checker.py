import re

def check_password_strength(password: str) -> str:
    """
    Assess the strength of a given password and return feedback.
    """
    score = 0
    feedback = []

    # Criteria 1: Length
    if len(password) < 6:
        feedback.append("Password is too short (minimum 6 characters).")
    elif len(password) < 10:
        feedback.append("Consider using at least 10 characters for stronger security.")
        score += 1
    else:
        score += 2

    # Criteria 2: Uppercase and lowercase
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 2
    else:
        feedback.append("Use a mix of uppercase and lowercase letters.")

    # Criteria 3: Numbers
    if re.search(r"\d", password):
        score += 2
    else:
        feedback.append("Include numbers in your password.")

    # Criteria 4: Special characters
    if re.search(r"[^A-Za-z0-9]", password):
        score += 2
    else:
        feedback.append("Add special characters (e.g., !@#$%^&*).")

    # Strength rating
    if score <= 2:
        strength = "Weak"
    elif score <= 5:
        strength = "Moderate"
    elif score <= 7:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return f"Password strength: {strength}\n" + "\n".join(feedback)


def main():
    print("=== Password Strength Checker ===")
    pwd = input("Enter a password to test: ")
    print("\n" + check_password_strength(pwd))


if __name__ == "__main__":
    main()
