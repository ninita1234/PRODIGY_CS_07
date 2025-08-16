def caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    if mode == 'decrypt':
        shift = -shift  # Reverse shift for decryption

    for char in text:
        if char.isalpha():  # Only encrypt letters
            # Shift uppercase letters
            if char.isupper():
                result += chr((ord(char) - 65 + shift) % 26 + 65)
            # Shift lowercase letters
            else:
                result += chr((ord(char) - 97 + shift) % 26 + 97)
        else:
            # Leave non-alphabet characters unchanged
            result += char
    return result


def main():
    print("=== Caesar Cipher Program ===")
    message = input("Enter your message: ")
    shift = int(input("Enter shift value (e.g., 3): "))

    encrypted = caesar_cipher(message, shift, mode='encrypt')
    decrypted = caesar_cipher(encrypted, shift, mode='decrypt')

    print("\n--- Results ---")
    print(f"Original message: {message}")
    print(f"Encrypted message: {encrypted}")
    print(f"Decrypted message: {decrypted}")


if __name__ == "__main__":
    main()
