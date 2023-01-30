from django.shortcuts import render
import string
import random
from django.http import HttpResponse

def encrypt_decrypt(request):
    password = "family"
    if password == "family":
        def randomword(length):
            letters = string.ascii_letters + string.digits + string.punctuation
            return ''.join(random.choice(letters) for i in range(length))

        def encrypt(content, key):
            content = "\n".join(content)
            encrypted = []
            lines = content.split("\n")
            for line in lines:
                if line == "":
                    encrypted.append("")
                    continue
                encrypted_line = ""
                for i, char in enumerate(line):
                    shift = ord(key[i % len(key)])
                    char_code = ord(char)
                    encrypted_line += chr((char_code + shift) % 128)
                encrypted.append(encrypted_line)
            return "\n".join(encrypted)

        def nencrypt(codedcontent):
            numbers = []
            for i in range(len(codedcontent)):
                numbers.append(str((ord(codedcontent[i])) + (i*3)))
            return ' '.join(numbers)

        def ndecrypt(codedcontent):
            split_content = codedcontent.split(' ')
            decoded = ''
            for i in range(len(split_content)):
                decoded += chr((int(split_content[i])) - (i*3))
            return decoded

        def decrypt(content, key):
            decrypted = []
            lines = content.split("\n")
            for line in lines:
                if line == "":
                    decrypted.append("")
                    continue
                decrypted_line = ""
                for i, char in enumerate(line):
                    shift = ord(key[i % len(key)])
                    char_code = ord(char)
                    decrypted_line += chr((char_code - shift) % 128)
                decrypted.append(decrypted_line)
            return "\n".join(decrypted)

        if request.method == 'GET':
            return render(request, 'encrypt_decrypt.html')

        if request.method == 'POST':
            content = request.POST.get("content")
            action = request.POST.get("action")
            if action == "1":
                content = content.split("\n")
                key = randomword(15)
                codedcontent = encrypt(content, key)
                numbers = nencrypt(codedcontent)
                output = f"Key: {key}\nNumbers: {numbers}"
                return HttpResponse(output)
            elif action == "2":
                content = ndecrypt(content)
                key = request.POST.get("key")
                decoded = decrypt(content, key)
                return HttpResponse(decoded)
    else:
        return HttpResponse("Incorrect")

