from tkinter import *
from PIL import ImageTk, Image
import tkinter.messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = (ord(clear[i]) + ord(key_c)) % 256
        enc.append(enc_c)
    encoded_bytes = bytes(enc)
    encoded_string = base64.urlsafe_b64encode(encoded_bytes).decode()
    return encoded_string

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc)
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + enc[i] - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

wn=Tk()
wn.title("Secret Notes")
wn.geometry("450x700")
wn.config(padx=30,pady=30)
wn.configure(bg="black")

image = Image.open("C:/Users/555/Desktop/xxxjpg.png")
resized_image = image.resize((250, 100))
photo = ImageTk.PhotoImage(resized_image)
image_label = Label(wn, image=photo, bg="gray63")
image_label.pack(pady=5)



def Save_Button():
    title=enter_yourTitle.get()
    secret=enter_yourSecret.get("1.0","end")
    key=enter_masterKey.get()
    if len(title)==0 or len(secret)== 0 or len(key)== 0:
        tkinter.messagebox.showwarning(title="error", message="please enter all informations")
    else:
        try:
            dec_secret = decode(key, secret)
            enter_yourSecret.delete("1.0", "end")
            enter_yourSecret.insert("1.0", dec_secret)
        except:
            secret_encode = encode(key, secret)
            try:
                with open("secret.txt", "a") as data_file:
                    data_file.write(f"\n{title}\n{secret_encode}")
            except FileNotFoundError:
                with open("secret.txt", "w") as data_file:
                    data_file.write(f"\n{title}\n{secret_encode}")

            finally:
                enter_yourTitle.delete(0, END)
                enter_yourSecret.delete("1.0", "end")
                enter_masterKey.delete(0, END)

def Decrypt_Button():
    secret = enter_yourSecret.get("1.0", "end")
    key = enter_masterKey.get()
    if len(secret) == 0 or len(key) == 0:
        tkinter.messagebox.showwarning(title="error", message="Please Enter All Informations")
    else:
        try:

            dec_secret = decode(key, secret)
            enter_yourSecret.delete("1.0", "end")
            enter_yourSecret.insert("1.0", dec_secret)

        except:
            tkinter.messagebox.showwarning(title="error", message="Please Enter Your Encrypted Message")








Enter_yourTitle=Label(text="Enter Your Title",font=("arial",12,"italic bold"),bg="black",fg="gold4")
Enter_yourTitle.pack()

enter_yourTitle=Entry(width=45)
enter_yourTitle.pack(pady=5)

Enter_yourSecret=Label(text="Enter Your Secret",font=("arial",12,"italic bold"),bg="black",fg="gold4")
Enter_yourSecret.pack(pady=5)

enter_yourSecret=Text(wn,height=15)
enter_yourSecret.pack(pady=5)

Enter_masterKey=Label(text="Enter Master Key",font=("arial",12,"italic bold"), bg ="black",fg="gold4")
Enter_masterKey.pack(pady=5)

enter_masterKey=Entry(width=45)
enter_masterKey.pack(pady=5)

Save_button=Button(wn,text="Save & Encrypt",font=("arial",12,"italic bold"),command=Save_Button)
Save_button.pack(pady=5)

Decrypt_button=Button(wn,text="Decrypt",font=("arial",12,"italic bold"),command=Decrypt_Button)
Decrypt_button.pack(pady=5)

result_label =Label(text="", bg="black", fg="gold4")
result_label.pack()



wn.mainloop()