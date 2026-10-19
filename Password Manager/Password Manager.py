#This program is a secure password manager
#Bulding a password manager that stores user credentials securing using
# strong encryption. This ensures the safety of sensitive information.
# I ensured I installed the necessary libraries for the encryption and decryption processes.

import sqlite3 #this will be used to create and manage the database - SQLite
              # will store data/information users and credentials - necessary for username and
              #password encryption
import secrets #very important for password manager as generates cryptographically secure random values
import base64 # this will convert binary data into text representation that will be easier to store
import string # this will be used to generate secure passwords and a collection of characters

import os

from argon2 import PasswordHasher
# argon2 was chosen as this password manager requires a secured user's master password hashing
#sha-256 was not used because it is very fast and not suitable for password hashing
#argon2 is slow and memory-intensive making it more secure

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
#using cryptography for secure encryption and decryption ensuring that stored credentials are protected
#hazmat would allow for low-level cryptographic operationss; allows me  to use an implementation
# rather than  writing AES encryption and hazmat stands for hazardous materials.
#primitivies would contain the cryptographic building blocks needed for encryption and decryption
#ciphers would contain the actual encryption and decryption algorithms
#aead provides confidentiality and integrity for the encrypted data

# **************CONFIGURATION**************

database = "passwordmanager.db"
# this is the name of the database file in SQLite being used
#this database will store all the user credentials securely in the SQLite database

passwordhasher = PasswordHasher()
#Using the Argon2 password hasher for secure master password hashing, making password attacks
#more difficult to succeed.

# !!!!!!!!!!!!!!!!Database Configuration!!!!!!!!!!!!!!!!
def create_database():
    # function will create the database and the required tables
    
    connection = sqlite3.connect(database)
    # opens a connection to the SQLite database
    #if the database file does not exist, it will be created automatically
    
    cursor = connection.cursor()
    # this creates a cursor that will send SQL commands to the database

    cursor.execute("""id
                   username
                   password
                   failed attempts"""
                   )
    # this will store the info needed to authenticate the users
    
    cursor.execute("""id
                   userid
                   website
                   username_encrypted
                   password_encrypted
                   foreign key
                   """)
    
    connection.commit()
    # permanently saves the changes made to the database
    
    connection.close()
    # closes the connection to the database as I am finished with the operations
    
    
# ===================== Encryption and Decryption =====================
def encryptdata(data, key):
    
    # the function will encrypt the data using  AES-GCM encryption
    # This encryption algorithm is used because it provides confidentiality,
    # integrity and authenication.
    
    rvalues = secrets.token_bytes(12)
    #rvalues - value used once required by AES-GCM for each encyption
    # what is happening is that for secrets.tokon_bytes is generating 12 random bytes
    #secrets ensures that the module rvalues generate cryptographically secure random values
    
    aes = AESGCM(key)
    # this would create the AES-GCM encryption object using our encryption key
    
    #now conversion of text into bytes will be done and then encrypted
    encrypted_data = aes.encrypt(rvalues,
                                 data.encode,
                                 None)

# now doing the reverse oepration of decryption
def decryptdata(encrypted_data, key):
    # the function will decrypt the data using the AES-GCM decryption
    
    # creating the AES-GCM decryption object using the same encryption key
    aes = AESGCM(key)
    
    #now the first 12 bytes of the encrypted data will be extracted as the rvalues
    rvalues = encrypted_data[:12]
    
    # and everything after the first 12 bytes will be extracted as the actual encryption
    ciphertext =encrypted_data[12:]
    
    # finally decrypting the ciphertext using the AES-GCM decryption object 
    # and the extracted rvalues
    decrypted_data =aes.decrypt(rvalues, ciphertext, None)
    
    #Convert the decrypted data from bytes back to string representation
    return decrypted_data.decode

#now adding the add_password() function to save passwords securely in the SQLite database
def add_password(website, username, password, key):
    #this function will add a new password entry to the database for a specific website and username
    encrypted_password = encryptdata(password, key)
    # encrypting the password using the encryptdata() function and the provided encryption key
    
    connection = sqlite3.connect(database)
    # opens a connection to the SQLite database
    cursor = connection.cursor()
    # creates a cursor that will send SQL commands to the database
    
    cursor.execute("INSERT INTO credentials (website, username_encrypted, password_encrypted) VALUES (?, ?, ?)", (website, username, encrypted_password))
    # this will insert the website, username, and encrypted password into the credentials table
    
    connection.commit()
    #permanently saving the changes made to the database
    
    connection.close()
    # closing the connection to the database as I am finished with the operations
    
    print("Password added successfully!")

# next I am implementing view_passwords() function, which uses SQL select statement to retrieve and display all stored  encrypted credentials from the database
    
