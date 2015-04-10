JCryptoPad
==========

It aims to be a simple, portable and *strong* encrypting Notepad coded in Java 7.

It is able to read and write ETXT text documents, which are simple ZIP archives containing a TXT file (UTF-8 encoded, CR-LF line-ended) encrypted with AES, for maximum security and portability.

It encrypts with AES-128, but automatically switches to AES-256 if the "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files"[1] are installed in the JRE.

Obviously, the file contents are also deflated before encryption.

The well known AE-1 specification from WinZip[2] is implemented in MiniZipAE class using the pure JRE, along with a minimal ZIP reader/writer.

The project was developed with NetBeans 8, but can be easily imported in eclipse: just create a new JCryptoPad Java project in eclipse (updated with WindowBuilder plugin), merge the "src" directory with the eclipse project's one and refresh the project pane. Then open, edit, visually modify the sources or do what you want; build the Java classes and, eventually, export them all into a stand-alone JAR file.

A smarter, compatible version of this notepad coded in Python is also available in my CryptoPad repository. [3]



[1] Look at http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html

[2] See http://www.winzip.com/aes_info.htm

[3] https://github.com/maxpat78/CryptoPad

