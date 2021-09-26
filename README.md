# Calibre ACSM plugin

This is a Calibre plugin that allows you to turn ACSM files into EPUBs without the need for ADE. 
It is a full Python reimplementation of libgourou by Grégory Soutadé (http://indefero.soutade.fr/p/libgourou/).

## Setup

1. Download the plugin and import it into Calibre
2. Open the plugin settings, it should say "Not authorized for any ADE ID"
3. Click the "Link to ADE account" button
4. Enter your AdobeID and password, then wait a couple seconds for the success message.
5. The settings window should now say "Authorized with ADE ID X on device Y".
6. Click the "Export account activation data" and "Export account encryption key" buttons to export / backup your keys. Do not skip this step. The first file (ZIP) can be used to re-authorize Calibre after a reset / reinstall without using up one of your Adobe authorizations. The second file (DER) can be imported into DeDRM.
7. If needed (new AdobeID), import the DER file into the DeDRM plugin.
8. Download an EPUB ACSM file from Adobe's test library and see if you can import it into Calibre: https://www.adobe.com/de/solutions/ebook/digital-editions/sample-ebook-library.html 

IMPORTANT: 

- I would suggest creating a new dummy AdobeID to use for Calibre so just in case Adobe detects this and bans you, you don't lose your main AdobeID. 
- Combined with that I suggest importing the DER file into the DeDRM plugin to make sure that losing your AdobeID doesn't also mean you'll lose access to all your eBooks. 
- This plugin doesn't yet work with PDFs. Importing an ACSM file for a PDF book will just result in the ACSM file being imported, it won't be converted into a PDF.
- This software is not approved by Adobe. I am not responsible if Adobe detects that you're using nonstandard software and bans your account. Do not complain to me if Adobe bans your main ADE account - you have been warned. 


## To-Do list for the future?

There's a bunch of features that could still be added, but most of them aren't implemented in libgourou either, so I don't know if or when I'll be able to add these: 

- Support for anonymous Adobe IDs
- Support for un-authorizing a machine
- Support to re-import a backed-up authorization after a reinstallation (right now you can only do that manually)
- Support for PDFs
- Support for returning loan books
- ...
