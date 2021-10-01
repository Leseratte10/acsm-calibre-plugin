# Calibre ACSM Input plugin

This is a Calibre plugin that allows you to turn ACSM files into EPUB or PDF files without the need for Adobe Digital Editions. 
It is a full Python reimplementation of libgourou by Grégory Soutadé (http://indefero.soutade.fr/p/libgourou/).

## Setup

1. Download the plugin and import it into Calibre
2. Open the plugin settings, it should say "Not authorized for any ADE ID"
3. Click the "Link to ADE account" button
4. Enter your AdobeID and password, then wait a couple seconds for the success message.
5. The settings window should now say "Authorized with ADE ID X on device Y".
6. Click the "Export account activation data" and "Export account encryption key" buttons to export / backup your keys. Do not skip this step. The first file (ZIP) can be used to re-authorize Calibre after a reset / reinstall without using up one of your Adobe authorizations. The second file (DER) can be imported into DeDRM.
7. If needed (new AdobeID), import the DER file into the DeDRM plugin.
8. Download an ACSM file from Adobe's test library and see if you can import it into Calibre: https://www.adobe.com/de/solutions/ebook/digital-editions/sample-ebook-library.html 

IMPORTANT: 

- I would suggest creating a new dummy AdobeID to use for Calibre so just in case Adobe detects this and bans you, you don't lose your main AdobeID. 
- Combined with that I suggest importing the DER file into the DeDRM plugin to make sure that losing your AdobeID doesn't also mean you'll lose access to all your eBooks. 
- Support for PDFs might be unreliable. You will need to apply pull request #1689 (including my additional bugfix in the comments of that PR) to the DeDRM plugin in order to remove the DRM from PDF files. If you still encounter an issue with a PDF file created by this tool even with these bugfixes, please report a bug (in this repository, not in the DeDRM one) and attach the corrupted PDF.
- This software is not approved by Adobe. I am not responsible if Adobe detects that you're using nonstandard software and bans your account. Do not complain to me if Adobe bans your main ADE account - you have been warned. 


## Standalone version

In the folder "calibre-plugin" in this repo (or inside the Calibre plugin ZIP file) there's some scripts that can also be used standalone without Calibre. If you want to use these, you need to extract the whole ZIP file. 

- `register_ADE_account.py` can be used to authorize a computer with an ADE account. This creates the three files `activation.xml`, `device.xml` and `devicesalt`. These files are in the same format as the ones for the Calibre computer authorization (inside the `plugins/DeACSM/account/` folder). A ZIP activation export from Calibre will also contain these three files.
- `fulfill.py` can be used - with valid ADE account files in the same folder - to turn an URLLink.acsm file into an eBook. 
- `get_key_from_Adobe.py` can be used to contact the Adobe server and download the DER key file for a given AdobeID to import into a DeDRM plugin. Just input your credentials and this script will output the DER file that can be used with DeDRM to decrypt books for this AdobeID. This works independantly from the account activation files or from this plugin, so it's a good way to get your AdobeID decryption key, especially if you're on Linux and it's too difficult to export the keys from ADE running inside Wine. This process does not use up one of your six device activations.

Though, generally it's recommended to use the Calibre plugin instead of these standalone scripts. Except for maybe the `get_key_from_Adobe.py` script if you want to remove DRM from existing eBooks without having to extract the key from ADE.

## To-Do list for the future?

There's a bunch of features that could still be added, but most of them aren't implemented in libgourou either, so I don't know if or when I'll be able to add these: 

- Support for anonymous Adobe IDs
- Support for un-authorizing a machine
- Support for returning loan books
- ...
