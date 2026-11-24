#include <stdio.h>
#include <string.h>
#include <cpuid.h>
#include <intsafe.h>

// Size for buffers that will hold unknown-size data
#define BUFSIZE 1024

// Exit status for every error; the error code itself is printed to stderr. A Windows error
// code can't be the exit status, because only its low 8 bits survive, and those can be 0.
#define EXIT_ERROR 1

union CPUIDVendor {
	unsigned int reg[3];
	char vendor[13];
};

struct EncEntropy {
	unsigned int serial;
	char vendor[12];
	char signature[3];
	char user[13];
};

int main(int argc, char *argv[]) {
	// Which install's device key to decrypt: "bytebooks" or "adobe". The plugin passes
	// the one whose activation it imports, so the key always matches that activation.
	// Without an argument, use ByteBooks if BDE has a device key, otherwise Adobe.
	int force_adobe = 0;
	int allow_fallback = 1;
	if (argc > 1) {
		if (strcmp(argv[1], "adobe") == 0) {
			force_adobe = 1;
		}
		else if (strcmp(argv[1], "bytebooks") != 0) {
			fprintf(stderr, "Usage: %s [bytebooks|adobe]\n", argv[0]);
			return EXIT_ERROR;
		}
		allow_fallback = 0;
	}

	// Get disk serial
	DWORD serial;
	if (GetVolumeInformation("c:\\\\", NULL, 0, &serial, NULL, NULL, NULL, 0) == 0) {
		DWORD err = GetLastError();
		fprintf(stderr, "Error with GetVolumeInformation: %ld\n", err);
		return EXIT_ERROR;
	}
	DWORD be_serial = htonl(serial);
	fprintf(stderr, "Disk serial (hex): %08lx\n", serial);


	unsigned int eax, ebx, ecx, edx;
	// Get CPUID vendor string
	union CPUIDVendor cpu_vendor;
	if (__get_cpuid(0, &eax, &cpu_vendor.reg[0], &cpu_vendor.reg[2], &cpu_vendor.reg[1]) == 0) {
		fprintf(stderr, "Error: cpuid(0) not supported");
		return EXIT_ERROR;
	}
	cpu_vendor.vendor[12] = '\0';
	fprintf(stderr, "CPUID Vendor: %s\n", cpu_vendor.vendor);
	// Get CPUID "signature" (eax of CPUID(1))
	unsigned int signature;
	if (__get_cpuid(1, &signature, &ebx, &ecx, &edx) == 0) {
		fprintf(stderr, "Error: cpuid(1) not supported");
		return EXIT_ERROR;
	}
	unsigned int be_signature = htonl(signature);
	fprintf(stderr, "CPUID Signature (hex): %08x\n", signature);



	// Get Encrypted adobe key
	BYTE key[BUFSIZE];
	memset(&key, 0, sizeof(key)); 
	DWORD key_size = BUFSIZE;

	// BDE/ADE only write the "key" attribute to the Device key when the software is activated.
	LSTATUS key_retval = ERROR_FILE_NOT_FOUND;
	if (!force_adobe) {
		key_retval = RegGetValue(HKEY_CURRENT_USER, "Software\\ByteBooks\\Adept\\Device", "key", RRF_RT_REG_BINARY, NULL, &key, &key_size);
		if (key_retval != ERROR_SUCCESS && allow_fallback) {
			force_adobe = 1;
		}
	}
	if (force_adobe) {
		key_size = BUFSIZE;
		key_retval = RegGetValue(HKEY_CURRENT_USER, "Software\\Adobe\\Adept\\Device", "key", RRF_RT_REG_BINARY, NULL, &key, &key_size);
	}
	fprintf(stderr, "Using the %s device key\n", force_adobe ? "Adobe" : "ByteBooks");
	if (key_retval != ERROR_SUCCESS) {
		fprintf(stderr, "Error with RegGetValue: %ld\n", key_retval);
		fprintf(stderr, "key_size: %ld\n", key_size);
		return EXIT_ERROR;
	}
	fprintf(stderr, "Encrypted key (hex): ");
	for (size_t i = 0; i < key_size; i++ )
	{
	   fprintf(stderr, "%02x", key[i]);
	}
	fprintf(stderr, "\n");


	// Get windows user
	wchar_t wideuser[BUFSIZE];
	// RegGetValueW/GetUserNameW only sets bytes as needed for length of username, but we need null bytes to fill the rest
	memset(&wideuser, 0, sizeof(wideuser)); 
	DWORD wideuser_size = BUFSIZE;
	LSTATUS user_retval;
	if (force_adobe) {
		user_retval = RegGetValueW(HKEY_CURRENT_USER, L"Software\\Adobe\\Adept\\Device", L"username", RRF_RT_REG_SZ, NULL, &wideuser, &wideuser_size);
	}
	else {
		user_retval = RegGetValueW(HKEY_CURRENT_USER, L"Software\\ByteBooks\\Adept\\Device", L"username", RRF_RT_REG_SZ, NULL, &wideuser, &wideuser_size);
	}
	if (user_retval != ERROR_SUCCESS) {
		fprintf(stderr, "Error with RegGetValue: %ld\n", user_retval);
		fprintf(stderr, "wideuser_size: %ld\n", wideuser_size);
		fprintf(stderr, "Falling back to GetUserNameW\n");
		wideuser_size = BUFSIZE;
		if (GetUserNameW(wideuser, &wideuser_size) == 0) {
			DWORD err = GetLastError();
			fprintf(stderr, "Error with GetUserName: %ld\n", err);
			fprintf(stderr, "wideuser_size: %ld\n", wideuser_size);
			return EXIT_ERROR;
		}
	}
	fprintf(stderr, "Username: %ls\n", wideuser);
	// Copy every second byte of the wide string, to make an ascii-ish/non-long string
	// As adobe does
	// Only the first 13 chars are used, so only copy those
	char user[13];
	for (unsigned int i = 0; i < 13; i++) {
		user[i] = ((char *)wideuser)[i*2];
	}


	// Assemble "entropy" (passphrase) for key
	struct EncEntropy entropy;
	memcpy(&entropy.serial, &be_serial, sizeof(entropy.serial));
	memcpy(&entropy.vendor, &cpu_vendor.vendor, sizeof(entropy.vendor));
	memcpy(&entropy.signature, ((char*)(&be_signature))+1, sizeof(entropy.signature)); // Only the last 3 bytes are needed, hence the +1 ptr
	memcpy(&entropy.user, &user, sizeof(entropy.user));

	// Print entropy byte by byte in hex
	fprintf(stderr, "Entropy: ");
	for (size_t i = 0; i < sizeof(entropy); i++ )
	{
	   fprintf(stderr, "%02x", ((unsigned char*)&entropy)[i]);
	}
	fprintf(stderr, "\n");


	// Run decryption API
	DATA_BLOB ciphertext_data, entropy_data, plaintext_data;
	ciphertext_data.pbData = key;
	ciphertext_data.cbData = key_size;
	entropy_data.pbData = (BYTE*)(&entropy);
	entropy_data.cbData = sizeof(entropy);
	if (CryptUnprotectData(&ciphertext_data, NULL, &entropy_data, NULL, NULL, 0, &plaintext_data) != TRUE) {
		DWORD err = GetLastError();
		fprintf(stderr, "Error with CryptUnprotectData: %ld\n", err);
		return EXIT_ERROR;
	}
	fprintf(stderr, "Decrypted key length: %lu\n", plaintext_data.cbData);

	// The device key has 16 bytes. Anything else isn't a device key, and printing 16 bytes
	// of a shorter one would read past its end.
	if (plaintext_data.cbData != 16) {
		fprintf(stderr, "Error: the decrypted key has %lu bytes instead of 16\n", plaintext_data.cbData);
		return EXIT_ERROR;
	}

	// Print decrypted key to stdout
	for (unsigned int i = 0; i < 16; i++) {
		printf("%02x", plaintext_data.pbData[i]);
	}
	return 0;
}