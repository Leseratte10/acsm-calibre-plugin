#include <stdio.h>
#include <cpuid.h>
#include <intsafe.h>

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

int main() {
	// Get disk serial
	DWORD serial;
	if (GetVolumeInformation("c:\\\\", NULL, 0, &serial, NULL, NULL, NULL, 0) == 0) {
		DWORD err = GetLastError();
		fprintf(stderr, "Error with GetVolumeInformation: %ld\n", err);
		return err;
	}
	DWORD be_serial = htonl(serial);
	fprintf(stderr, "Disk serial (hex): %08lx\n", serial);


	unsigned int eax, ebx, ecx, edx;
	// Get CPUID vendor string
	union CPUIDVendor cpu_vendor;
	if (__get_cpuid(0, &eax, &cpu_vendor.reg[0], &cpu_vendor.reg[2], &cpu_vendor.reg[1]) == 0) {
		fprintf(stderr, "Error: cpuid(0) not supported");
		return 1;
	}
	cpu_vendor.vendor[12] = '\0';
	fprintf(stderr, "CPUID Vendor: %s\n", cpu_vendor.vendor);
	// Get CPUID "signature" (eax of CPUID(1))
	unsigned int signature;
	if (__get_cpuid(1, &signature, &ebx, &ecx, &edx) == 0) {
		fprintf(stderr, "Error: cpuid(1) not supported");
		return 1;
	}
	unsigned int be_signature = htonl(signature);
	fprintf(stderr, "CPUID Signature (hex): %08x\n", signature);


	// Get windows user
	#define USERBUFSIZE 512
	TCHAR user[USERBUFSIZE];
	memset(&user, 0, sizeof(user));  // GetUserName only sets bytes as needed for length of username, but we need null bytes to fill the rest
	DWORD bufsize = USERBUFSIZE	;
	LSTATUS user_retval = RegGetValue(HKEY_CURRENT_USER, "Software\\Adobe\\Adept\\Device", "username", RRF_RT_REG_SZ, NULL, &user, &bufsize);
	if (user_retval != ERROR_SUCCESS) {
		fprintf(stderr, "Error with RegGetValue: %ld\n", user_retval);
		fprintf(stderr, "bufsize: %ld\n", bufsize);
		fprintf(stderr, "Falling back to GetUserName");
		if (GetUserName(user, &bufsize) == 0) {
			DWORD err = GetLastError();
			fprintf(stderr, "Error with GetUserName: %ld\n", err);
			return err;
		}
	}
	fprintf(stderr, "Username: %s\n", user);


	// Get Encrypted adobe key
	#define KEYBUFSIZE 180  // As measured
	BYTE key[KEYBUFSIZE];
	DWORD regkeysize = KEYBUFSIZE;
	LSTATUS key_retval = RegGetValue(HKEY_CURRENT_USER, "Software\\Adobe\\Adept\\Device", "key", RRF_RT_REG_BINARY, NULL, &key, &regkeysize);
	if (key_retval != ERROR_SUCCESS) {
		fprintf(stderr, "Error with RegGetValue: %ld\n", key_retval);
		fprintf(stderr, "regkeysize: %ld\n", regkeysize);
		return key_retval;
	}
	fprintf(stderr, "Encrypted key (hex): ");
	for (size_t i = 0; i < KEYBUFSIZE; i++ )
	{
	   fprintf(stderr, "%02x", key[i]);
	}
	fprintf(stderr, "\n");


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
	ciphertext_data.cbData = sizeof(key);
	entropy_data.pbData = (BYTE*)(&entropy);
	entropy_data.cbData = sizeof(entropy);
	if (CryptUnprotectData(&ciphertext_data, NULL, &entropy_data, NULL, NULL, 0, &plaintext_data) != TRUE) {
		DWORD err = GetLastError();
		fprintf(stderr, "Error with CryptUnprotectData: %ld\n", err);
		return err;
	}
	fprintf(stderr, "Decrypted key length: %lu\n", plaintext_data.cbData);

	// Print decrypted key to stdout
	for (int i = 0; i < 16; i++) {
		printf("%02x", plaintext_data.pbData[i]);
	}
}