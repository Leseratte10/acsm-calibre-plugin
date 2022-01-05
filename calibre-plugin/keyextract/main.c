#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>
#include <dpapi.h>
#include <fileapi.h>
#include <direct.h>

#ifdef DEBUG
#undef DEBUG
#endif

int char2int(char input) {
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	
	fputs("PROGOUTPUT:-3", stdout);
	exit(-3);
}

void hex2bin(const char * src, char * dst) {
	while (*src && src[1]) {
		*(dst++) = char2int(*src) * 16 + char2int(src[1]);
		src += 2;
	}
}

#ifdef DEBUG
void hexDump (
    const char * desc,
    const void * addr,
    const int len,
    int perLine
) {
    // Silently ignore silly per-line values.

    if (perLine < 4 || perLine > 64) perLine = 16;

    int i;
    unsigned char buff[perLine+1];
    const unsigned char * pc = (const unsigned char *)addr;

    // Output description if given.

    if (desc != NULL) fprintf (stderr, "%s:\n", desc);

    // Length checks.

    if (len == 0) {
        fprintf(stderr, "  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        fprintf(stderr, "  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of perLine means new or first line (with line offset).

        if ((i % perLine) == 0) {
            // Only print previous-line ASCII buffer for lines beyond first.

            if (i != 0) fprintf (stderr, "  %s\n", buff);

            // Output the offset of current line.

            fprintf (stderr, "  %04x ", i);
        }

        // Now the hex code for the specific character.

        fprintf (stderr, " %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % perLine] = '.';
        else
            buff[i % perLine] = pc[i];
        buff[(i % perLine) + 1] = '\0';
    }

    // Pad out last line if not exactly perLine characters.

    while ((i % perLine) != 0) {
        fprintf (stderr, "   ");
        i++;
    }

    // And print the final ASCII buffer.

    fprintf (stderr, "  %s\n", buff);
}
#endif

int get_serial() {
	DWORD serial = 0;
	int retval = GetVolumeInformation("c:\\\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
	if (retval == 0) {
		fprintf(stderr, "Error with GetVolumeInformation: %d\n", GetLastError());
		return 0;
	}
	return serial;
}

int main() {
	char * var_data = "X_DECRYPT_DATA";
	char * var_entropy = "X_DECRYPT_ENTROPY";

	char * data_hex = getenv(var_data);
	char * entropy_hex = getenv(var_entropy);

	if (data_hex == NULL || entropy_hex == NULL) {
		fputs("PROGOUTPUT:-1", stdout);
		exit(-1);
	}

	char * data_bytes = malloc((strlen(data_hex) / 2));
	char * entropy_bytes = malloc((strlen(entropy_hex) / 2));

	if (data_bytes == NULL || entropy_bytes == NULL) {
		fputs("PROGOUTPUT:-2", stdout);
		exit(-2);
	}

	hex2bin(data_hex, data_bytes);
	hex2bin(entropy_hex, entropy_bytes);

#ifdef DEBUG
	hexDump("data", data_bytes, strlen(data_hex)/2, 16);
	hexDump("entropy", entropy_bytes, strlen(entropy_hex)/2, 16);
#endif



DATA_BLOB input_data;
DATA_BLOB entropy_data;


DATA_BLOB output_data;

input_data.pbData = data_bytes;
input_data.cbData = strlen(data_hex)/2;

entropy_data.pbData = entropy_bytes;
entropy_data.cbData = strlen(entropy_hex)/2;


int ret = CryptUnprotectData(
	&input_data, 
	NULL, 
	&entropy_data, 
	NULL,
	NULL, 
	0, 
	&output_data);



if (ret) {
	if (output_data.cbData != 16) {
		printf("PROGOUTPUT:-5:%d", output_data.cbData);	
		exit(-5);
	}
	// Success! Return decrypted data
	fputs("PROGOUTPUT:0:", stdout);
	for (int i = 0; i < 16; i++) {
		printf("%02x", output_data.pbData[i]);
	}
	exit(0);
}
else {

	// Apparently Wine has issues with the volume serial code sometimes
	// so the code on the Linux side detects the wrong serial number.
	// Thus, if the decryption fails, we read the serial number that Wine
	// (and ADE) sees back to the Linux side for another attempt.

	int err = GetLastError();

	printf("PROGOUTPUT:-4:%d:%08x", err, get_serial());

	exit(-4);
}


}

