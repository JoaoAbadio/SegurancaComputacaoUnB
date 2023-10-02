#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define SIZE 1000
#define ASCII 65

// Prints the main menu and wait for an input.
void menu(char* option) {
    printf("\nThe Vigenere cipher\n");
    printf("1. Encrypt\n");
    printf("2. Decrypt\n");
    printf("3. Discover key\n");
    printf("4. Exit\n");
    scanf(" %c", option);
}

// Creates new file (new_fp) that is the fp with all letters uppercase.
void format_plaintext(FILE* fp) {
    char file_char;
    FILE* new_fp = fopen("formated_input.txt", "w");

    while ((file_char = fgetc(fp)) != EOF) {
        if (isalpha(file_char)) {
            if (islower(file_char)) {
                fputc(toupper(file_char), new_fp);
            }
            else {
                fputc(file_char, new_fp);
            }
        }
        else {
            fputc(file_char, new_fp);
        }
    }

    fclose(new_fp);
}

// Fomarts key string to be only letters and uppercase.
char* format_key (char* key) {
    char* new_key = (char*) malloc(sizeof(char) * 30);
    size_t i;   // Index used in for loop.

    for (i = 0; key[i] != '\0'; i++) {
        if (isalpha(key[i])) {
            if (isupper(key[i])) {
                new_key[i] = key[i];
            }
            else {
                new_key[i] = toupper(key[i]);
            }
        }
    }

    new_key[i] = '\0';

    return new_key;
}

// Encrypts the plainfile with the key according to Vigenere Cipher.
void encrypt_file(FILE* fp, char* key) {
    char file_char;     // The characters of the plainfile.
    char filename[30];  // Output (cipherfile) file name.
    FILE* new_fp;       // File pointer to the new cipherfile.
    size_t key_len = strlen(key);

    printf("Enter the new ciphertext filename: ");
    scanf("%s", filename);
    new_fp = fopen(filename, "w");

    int i = 0;  // Used to cycle over key.
    while (((file_char = fgetc(fp)) != EOF)) {
        if (isalpha(file_char)) {
            char cipher_char;
            // c_i = (m_i + k_i) mod 26.
            cipher_char = ( ( (file_char - ASCII) + (key[i % key_len] - ASCII) ) % 26) + ASCII;
            fputc(cipher_char, new_fp);
            i++;
        }
        else {
            fputc(file_char, new_fp);
        }
    }

    printf("\nFile encrypted in %s\n", filename);

    fclose(new_fp);
}

// Decrypts the cipherfile with the key according to Vigenere Cipher.
void decrypt_file(FILE* fp, char* key) {
    char file_char;     // The characters of the plainfile.
    char filename[30];  // Output (plainfile) file name.
    FILE* new_fp;       // File pointer to the new plainfile.
    size_t key_len = strlen(key);

    printf("Enter the new plaintext filename: ");
    scanf("%s", filename);
    new_fp = fopen(filename, "w");

    int i = 0;  // Used to cycle over key.
    while (((file_char = fgetc(fp)) != EOF)) {
        if (isalpha(file_char)) {
            char plain_char;
            // m_i = (c_i - k_i) mod 26.
            plain_char = ( ( (file_char - ASCII) - (key[i % key_len] - ASCII) ) % 26);

            // plain_char can result in a negative integer, if it is, find its positive congruent.
            if (plain_char < 0) {
                plain_char += ASCII + 26;
                fputc(plain_char, new_fp);
            }
            else {
                plain_char += ASCII;
                fputc(plain_char, new_fp);
            }

            i++;
        }
        else {
            fputc(file_char, new_fp);
        }
    }

    printf("\nFile decrypted in %s\n", filename);

    fclose(new_fp);
}

// Calculates the IOC of a given vector.
float index_of_coincidence(float* ocurrencies, size_t size) {
    float ioc = 0;

    for (int i = 0; i < 26; i++) {
        ocurrencies[i] /= size;
        ioc += ocurrencies[i] * ocurrencies[i];
    }

    return ioc;
}

// Fomarts cipherfile to be only letters and uppercase.
void format_ciphertext(FILE* fp) {
    char file_char;
    FILE* new_fp = fopen("formated_input.txt", "w");

    while ((file_char = fgetc(fp)) != EOF) {
        if (isalpha(file_char)) {
            if (islower(file_char)) {
                fputc(toupper(file_char), new_fp);
            }
            else {
                fputc(file_char, new_fp);
            }
        }
    }

    fclose(new_fp);
}

// Prints the average of IOCs and wait for user choose which one makes more sense.
int key_size(FILE* fp) {
    int key_size;   // Chosen by user.
    format_ciphertext(fp);

    // The ciphertext file formated.
    FILE* new_fp = fopen("formated_input.txt", "r");

    // t is the period (possible key size).
    for (int t = 2; t < 13; t++) {
        // group is [0, t).
        int group = 0;
        // avg_ioc is the average of all IOCs of a given group [0, t).
        float avg_ioc = 0;

        for (group = 0; group < t; group++) {
            // All ocurrencies of a letter from alphabet in the cipherfile.
            float ocurrencies[26] = {0};
            size_t letters_in_group = 0;   // Quantity of chars in a group.
            int n = 0;  // The multiplier of the period (t).
            char char_group;

            // Seek to c_group.
            fseek(new_fp, group, SEEK_SET);
            while ( (char_group = fgetc(new_fp)) != EOF) {
                letters_in_group++;
                int position = char_group - ASCII;
                ocurrencies[position]++;

                // Seek to c_group + nt.
                fseek(new_fp, group + (++n * t), SEEK_SET);
            }

            // IOC of each group is added.
            avg_ioc += index_of_coincidence(ocurrencies, letters_in_group);
        }

        avg_ioc /= group;
        printf("Result from index of coincidence method (|k| = %d): %f\n", t, avg_ioc);
    }

    printf("\nEnter the key size (English ≃ 0.066 || Portuguese ≃ 0.078): ");
    scanf("%d", &key_size);

    rewind(fp);
    fclose(new_fp);

    return key_size;
}

// Finds the key size calculating the average of each alphabetic caracter and comparing with
// the average of portuguese and english.
char* find_key(FILE* fp) {
    int key_len = key_size(fp);
    char* key = (char*) malloc(sizeof(char) * key_len);
    FILE* new_fp = fopen("formated_input.txt", "r");
    char cipher_char;

    char letters[26] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ"};

    float portuguese_probabilities[26] = {0.1463, 0.0104, 0.0388, 0.0499, 0.1257,
    0.0102, 0.0130, 0.0128, 0.0618, 0.0040, 0.0002, 0.0278, 0.0474, 0.0505, 0.1073,
    0.0252, 0.0120, 0.0653, 0.0781, 0.0434, 0.0463, 0.0167, 0.0001, 0.0021, 0.0001,
    0.0047};

    float english_probabilities[26] = {0.08167, 0.01492, 0.02782, 0.04253, 0.12702,
    0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360,
    0.00150, 0.01974, 0.00074};

    char language;
    printf("Enter: 1. Portuguese\t2. English: ");
    scanf(" %c", &language);

    int i;
    for (i = 0; i < key_len; i++) {
        // All ocurrencies of a letter from alphabet in the cipherfile.
        float ocurrencies[26] = {0};
        size_t letters_in_group = 0;    // Quantity of chars in a group.
        int n = 0;                      // key_len multiplier.

        fseek(new_fp, i , SEEK_SET);
        while ( (cipher_char = fgetc(new_fp)) != EOF) {
            letters_in_group++;
            int position = cipher_char - ASCII;
            ocurrencies[position]++;
            fseek(new_fp, i + (++n * key_len), SEEK_SET);
        }

        printf("\n*****Character %d*****\n", i);

        if (language == 1) {
            printf("\n\nPortuguese: ");
            for (int j = 0; j < 26; j++) {
                printf("|%d [%c]: %f| ", j, letters[j], portuguese_probabilities[j]);
            }
        } else {
            printf("\nEnglish: ");
            for (int j = 0; j < 26; j++) {
                printf("|%d [%c]: %f| ", j, letters[j], english_probabilities[j]);
            }
        }

        printf("\n\nCipher: ");
        for (int j = 0; j < 26; j++) {
            ocurrencies[j] /= letters_in_group;
            printf("|%d [%c]: %f| ", j, letters[j], ocurrencies[j]);
        }

        printf("\n\nEnter the key character: ");
        scanf(" %c", &key[i]);
    }

    key[i] = '\0';

    return key;
}

int main() {
    char option;    // Used in menu.
    char key[30];   // Key for Vigenere cipher.
    
    /*
        original_plainfile: is the unformated plainfile entered by the user.
        formated_plainfile: is the formated plainfile (letters are set to upper case).
        cipherfile: is the cipherfile entered by the user.
    */
    FILE *original_plainfile, *formated_plainfile, *cipherfile;

    // String used to deal with input filename.
    char filename[30];

    do {
        menu(&option);

        switch (option) {
            // Encrypt file case.
            case '1':
                printf("Enter the plaintext filename: ");
                scanf("%s", filename);

                original_plainfile = fopen(filename, "r");
                
                // format_plaintext(FILE*) creates a new file called "formated_input.txt".
                format_plaintext(original_plainfile);

                formated_plainfile = fopen("formated_input.txt", "r");

                printf("Enter the key: ");
                scanf(" %s", key);
                strcpy(key, format_key(key));

                encrypt_file(formated_plainfile, key);

                fclose(original_plainfile);
                fclose(formated_plainfile);

                break;
            
            // Decrypt file case.
            case '2':
                printf("Enter the filename: ");
                scanf("%s", filename);

                cipherfile = fopen(filename, "r");

                printf("Enter the key: ");
                scanf("%s", key);
                strcpy(key, format_key(key));

                decrypt_file(cipherfile, key);

                fclose(cipherfile);

                break;
            
            // Discover key case.
            case '3':
                printf("Enter the filename: ");
                scanf("%s", filename);
                printf("\n");

                cipherfile = fopen(filename, "r");

                strcpy(key, find_key(cipherfile));

                printf("\nDeciphering with key: %s\n", key);
                decrypt_file(cipherfile, key);

                fclose(cipherfile);

                break;
        }
    } while (option != '4');

    return 0;
}
