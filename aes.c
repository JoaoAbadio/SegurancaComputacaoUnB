/*
Universidade de Brasília
Instituto de Ciências Exatas
Departamento de Ciência da Computação

CIC0201 - Segurança Computacional - 2023/2
Professor: João Gondim

Aluno: João Vitor Abadio Siqueira
Matricula: 18/0123394

Trabalho de Implementação 2 - Cifra de bloco e modo de operação CTR

*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

const unsigned char sbox[] =
    // 0      1     2     3     4     5     6    7      8    9      a     b    c      d    e     f
    { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
      0x60,	0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  // f
    };

const unsigned char invsbox[] =
    // 0     1     2     3      4    5      6    7      8    9     a     b      c    d     e      f
    { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // 0
      0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // 1
      0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // 2
      0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // 3
      0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // 4
      0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // 5
      0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // 6
      0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // 7
      0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // 8
      0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // 9
      0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // a
      0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // b
      0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // c
      0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // d
      0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // e
      0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  // f
    };

const unsigned int r_con[] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

/************** Auxiliar functions **************/

// Prints menu.
int menu() {
    int opcao;

    printf("\n1. Cifrar AES (ECB)\n");
    printf("2. Decifrar AES (ECB)\n");
    printf("3. Cifrar AES (CTR)\n");
    printf("4. Decifrar AES (CTR)\n");
    printf("5. Sair\n");

    scanf("%d", &opcao);

    return opcao;
}

// Prints array.
void print_array(int size, unsigned char* input) {
    for (int i = 0; i < size; i++) {
        printf("%x ", input[i]);
    }
    printf("\n");
}

// Allocates 4x4 matrix.
unsigned char** allocate_martix() {
    unsigned char** matrix;

    matrix = (unsigned char**) calloc(4, sizeof(unsigned char*));
    
    for (int i = 0; i < 4; i++)
        matrix[i] = (unsigned char*) calloc(4, sizeof(unsigned char));

    return matrix;
}

// // Deallocates 4x4 matrix.
void deallocate_matrix(unsigned char** matrix) {
    for (int i = 0; i < 4; i++)
        free(matrix[i]);
    
    free(matrix);
}

// Create the state matrix (4x4 bytes) with the array input (16 bytes).
unsigned char** init_state(unsigned char* input) {
    unsigned char** state = allocate_martix();

    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = input[row + (4 * col)];
        }
    }

    return state;
}

// Create the output array (16 bytes) with the final state matrix (4x4 bytes).
unsigned char* output_array(unsigned char** state) {
    unsigned char* output = (unsigned char*) malloc(sizeof(unsigned char) * 16);

    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            output[row + (4 * col)] = state[row][col];
        }
    }

    return output;
}

// Galois multiplication in GF(2^8)
unsigned char mult_galois(unsigned char a, unsigned char b) {
    unsigned char r = 0;
    unsigned char i = 8;
    
    while(i)
        r = (-(b>>--i & 1) & a) ^ (-(r>>7) & 0x1B) ^ (r+r);
    return r;
}

// Takes a word (4 bytes) as input and output an array of 4 bytes.
unsigned char* extract_bytes(unsigned int word) {
    unsigned char* bytes = (unsigned char*) malloc(sizeof(unsigned char) * 4);

    bytes[0] = word >> 8 * 3;
    bytes[1] = word >> 8 * 2;
    bytes[2] = word >> 8 * 1;
    bytes[3] = word >> 8 * 0;

    return bytes;
}

// Takes 4 bytes as input and output a word (4 bytes).
unsigned int new_word(unsigned char a, unsigned char b, unsigned char c,  unsigned char d) {
    unsigned int word;
    word = a << 8 | b;
    word = word << 8 | c;
    word = word << 8 | d;

    return word;
}

// Rotates the word.
unsigned char* rotword(unsigned char* word) {
    unsigned char* new_word = (unsigned char*) malloc(sizeof(unsigned char) * 4);

    new_word[0] = word[1];
    new_word[1] = word[2];
    new_word[2] = word[3];
    new_word[3] = word[0];

    return new_word;
}

// Uses S-box to substitute bytes of a word.
unsigned char* subword(unsigned char* word) {
    unsigned char* new_word = (unsigned char*) malloc(sizeof(unsigned char) * 4);

    new_word[0] = sbox[word[0]];
    new_word[1] = sbox[word[1]];
    new_word[2] = sbox[word[2]];
    new_word[3] = sbox[word[3]];

    return new_word;
}

/* Gen algorithm */

// Generates a key of bytes using rand().
unsigned char* key_generation() {
    unsigned char* key = (unsigned char*) malloc(sizeof(unsigned char) * 16);
    srand(time(NULL));

    for (int i = 0; i < 16; i++) {
        key[i] = rand() % 256;
    }

    return key;
}

// Expands the key array (16 bytes) to an array of 44 keys.
unsigned int* key_expansion(unsigned char* key) {
    unsigned int* words = (unsigned int*) malloc(sizeof(unsigned int) * 44);
    int i = 0;

    // Copy the original values from key to the expanded key.
    for (i; i < 4; i++) {
        words[i] = new_word(key[4 * i], key[(4 * i) + 1], key[(4 * i) + 2], key[(4 * i) + 3]);
    }

    // Generates the new values from expansion.
    for (i; i < 44; i++) {
        unsigned int temp = words[i - 1];

        if (i % 4 == 0) {
            unsigned char* bytes = (unsigned char*) malloc(sizeof(unsigned char) * 4);

            bytes = extract_bytes(temp);
            bytes = rotword(bytes);
            bytes = subword(bytes);

            temp = new_word(bytes[0], bytes[1], bytes[2], bytes[3]);
            temp ^= r_con[(i / 4) - 1];

            free(bytes);
        }

        words[i] = words[i - 4] ^ temp;
    }

    return words;
}

/* IV algorithms */

// Initialize the IV with random values in the first 12 entries, the last 4 are 0.
unsigned char* iv_init() {
    unsigned char* iv = (unsigned char*) calloc(16, sizeof(unsigned char));
    srand(time(NULL));

    for (int i = 0; i < 12; i++) {
        iv[i] = rand() % 256;
    }

    return iv;
}

// Reset the 4 last entries to 0 of IV.
unsigned char* iv_zeroing(unsigned char* iv) {
    iv[12] = 0;
    iv[13] = 0;
    iv[14] = 0;
    iv[15] = 0;

    return iv;
}

// Increment 1 in the last 4 entries of IV, if the sum overflow, set the values to 0.
unsigned char* iv_next(unsigned char* iv) {
    if (iv[15] < 0xff) {
        iv[15]++;
    }
    else if (iv[14] < 0xff) {
        iv[14]++;
        iv[15] = 0;
    }
    else if (iv[13] < 0xff) {
        iv[13]++;
        iv[14] = 0;
        iv[15] = 0;
    }
    else if (iv[12] < 0xff) {
        iv[12]++;
        iv[13] = 0;
        iv[14] = 0;
        iv[15] = 0;
    }
    else {
        iv = iv_zeroing(iv);
    }

    return iv;
}

/* Enc algorithm (ECB) */

// The XORing of the states with the round key.
unsigned char** add_round_key(int round, unsigned char** state, unsigned int* words) {
    unsigned char* bytes;

    for (int col = 0; col < 4; col++) {
        unsigned int word = new_word(state[0][col], state[1][col], state[2][col], state[3][col]);
        word ^= words[(4 * round) + col];

        bytes = extract_bytes(word);    // Deallocate
        state[0][col] = bytes[0];
        state[1][col] = bytes[1];
        state[2][col] = bytes[2];
        state[3][col] = bytes[3];
    }

    free(bytes);

    return state;
}

// The substituition of bytes using the S-box
unsigned char** sub_bytes(unsigned char** state) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            unsigned char new_value = state[row][col];
            state[row][col] = sbox[new_value];
        }
    }

    return state;
}

// The shift of rows using the equation (col + row) mod 4 to the new col.
unsigned char** shift_rows(unsigned char** state) {
    unsigned char** new_state = allocate_martix();

    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            int new_col = (col + row) % 4;
            new_state[row][col] = state[row][new_col];
        }
    }

    deallocate_matrix(state);

    return new_state;
}

// The mix columns using sum and multiplication in GF(2^8)
unsigned char** mix_columns(unsigned char** state) {
    unsigned char** new_state = allocate_martix();

    unsigned char fixed_matrix[4][4] = 
    {
        { 0x02, 0x03, 0x01, 0x01 },
        { 0x01, 0x02, 0x03, 0x01 },
        { 0x01, 0x01, 0x02, 0x03 },
        { 0x03, 0x01, 0x01, 0x02 }
    };

    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            for (int  k = 0; k < 4; k++) {
                new_state[row][col] ^= mult_galois(fixed_matrix[row][k], state[k][col]);
            }
        }
    }

    deallocate_matrix(state);

    return new_state;
}

// Cipher function of AES.
unsigned char* cipher_ecb(unsigned char* input, int rounds, unsigned int* key) {
    unsigned char** state = init_state(input);
    unsigned char* output;  // Return pointer.

    state = add_round_key(0, state, key);
    int round;

    for (round = 1; round < rounds; round++) {
        state = sub_bytes(state);
        state = shift_rows(state);
        state = mix_columns(state);
        state = add_round_key(round, state, key);
    }

    state = sub_bytes(state);
    state = shift_rows(state);
    state = add_round_key(round, state, key);

    output = output_array(state);
    deallocate_matrix(state);

    return output;
}

/* Dec algorithm (ECB) */

// The inv shift of rows using the equation (col - row) mod 4 to the new col.
unsigned char** inv_shift_rows(unsigned char** state) {
    unsigned char** new_state = allocate_martix();

    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            int new_col = (col - row) % 4;
            if (new_col < 0) {
                new_col += 4;
            }

            new_state[row][col] = state[row][new_col];
        }
    }

    deallocate_matrix(state);

    return new_state;
}

// The substituition of bytes using the inv S-box
unsigned char** inv_sub_bytes(unsigned char** state) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            unsigned char new_value = state[row][col];
            state[row][col] = invsbox[new_value];
        }
    }

    return state;
}

// The mix columns using sum and multiplication in GF(2^8)
unsigned char** inv_mix_columns(unsigned char** state) {
    unsigned char** new_state = allocate_martix();

    unsigned char fixed_matrix[4][4] = 
    {
        { 0x0e, 0x0b, 0x0d, 0x09 },
        { 0x09, 0x0e, 0x0b, 0x0d },
        { 0x0d, 0x09, 0x0e, 0x0b },
        { 0x0b, 0x0d, 0x09, 0x0e }
    };

    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            for (int  k = 0; k < 4; k++) {
                new_state[row][col] ^= mult_galois(fixed_matrix[row][k], state[k][col]);
            }
        }
    }

    deallocate_matrix(state);

    return new_state;
}

// Inv cipher function of AES.
unsigned char* inv_cipher_ecb(unsigned char* input, int rounds, unsigned int* key) {
    unsigned char** state = init_state(input);
    unsigned char* output;

    state = add_round_key(rounds, state, key);
    int round;

    for (round = rounds - 1; round > 0; round--) {
        state = inv_shift_rows(state);
        state = inv_sub_bytes(state);
        state = add_round_key(round, state, key);
        state = inv_mix_columns(state);
    }

    state = inv_shift_rows(state);
    state = inv_sub_bytes(state);
    state = add_round_key(round, state, key);

    output = output_array(state);
    deallocate_matrix(state);

    return output;
}

/* Enc/Dec algorithm (CTR) */

// The cipher and inv cipher of AES in CTR mode
unsigned char* cipher_ctr(unsigned char* input, int rounds, unsigned int* key, unsigned char* iv) {
    unsigned char* output = cipher_ecb(iv, rounds, key);
    iv = iv_next(iv);
    
    for (int i = 0; i < 16; i++) {
        output[i] ^= input[i];
    }

    return output;
}

int main() {
    int option; // Menu option

    FILE* fp1;  // Read mode file
    FILE* fp2;  // Write mode file

    unsigned char* output;  // Points to the result of cipher or inv_cipher.
    unsigned char* key;     // Key generated with rand()
    unsigned int* expanded_key;
    unsigned char* iv;
    char filename[30];
    int rounds;

    key = key_generation();             // Deallocate
    expanded_key = key_expansion(key);  // Deallocate
    iv = iv_init();                     // Deallocate

    while( (option = menu()) != 5) {
        iv = iv_zeroing(iv);

        switch(option) {
            // Cifrar AES (ECB)
            case 1:
                // Open the read file
                printf("\nEnter plain file name: ");
                scanf(" %s", filename);
                fp1 = fopen(filename, "rb");

                if (fp1 == NULL) {
                    perror("");
                    exit(-1);
                }

                // Open the write file
                printf("Enter cipher file name: ");
                scanf(" %s", filename);
                fp2 = fopen(filename, "wb");

                if (fp2 == NULL) {
                    perror("");
                    exit(-1);
                }

                printf("Enter how many rounds you want (1 ~ 10): ");
                scanf("%d", &rounds);

                // Set file size
                fseek(fp1, 0L, SEEK_END);
                long int file_size = ftell(fp1);
                rewind(fp1);

                while (1) {
                    // Padding input with 0's
                    unsigned char buffer[16] = {0};

                    // Reads blocks of 16 bytes to buffer.
                    if (fread(buffer, sizeof(buffer), 1, fp1) != 0) {
                        output = cipher_ecb(buffer, rounds, expanded_key);

                        // Writes the output into file.
                        fwrite(output, sizeof(buffer), 1, fp2);

                        if (file_size == ftell(fp1)) {
                            // If this break doesn't exist, the else will always be executed.
                            // Even if the file is already at the end after the first fread.
                            break;
                        }
                    }
                    else {
                        output = cipher_ecb(buffer, rounds, expanded_key);
                        fwrite(output, sizeof(buffer), 1, fp2);

                        break;
                    }
                }

                printf("\n[KEY]: ");
                print_array(16, key);

                free(output);
                fclose(fp1);
                fclose(fp2);

                break;
            
            // Decifrar AES (ECB)
            case 2:
                // Open the read file.
                printf("\nEnter cipher file name: ");
                scanf(" %s", filename);
                fp1 = fopen(filename, "rb");

                // Check file.
                if (fp1 == NULL) {
                    perror("");
                    exit(-1);
                }

                // Open the write file.
                printf("Enter cipher file name: ");
                scanf("%s", filename);
                fp2 = fopen(filename, "wb");

                // Check file.
                if (fp2 == NULL) {
                    perror("");
                    exit(-1);
                }

                printf("Enter how many rounds you want (1 ~ 10): ");
                scanf("%d", &rounds);

                while (1) {
                    // Padding input with 0's
                    unsigned char buffer[16] = {0};

                    // Reads blocks of 16 bytes to buffer.
                    if (fread(buffer, sizeof(buffer), 1, fp1) != 0) {
                        output = inv_cipher_ecb(buffer, rounds, expanded_key);
                        // Writes the output into file.
                        fwrite(output, sizeof(buffer), 1, fp2);
                    }
                    else {
                        break;
                    }
                }

                printf("\n[KEY]: ");
                print_array(16, key);

                free(output);
                fclose(fp1);
                fclose(fp2);

                break;

            // Cifrar AES (CTR)
            case 3:
                printf("\nEnter plain file name: ");
                scanf(" %s", filename);
                fp1 = fopen(filename, "rb");

                if (fp1 == NULL) {
                    perror("");
                    exit(-1);
                }

                printf("Enter cipher file name: ");
                scanf(" %s", filename);
                fp2 = fopen(filename, "wb");

                if (fp2 == NULL) {
                    perror("");
                    exit(-1);
                }

                printf("Enter how many rounds you want (1 ~ 10): ");
                scanf("%d", &rounds);

                while (1) {
                    // Padding input with 0's
                    unsigned char buffer[16] = {0};
                    if (fread(buffer, sizeof(buffer), 1, fp1) != 0) {
                        output = cipher_ctr(buffer, rounds, expanded_key, iv);

                        fwrite(output, sizeof(buffer), 1, fp2);

                        if (file_size == ftell(fp1)) {
                            break;
                        }
                    }
                    else {
                        output = cipher_ctr(buffer, rounds, expanded_key, iv);

                        fwrite(output, sizeof(buffer), 1, fp2);
                        break;
                    }
                }

                printf("\n[KEY]: ");
                print_array(16, key);
                printf("[IV]: ");
                print_array(16, iv);

                free(output);
                fclose(fp1);
                fclose(fp2);

                break;
            
            // Decifrar AES (CTR)
            case 4:
                printf("\nEnter cipher file name: ");
                scanf(" %s", filename);
                fp1 = fopen(filename, "rb");

                if (fp1 == NULL) {
                    perror("");
                    exit(-1);
                }

                printf("Enter plain file name: ");
                scanf("%s", filename);
                fp2 = fopen(filename, "wb");

                if (fp2 == NULL) {
                    perror("");
                    exit(-1);
                }

                printf("Enter how many rounds you want (1 ~ 10): ");
                scanf("%d", &rounds);

                while (1) {
                    // Padding input with 0's
                    unsigned char buffer[16] = {0};
                    if (fread(buffer, sizeof(buffer), 1, fp1) != 0) {
                        output = cipher_ctr(buffer, rounds, expanded_key, iv);
                        fwrite(output, sizeof(buffer), 1, fp2);
                    }
                    else {
                        break;
                    }
                }

                printf("\n[KEY]: ");
                print_array(16, key);
                printf("[IV]: ");
                print_array(16, iv);

                free(output);
                fclose(fp1);
                fclose(fp2);

                break;
        }
    }

    free(key);
    free(expanded_key);
    free(iv);

    return 0;
}