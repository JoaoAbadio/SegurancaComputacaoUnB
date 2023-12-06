// Compile: gcc rsa.c -lgmp -lcrypto -o rsa

/*
Universidade de Brasília
Instituto de Ciências Exatas
Departamento de Ciência da Computação

CIC0201 - Segurança Computacional - 2023/2
Professor: João Gondim

Aluno: João Vitor Abadio Siqueira
Matricula: 18/0123394

Trabalho de Implementação 3 - Gerador/Verificador de Assinaturas

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <gmp.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define EXIT 3
#define BUFFER_SIZE 1024

int menu() {
    int opcao;

    printf("\n1. Cifracao/Decifracao assimetrica RSA\n");
    printf("2. Assinatura/Verificacao RSA\n");
    printf("3. Sair\n");
    
    scanf("%d", &opcao);
    getchar();

    return opcao;
}

/***** Number theory functions *****/

int miller_rabin_pass(mpz_t a, mpz_t n) {
    int i, s;
    mpz_t a_to_power, d, n_minus_one;
    mpz_init(n_minus_one);
    mpz_sub_ui(n_minus_one, n, 1);
    
    s = 0;
    mpz_init_set(d, n_minus_one);

    while (mpz_even_p(d)) {
        // Divide d by 2 until d is odd.
        mpz_fdiv_q_2exp(d, d, 1);
        s++;
    }

    mpz_init(a_to_power);
    mpz_powm(a_to_power, a, d, n);

    if (mpz_cmp_ui(a_to_power, 1) == 0)  {
        mpz_clear(a_to_power);
        mpz_clear(d);
        mpz_clear(n_minus_one);
        return 1;
    }

    for(i = 0; i < s - 1; i++) {
        if (mpz_cmp(a_to_power, n_minus_one) == 0) {
            mpz_clear(a_to_power);
            mpz_clear(d);
            mpz_clear(n_minus_one);
            return 1;
        }
        mpz_powm_ui(a_to_power, a_to_power, 2, n);
    }
    if (mpz_cmp(a_to_power, n_minus_one) == 0) {
        mpz_clear(a_to_power);
        mpz_clear(d);
        mpz_clear(n_minus_one);
        return 1;
    }

    mpz_clear(a_to_power);
    mpz_clear(d);
    mpz_clear(n_minus_one);

    return 0;
}

int miller_rabin(mpz_t n, gmp_randstate_t rand_state) {
    mpz_t a;
    mpz_init(a);
    for(int i = 0; i < 20; i ++) {
        do {
            mpz_urandomm(a, rand_state, n);
        } while (mpz_sgn(a) == 0);
        if (miller_rabin_pass(a, n) == 0) {
            return 0;
        }
    }
    return 1;
}

void key_generation(mpz_t e, mpz_t d, mpz_t n, gmp_randstate_t state) {
    int prime_size = 1024;

    // Setting p and q, both primes.
    mpz_t p;
    mpz_t q;
    mpz_init(p);
    mpz_init(q);
    mpz_urandomb(p, state, prime_size);
    mpz_urandomb(q, state, prime_size);
    // mpz_set_ui(p, 11);
    // mpz_set_ui(q, 13);

    while(miller_rabin(p, state) != 1) {
        mpz_urandomb(p, state, prime_size);
    }

    while(miller_rabin(q, state) != 1) {
        mpz_urandomb(q, state, prime_size);
    }

    // Calculate n = p*q
    mpz_mul(n, p, q);

    // Calculate phi(n) = (p - 1)*(q - 1)
    mpz_t phi_n, p_minus_one, q_minus_one;
    mpz_init(phi_n);
    mpz_init(p_minus_one);
    mpz_init(q_minus_one);
    mpz_sub_ui(p_minus_one, p, 1);
    mpz_sub_ui(q_minus_one, q, 1);
    mpz_mul(phi_n, p_minus_one, q_minus_one);

    // Select integer e: gcd(phi(n), e) = 1; 1 < e < phi(n)
    mpz_t gcd;
    mpz_init_set_ui(gcd, 0);

    do {
        mpz_urandomm(e, state, phi_n);
        if (mpz_cmp_ui(e, 1) > 0) {
            mpz_gcd(gcd, phi_n, e);
        }
    } while (mpz_cmp_ui(gcd, 1) != 0);

    //mpz_set_ui(e, 23);

    // Calculate d , d is congruent e^(-1) mod(phi(n))
    mpz_invert(d, e, phi_n);

    // Free GMP integers
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(phi_n);
    mpz_clear(p_minus_one);
    mpz_clear(q_minus_one); 
    mpz_clear(gcd);
}

void rsa_encrypt(const mpz_t n, const mpz_t e, const mpz_t m, mpz_t c) {
    if (mpz_cmp(m, n) < 0) {
        mpz_powm(c, m, e, n);
    }

    //gmp_printf("\n\nENCRYPT\n\nn: %Zd\n\ne: %Zd\n\nm: %Zd\n\nc: %Zd\n\n", n, e, m, c);
}

void rsa_decrypt(const mpz_t n, const mpz_t d, const mpz_t c, mpz_t m) {
    mpz_powm(m, c, d, n);

    //gmp_printf("\n\nDECRYPT\n\nn: %Zd\n\nd: %Zd\n\nc: %Zd\n\nm: %Zd\n\n", n, d, c, m);
}

// SHA3-256 functions

void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

// Function from: https://wiki.openssl.org/index.php/EVP_Message_Digests
void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len) {
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha3_256()))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_free(mdctx);
}

// Compare two hashes
int compare_hash(const unsigned char* hash1, const unsigned char* hash2) {
    size_t hash1_len, hash2_len;
    hash1_len = strlen(hash1);
    hash2_len = strlen(hash2);

    if (hash1_len != hash2_len)
        return 0;
    
    for (int i = 0; i < hash1_len; i++) {
        if (hash1[i] != hash2[i])
            return 0;
    }

    return 1;
}

int main() {
    int opcao = 0;

    // Create state to RNG algorithm.
    gmp_randstate_t state;
    // Simple RNG algorithm;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, getpid());

    // Init keys e, d and n.
    mpz_t e, d, n, message, cipher, decrypted;
    mpz_inits(e, d, n, message, cipher, decrypted, NULL);

    key_generation(e, d, n, state);

    char buffer[BUFFER_SIZE];

    while (opcao != EXIT) {
        opcao = menu();

        switch (opcao) {
            // Encrypt/Decrypt RSA
            case 1:
                // Get a message from the user
                printf("\n***Enter a message to encrypt***: ");
                fgets(buffer, BUFFER_SIZE, stdin);
                mpz_set_str(message, buffer, 10);

                // Encrypt the message
                rsa_encrypt(n, e, message, cipher);
                gmp_printf("\n***Encrypted message***: %Zd\n\n", cipher);

                // Decrypt the message
                rsa_decrypt(n, d, cipher, decrypted);
                gmp_printf("***Decrypted message***: %Zd\n\n", decrypted);

                break;
            
            case 2:
                // SHA3_256_LENGTH macro doesn't exist.
                int sha3_256_length = SHA256_DIGEST_LENGTH;
                unsigned char* digest;  

                // Get a message from the user
                printf("\n***Enter a message to hash***: ");
                fgets(buffer, BUFFER_SIZE, stdin);

                // Calculate hash
                digest_message(buffer, strlen(buffer), &digest, &sha3_256_length);
                size_t digest_length = strlen(digest);
                
                printf("\n***Hash***: ");
                for (int i = 0; i < sha3_256_length; i++) {
                    printf("%02x", digest[i]);
                }
                printf("\n");

                // unsigned char must be converted to mpz_t.
                // mpz_import(cipher, digest_length, 1, sizeof(unsigned char), 0, 0, digest);
                mpz_import(message, digest_length, 1, sizeof(unsigned char), 0, 0, digest);

                // rsa_decrypt called first will encrypt with private key.
                // rsa_decrypt(n, d, cipher, message);
                rsa_encrypt(n, e, message, cipher);
                gmp_printf("\n***Hash signature***: %Zd\n", cipher);

                // rsa_encrypt called last will decrypt with public key.
                // rsa_encrypt(n, e, message, cipher);
                rsa_decrypt(n, d, cipher, message);

                // mpz_t must be converted to unsigend char back.
                unsigned char* new_digest = malloc(sizeof(unsigned char) * digest_length);
                mpz_export(new_digest, &digest_length, 1, sizeof(unsigned char), 0, 0, message);
                //gmp_printf("\n***Validation***: %Zd\n\n", message);

                printf("\n***New hash***: ");
                for (int i = 0; i < sha3_256_length; i++) {
                    printf("%02x", new_digest[i]);
                }
                printf("\n");

                if (compare_hash(digest, new_digest)) {
                    printf("\nThe hashes are the same.\n");
                }
                else {
                    printf("\nThe hashes are different.\n");
                }

                free(digest);
                free(new_digest);
        }
    }

    mpz_clears(e, d, n, message, cipher, decrypted, NULL);

    // Free RNG state.
    gmp_randclear(state);

    return 0;
}