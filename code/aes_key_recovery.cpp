// Required: C++11, OpenSSL
// Compile with: g++ -std=c++11 -O2 -o aes_key_recovery aes_key_recovery.cpp -lcrypto -maes

#include <iostream>
#include <string>
#include <cstring>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <math.h> // log2(.)
#include <wmmintrin.h> // SSE, AES

typedef unsigned char uchar;
typedef unsigned long uint32;

// S-box
const uchar s_box[256] = {
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// S-box inverse
const uchar s_box_inv[256] = {
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

std::string to_string(void* source, uint32 num_bytes) {
  uchar* pointer = (uchar*)source;
  std::ostringstream string_stream;
  for(uint32 i = 0; i < num_bytes; i++) {
    string_stream << std::setfill('0') << std::setw(2) << std::hex << (uint32)(pointer[num_bytes - i - 1]);
  }
  std::string ret_string = string_stream.str();
  return ret_string;
}

uint32 get_bit(uchar* val, uint32 position) {
  uint32 bit = (*val >> position) & 0x1;
  return bit;
}

void set_bit(uchar* val, uint32 position, uint32 bit) {
  uchar new_bit = !!bit; // Force 0 or 1
  uchar mask = 0x1;
  *val ^= (-new_bit ^ *val) & (mask << position);
}

uchar mul_x(uchar val) {
  if((val & 0x80) == 0) {
    return (val << 1);
  }
  else {
    return ((val << 1) ^ 0x1B);
  }
}

uchar mul_x_n(uchar val, uint32 n) {
  for(uint32 i = 0; i < n; i++) {
    val = mul_x(val);
  }
  return val;
}

// AES
void aes_print_data(uchar* data) {
  uchar (*data_matrix)[4] = (uchar (*)[4]) data;
  for(uint32 i = 0; i < 4; i++) {
    for(uint32 j = 0; j < 4; j++) {
      std::cout << to_string(&(data_matrix[i][j]), 1) << "   ";
    }
    std::cout << std::endl;
  }
}

void generate_new_round_key(uchar* key, uint32 round_num) {
  // Cast pointer to 4x4 matrix
  uchar (*matrix_key)[4] = (uchar (*)[4]) key;

  // Round constant (optimized for speed! assuming < 8 rounds are used, reductions are never required here!)
  uchar round_constant_part = 0x1 << round_num;

  // Generate new key from old one (assuming only 128-bit keys are used, and that the first key is already generated)
  uchar temp[4] = { 0 };

  // Rotation, substitution, and constant addition for last key column
  temp[0] = s_box[matrix_key[1][3]] ^ round_constant_part;
  temp[1] = s_box[matrix_key[2][3]];
  temp[2] = s_box[matrix_key[3][3]];
  temp[3] = s_box[matrix_key[0][3]];

  // Column 1
  matrix_key[0][0] = matrix_key[0][0] ^ temp[0];
  matrix_key[1][0] = matrix_key[1][0] ^ temp[1];
  matrix_key[2][0] = matrix_key[2][0] ^ temp[2];
  matrix_key[3][0] = matrix_key[3][0] ^ temp[3];

  // Columns 2-4
  for(uint32 i = 1; i < 4; i++) {
    matrix_key[0][i] = matrix_key[0][i] ^ matrix_key[0][i - 1];
    matrix_key[1][i] = matrix_key[1][i] ^ matrix_key[1][i - 1];
    matrix_key[2][i] = matrix_key[2][i] ^ matrix_key[2][i - 1];
    matrix_key[3][i] = matrix_key[3][i] ^ matrix_key[3][i - 1];
  }

  //std::cout << "New round key [1]:" << std::endl;
  //aes_print_data(key);
}

void add_round_key(uchar* state, uchar* key) {
  for(uint32 i = 0; i < 16; i++) {
    state[i] ^= key[i];
  }
}

void byte_substitution(uchar* state) {
  for(uint32 i = 0; i < 16; i++) {
    state[i] = s_box[state[i]];
  }
}

void byte_substitution_inv(uchar* state) {
  for(uint32 i = 0; i < 16; i++) {
    state[i] = s_box_inv[state[i]];
  }
}

void shift_rows(uchar* state){
  uchar tmp = 0;
  uchar tmp_buf[2] = { 0 };

  // Row 2
  tmp = state[4];
  memcpy(&(state[4]), &(state[5]), 3 * sizeof(uchar));
  state[7] = tmp;

  // Row 3 (this could be replaced by XOR swapping using two XORs with 16-bit casts)
  memcpy(tmp_buf, &(state[8]), 2 * sizeof(uchar));
  memcpy(&(state[8]), &(state[10]), 2 * sizeof(uchar));
  memcpy(&(state[10]), tmp_buf, 2 * sizeof(uchar));

  // Row 4
  tmp = state[15];
  state[15] = state[14];
  state[14] = state[13];
  state[13] = state[12];
  state[12] = tmp;
}

void shift_rows_inverse(uchar* state) {
  uchar tmp = 0;
  uchar tmp_buf[2] = { 0 };

  // Row 2
  tmp = state[7];
  // state[7] = state[6];
  // state[6] = state[5];
  // state[5] = state[4];
  // state[4] = tmp;
  memmove(&(state[5]), &(state[4]), 3 * sizeof(uchar));
  state[4] = tmp;

  // Row 3 (this could be replaced by XOR swapping using two XORs with 16-bit casts)
  memcpy(tmp_buf, &(state[10]), 2 * sizeof(uchar));
  memcpy(&(state[10]), &(state[8]), 2 * sizeof(uchar));
  memcpy(&(state[8]), tmp_buf, 2 * sizeof(uchar));

  // Row 4
  tmp = state[12];
  state[12] = state[13];
  state[13] = state[14];
  state[14] = state[15];
  state[15] = tmp;
}

void mix_columns(uchar* state){
  
  // Cast pointer to 4x4 matrix
  uchar (*matrix_state)[4] = (uchar (*)[4]) state;

  // Temp
  uchar temp[4][4] = { 0 };

  for(uint32 i = 0; i < 4; i++) {
    temp[0][i] = mul_x(matrix_state[0][i]) ^ (mul_x(matrix_state[1][i]) ^ matrix_state[1][i]) ^ matrix_state[2][i] ^ matrix_state[3][i];
    temp[1][i] = matrix_state[0][i] ^ mul_x(matrix_state[1][i]) ^ (mul_x(matrix_state[2][i]) ^ matrix_state[2][i]) ^ matrix_state[3][i];
    temp[2][i] = matrix_state[0][i] ^ matrix_state[1][i] ^ mul_x(matrix_state[2][i]) ^ (mul_x(matrix_state[3][i]) ^ matrix_state[3][i]);
    temp[3][i] = (mul_x(matrix_state[0][i]) ^ matrix_state[0][i]) ^ matrix_state[1][i] ^ matrix_state[2][i] ^ mul_x(matrix_state[3][i]);
  }

  // Copy to state
  memcpy(state, temp, 16 * sizeof(uchar));
}

// Maybe still a bug in there...
void mix_columns_inverse(uchar* state){
  
  // Cast pointer to 4x4 matrix
  uchar (*matrix_state)[4] = (uchar (*)[4]) state;

  // Temp
  uchar temp[4][4] = { 0 };

  for(uint32 i = 0; i < 4; i++) {
    temp[0][i] = mul_x_n(matrix_state[0][i], 3) ^ mul_x_n(matrix_state[0][i], 2) ^ mul_x(matrix_state[0][i]) ^
      mul_x_n(matrix_state[1][i], 3) ^ mul_x(matrix_state[1][i]) ^ matrix_state[1][i] ^ mul_x_n(matrix_state[2][i], 3) ^
      mul_x_n(matrix_state[2][i], 2) ^ matrix_state[2][i] ^ mul_x_n(matrix_state[3][i], 3) ^ matrix_state[3][i];

    temp[1][i] = mul_x_n(matrix_state[0][i], 3) ^ matrix_state[0][i] ^ mul_x_n(matrix_state[1][i], 3) ^ mul_x_n(matrix_state[1][i], 2) ^
      mul_x(matrix_state[1][i]) ^ mul_x_n(matrix_state[2][i], 3) ^ mul_x(matrix_state[2][i]) ^ matrix_state[2][i] ^
      mul_x_n(matrix_state[3][i], 3) ^ mul_x_n(matrix_state[3][i], 2) ^ matrix_state[3][i];

    temp[2][i] = mul_x_n(matrix_state[0][i], 3) ^ mul_x_n(matrix_state[0][i], 2) ^ matrix_state[0][i] ^ mul_x_n(matrix_state[1][i], 3) ^
      matrix_state[1][i] ^ mul_x_n(matrix_state[2][i], 3) ^ mul_x_n(matrix_state[2][i], 2) ^ mul_x(matrix_state[2][i]) ^
      mul_x_n(matrix_state[3][i], 3) ^ mul_x(matrix_state[3][i]) ^ matrix_state[3][i];

    temp[3][i] = mul_x_n(matrix_state[0][i], 3)^ mul_x(matrix_state[0][i]) ^ matrix_state[0][i] ^ mul_x_n(matrix_state[1][i], 3) ^
      mul_x_n(matrix_state[1][i], 2) ^ matrix_state[1][i] ^ mul_x_n(matrix_state[2][i], 3)^matrix_state[2][i] ^ mul_x_n(matrix_state[3][i], 3) ^
      mul_x_n(matrix_state[3][i], 2) ^ mul_x(matrix_state[3][i]);
  }

  // Copy to state
  memcpy(state, temp, 16 * sizeof(uchar));
}

void mix_columns_inverse_column(uchar* column) {
  uchar temp[4] = { 0 };
  temp[0] = mul_x_n(column[0], 3) ^ mul_x_n(column[0], 2) ^ mul_x(column[0]) ^
    mul_x_n(column[1], 3) ^ mul_x(column[1]) ^ column[1] ^ mul_x_n(column[2], 3) ^
    mul_x_n(column[2], 2) ^ column[2] ^ mul_x_n(column[3], 3) ^ column[3];

  temp[1] = mul_x_n(column[0], 3) ^ column[0] ^ mul_x_n(column[1], 3) ^ mul_x_n(column[1], 2) ^
    mul_x(column[1]) ^ mul_x_n(column[2], 3) ^ mul_x(column[2]) ^ column[2] ^
    mul_x_n(column[3], 3) ^ mul_x_n(column[3], 2) ^ column[3];

  temp[2] = mul_x_n(column[0], 3) ^ mul_x_n(column[0], 2) ^ column[0] ^ mul_x_n(column[1], 3) ^
    column[1] ^ mul_x_n(column[2], 3) ^ mul_x_n(column[2], 2) ^ mul_x(column[2]) ^
    mul_x_n(column[3], 3) ^ mul_x(column[3]) ^ column[3];

  temp[3] = mul_x_n(column[0], 3)^ mul_x(column[0]) ^ column[0] ^ mul_x_n(column[1], 3) ^
    mul_x_n(column[1], 2) ^ column[1] ^ mul_x_n(column[2], 3)^column[2] ^ mul_x_n(column[3], 3) ^
    mul_x_n(column[3], 2) ^ mul_x(column[3]);

  memcpy(column, temp, 4 * sizeof(uchar));
}

void aes_round_instruction(uchar* state, uchar* key) {
  __m128i* state_ptr = (__m128i*)state;
  __m128i* key_ptr = (__m128i*)key;
  *state_ptr = _mm_aesenc_si128(*state_ptr, *key_ptr);
}

void aes_mix_columns_inverse_two_columns_instruction(uchar* columns) {
  uchar temp[16] = { 0 };
  memcpy(temp, columns, 8 * sizeof(uchar));
  __m128i* temp_ptr = (__m128i*)temp;
  *temp_ptr = _mm_aesimc_si128(*temp_ptr);
  memcpy(columns, temp, 8 * sizeof(uchar));
}

// Use < 8 rounds!
int aes_encryption(uchar* plaintext, uchar* ciphertext, uchar* key, uint32 num_rounds) {

  uchar state[16];
  memcpy(state, plaintext, 16 * sizeof(uchar));
  uchar key_temp[16];
  memcpy(key_temp, key, 16 * sizeof(uchar));
  
  // Whitening
  add_round_key(state, key_temp);

  // Run rounds
  for(uint32 i = 0; i < num_rounds - 1; i++) {
    generate_new_round_key(key_temp, i);
    byte_substitution(state);
    shift_rows(state);
    // std::cout << "Before mix columns [1]:" << std::endl;
    // aes_print_data(state);
    // if(i < (num_rounds - 2) && num_rounds != 4) {
    //   mix_columns(state);
    //   // std::cout << "After mix columns [1]:" << std::endl;
    //   // aes_print_data(state);
    //   add_round_key(state, key_temp);
    // }
    // else {
    //   add_round_key(state, key_temp);
    //   mix_columns(state);
    // }
    mix_columns(state);
    add_round_key(state, key_temp);
    
    //aes_round_instruction(state, key_temp);
  }

  // Final round
  generate_new_round_key(key_temp, num_rounds - 1);
  byte_substitution(state);
  shift_rows(state);
  add_round_key(state, key_temp);

  // Write ciphertext
  memcpy(ciphertext, state, 16 * sizeof(uchar));
}

void key_recovery_3_rounds() {
  // Init key
  uchar key[16];
  RAND_bytes(key, 16);
  //memset(key, 0x0, 16); // Test with zero key

  // Init plaintexts
  uchar z_1 = 0xAB;
  uchar z_2 = 0xCD;
  uchar w_1 = 0x12;
  uchar w_2 = 0x34;
  uchar pt_1[16] = { z_1, 0, 0, 0, w_1 };
  uchar pt_2[16] = { z_2, 0, 0, 0, w_2 };
  uchar pt_3[16] = { z_1, 0, 0, 0, w_2 };
  uchar pt_4[16] = { z_2, 0, 0, 0, w_1 };

  // Print plaintexts
  // std::cout << "Plaintext 1:" << std::endl;
  // aes_print_data(pt_1);

  // std::cout << "Plaintext 2:" << std::endl;
  // aes_print_data(pt_2);

  // std::cout << "Plaintext 3:" << std::endl;
  // aes_print_data(pt_3);

  // std::cout << "Plaintext 4:" << std::endl;
  // aes_print_data(pt_4);

  // Get corresponding ciphertexts
  uchar ct_1[16] = { 0 };
  uchar ct_2[16] = { 0 };
  uchar ct_3[16] = { 0 };
  uchar ct_4[16] = { 0 };
  aes_encryption(pt_1, ct_1, key, 3);
  aes_encryption(pt_2, ct_2, key, 3);
  aes_encryption(pt_3, ct_3, key, 3);
  aes_encryption(pt_4, ct_4, key, 3);

  // Print ciphertexts
  // std::cout << "Ciphertext 1:" << std::endl;
  // aes_print_data(ct_1);

  // std::cout << "Ciphertext 2:" << std::endl;
  // aes_print_data(ct_2);

  // std::cout << "Ciphertext 3:" << std::endl;
  // aes_print_data(ct_3);

  // std::cout << "Ciphertext 4:" << std::endl;
  // aes_print_data(ct_4);

  // Pointers for easier access
  uchar (*matrix_ct_1)[4] = (uchar (*)[4]) ct_1;
  uchar (*matrix_ct_2)[4] = (uchar (*)[4]) ct_2;
  uchar (*matrix_ct_3)[4] = (uchar (*)[4]) ct_3;
  uchar (*matrix_ct_4)[4] = (uchar (*)[4]) ct_4;

  // Test property (key verification not yet implemented, this test finds the correct key with high probability)
  uchar test_val = 0;
  uchar key_guessed[16] = { 0 };
  uchar (*matrix_key_guessed)[4] = (uchar (*)[4]) key_guessed;
  for(uint32 i = 0; i < 4; i++) {
    for(uint32 j = 0; j < 4; j++) {
      for(uint32 k = 0; k <= 0xFF; k++) {
        test_val = s_box_inv[matrix_ct_1[i][j] ^ k] ^ s_box_inv[matrix_ct_2[i][j] ^ k] ^ s_box_inv[matrix_ct_3[i][j] ^ k] ^ s_box_inv[matrix_ct_4[i][j] ^ k];
        if(test_val == 0) {
          std::cout << "Candidate for [" << i << "][" << j << "]: " << to_string(&k, 1) << std::endl;
          matrix_key_guessed[i][j] = k;
        }
      }
      //exit(1);
    }
  }

  // Print correct last round key
  uchar key_temp[16];
  memcpy(key_temp, key, 16 * sizeof(uchar));
  for(uint32 i = 0; i < 3; i++) {
    generate_new_round_key(key_temp, i);
  }
  std::cout << "Correct last round key:" << std::endl;
  aes_print_data(key_temp);

  // Print guessed last round key
  std::cout << "Guessed last round key:" << std::endl;
  aes_print_data(key_guessed);
}

// Remark: This attack requires too much time to test quickly on full AES!
// -> Use small-scale version of AES ("Small Scale Variants of the AES")
void key_recovery_4_rounds() {
  // Init key
  uchar key[16];
  RAND_bytes(key, 16);
  //memset(key, 0x0, 16); // Test with zero key

  // Init plaintexts
  uint32 num_text_sets = 24;
  uchar pt[num_text_sets][2][16];
  memset(pt, 0x0, num_text_sets * 2 * 16 * sizeof(uchar));

  uchar x_1 = 0xAB;
  uchar x_2 = 0xCD;
  uchar y_1 = 0x12;
  uchar y_2 = 0x34;
  uchar byte_active = 0x00;

  for(uint32 i = 0; i < num_text_sets; i++) {
    pt[i][0][0] = x_1;
    pt[i][0][4] = y_1;
    pt[i][0][8] = byte_active;
    pt[i][0][12] = 0;
    pt[i][1][0] = x_2;
    pt[i][1][4] = y_2;
    pt[i][1][8] = byte_active;
    pt[i][1][12] = 0;
    byte_active++;
  }

  // Get corresponding ciphertexts
  uchar ct[num_text_sets][2][16];
  memset(ct, 0x0, num_text_sets * 2 * 16 * sizeof(uchar));
  for(uint32 i = 0; i < num_text_sets; i++) {
    aes_encryption(pt[i][0], ct[i][0], key, 4);
    aes_encryption(pt[i][1], ct[i][1], key, 4);
  }

  // Prepare data for partial decryptions
  uchar partial_decryptions[num_text_sets][8]; // 2*4 bytes for key guesses
  memset(partial_decryptions, 0x0, num_text_sets * 2 * sizeof(uchar));

  // Test property (distinguisher)
  /*
  for(uint32 m = 0; m < num_text_sets; m++) {
    for(uint32 n = m + 1; n < num_text_sets; n++) {
      for(uint32 i = 0; i < 4; i++) {
        for(uint32 j = 0; j < 4; j++) {
          uint32 ij_element_index = (i * 4) + j;
          uchar a = ct[m][0][ij_element_index];
          uchar b = ct[m][1][ij_element_index];
          uchar c = ct[n][0][ij_element_index];
          uchar d = ct[n][1][ij_element_index];
          if((((a ^ b) == 0) && ((c ^ d) != 0)) ||
            (((a ^ c) == 0) && ((b ^ d) != 0)) ||
            (((a ^ d) == 0) && ((b ^ c) != 0)) ||
            (((b ^ c) == 0) && ((a ^ d) != 0)) ||
            (((b ^ d) == 0) && ((a ^ c) != 0)) ||
            (((c ^ d) == 0) && ((a ^ b) != 0))) {
            std::cout << "RANDOM!" << std::endl;
            exit(1);
          }
        }
      }
    }
  }
  std::cout << "AES!" << std::endl;
  exit(1);
  */
  
  // Attack
  // Remark: This attack finds only candidates for one anti diagonal! Same procedure needs to be run four times (+ verification) to find the last round key.
  uchar key_guessed[16] = { 0 };
  uchar (*matrix_key_guessed)[4] = (uchar (*)[4]) key_guessed;
  uint32 flag = 0;
  uchar a, b, c, d;
  uchar key_guess[4] = { 0 };
  //for(uint32 i = 0; i < 4; i++) {
  for(uint32 k = 0; k <= 0xFFFFFFFF; k++) { // Guess 32 bits of key (column)
    //if(k % 0xFFFFF == 0) std::cout << k << " keys tried..." << std::endl;
    key_guess[0] = k & 0xFF;
    key_guess[1] = (k >> 8) & 0xFF;
    key_guess[2] = (k >> 16) & 0xFF;
    key_guess[3] = k >> 24;
    // Partially decrypt all prepared texts using current key byte guess
    for(uint32 t = 0; t < num_text_sets; t++) {
      uchar (*ct_0_matrix)[4] = (uchar (*)[4]) ct[t][0];
      uchar (*ct_1_matrix)[4] = (uchar (*)[4]) ct[t][1];
      
      // Text 1
      partial_decryptions[t][0] = s_box_inv[ct_0_matrix[0][0] ^ key_guess[0]];
      partial_decryptions[t][3] = s_box_inv[ct_0_matrix[3][1] ^ key_guess[1]];
      partial_decryptions[t][2] = s_box_inv[ct_0_matrix[2][2] ^ key_guess[2]];
      partial_decryptions[t][1] = s_box_inv[ct_0_matrix[1][3] ^ key_guess[3]];

      // Text 2
      partial_decryptions[t][4] = s_box_inv[ct_1_matrix[0][0] ^ key_guess[0]];
      partial_decryptions[t][7] = s_box_inv[ct_1_matrix[3][1] ^ key_guess[1]];
      partial_decryptions[t][6] = s_box_inv[ct_1_matrix[2][2] ^ key_guess[2]];
      partial_decryptions[t][5] = s_box_inv[ct_1_matrix[1][3] ^ key_guess[3]];

      // Inverse mix columns for both columns
      //std::cout << (uint32)partial_decryptions[t][0] << " " << (uint32)partial_decryptions[t][1] << " " << (uint32)partial_decryptions[t][2] << " " << (uint32)partial_decryptions[t][3] << std::endl;
      //std::cout << (uint32)partial_decryptions[t][4] << " " << (uint32)partial_decryptions[t][5] << " " << (uint32)partial_decryptions[t][6] << " " << (uint32)partial_decryptions[t][7] << std::endl;
      //mix_columns_inverse_column(&(partial_decryptions[t][0]));
      aes_mix_columns_inverse_two_columns_instruction(&(partial_decryptions[t][0]));
      //mix_columns_inverse_column(&(partial_decryptions[t][4]));
      //std::cout << (uint32)partial_decryptions[t][0] << " " << (uint32)partial_decryptions[t][1] << " " << (uint32)partial_decryptions[t][2] << " " << (uint32)partial_decryptions[t][3] << std::endl;
      //std::cout << (uint32)partial_decryptions[t][4] << " " << (uint32)partial_decryptions[t][5] << " " << (uint32)partial_decryptions[t][6] << " " << (uint32)partial_decryptions[t][7] << std::endl;
      //exit(1);
    }
    flag = 0;
    
    for(uint32 m = 0; m < num_text_sets; m++) {
      for(uint32 n = m + 1; n < num_text_sets; n++) {
        // The property cannot be fulfilled if the input plaintexts are all different!
        // Test for four indices
        for(uint32 l = 0; l < 4; l++) {
          a = partial_decryptions[m][l];
          b = partial_decryptions[m][l + 4];
          c = partial_decryptions[n][l];
          d = partial_decryptions[n][l + 4];

          if((((a ^ b) == 0) && ((c ^ d) != 0)) ||
            (((a ^ c) == 0) && ((b ^ d) != 0)) ||
            (((a ^ d) == 0) && ((b ^ c) != 0)) ||
            (((b ^ c) == 0) && ((a ^ d) != 0)) ||
            (((b ^ d) == 0) && ((a ^ c) != 0)) ||
            (((c ^ d) == 0) && ((a ^ b) != 0))) {
            flag = 1;
            break;
          }
        }
        if(flag == 1) {
          goto endloop;
        }
      }
    }
    
    if(flag == 0) {
      std::cout << "Candidate for k: " << to_string(&k, 4) << std::endl;
    }

  endloop:
    continue;
  }
  //}

  // Print correct last round key
  uchar key_temp[16];
  memcpy(key_temp, key, 16 * sizeof(uchar));
  for(uint32 i = 0; i < 4; i++) {
    generate_new_round_key(key_temp, i);
  }
  std::cout << "Correct last round key (check entry (0,0) with LS bytes of the candidates -> diagonal rotated one to the right):" << std::endl;
  aes_print_data(key_temp);

  // Print guessed last round key
  /*
  std::cout << "Guessed last round key:" << std::endl;
  aes_print_data(key_guessed);
  */
}

int main(int argc, char** argv) {

  // Test AES
  /*
  uchar pt[16] = { 0 };
  uchar key[16] = { 0 };
  uchar ct[16] = { 0 };
  //RAND_bytes(pt, 16);
  //RAND_bytes(key, 16);
  aes_encryption(pt, ct, key, 8);

  std::cout << "Result:" << std::endl;
  aes_print_data(ct);

  exit(1);
  */

  std::cout << "Testing 3-round key recovery..." << std::endl;
  key_recovery_3_rounds();

  std::cout << "Testing 4-round key recovery..." << std::endl;
  key_recovery_4_rounds();


  std::cout << "Finished" << std::endl;

  return 0;
}
