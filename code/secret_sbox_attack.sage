import copy
import operator
import random

#K.<a> = GF(2**8, name='a', modulus=x**8 + x**4 + x**3 + x + 1)
P.<y> = PolynomialRing(GF(2))
f = y**8 + y**4 + y**3 + y + 1 # Rijndael Polynomial
K.<x> = GF(2**8, modulus=f)

s_box = [
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
]

s_box_inv = [
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
]

def rotate(l, n):
    return l[n:] + l[:n]

def invert_sbox(sbox):
    sbox_inv = [0] * 256
    for i in range(0, 256):
        sbox_inv[sbox[i]] = i
    return sbox_inv
    
def gf_state_to_int(state):
    int_num = 0
    for i in range(0, 4):
        for j in range(0, 4):
            element_gf = state[j][i]
            int_num |= element_gf.integer_representation() << (((i * 4) + j) * 8)
    return int_num

def int_to_gf_state(int_num):
    #print hex(int_num)
    state = [[], [], [], []]
    for i in range(0, 4):
        for j in range(0, 4):
            element_int = (int_num >> (((i * 4) + j)) * 8) & 0xFF
            gf_num = K.fetch_int(element_int)
            state[j].append(gf_num)
    #print [hex(k.integer_representation()) for k in state[0]]
    #print [hex(k.integer_representation()) for k in state[1]]
    #print [hex(k.integer_representation()) for k in state[2]]
    #print [hex(k.integer_representation()) for k in state[3]]
    #exit()
    return state

def add_round_key(state, key):
    for i in range(0, 4):
        for j in range(0, 4):
            state[i][j] += key[i][j]

def byte_substitution(state, sbox):
    for i in range(0, 4):
        for j in range(0, 4):
            state[i][j] = K.fetch_int(sbox[state[i][j].integer_representation()])

def byte_substitution_inv(state):
    for i in range(0, 4):
        for j in range(0, 4):
            state[i][j] = K.fetch_int(s_box_inv[state[i][j].integer_representation()])

def shift_rows(state):
    state[1] = rotate(state[1], 1)
    state[2] = rotate(state[2], 2)
    state[3] = rotate(state[3], 3)

def shift_rows_inverse(state):
    state[1] = rotate(state[1], -1)
    state[2] = rotate(state[2], -2)
    state[3] = rotate(state[3], -3)

def mix_columns(state):
    state_matrix = matrix(state)
    mds_matrix_row_0 = [K.fetch_int(2), K.fetch_int(3), K.fetch_int(1), K.fetch_int(1)]
    mds_matrix = matrix([mds_matrix_row_0, rotate(mds_matrix_row_0, -1), rotate(mds_matrix_row_0, -2), rotate(mds_matrix_row_0, -3)])
    res = mds_matrix * state_matrix
    for i in range(0, 4):
        for j in range(0, 4):
            state[i][j] = res[i][j]
    
def mix_columns_inverse(state):
    state_matrix = matrix(state)
    mds_matrix_row_0 = [K.fetch_int(2), K.fetch_int(3), K.fetch_int(1), K.fetch_int(1)]
    mds_matrix = matrix([mds_matrix_row_0, rotate(mds_matrix_row_0, -1), rotate(mds_matrix_row_0, -2), rotate(mds_matrix_row_0, -3)])
    mds_matrix_inverse = mds_matrix.inverse()
    res = mds_matrix_inverse * state_matrix
    for i in range(0, 4):
        for j in range(0, 4):
            state[i][j] = res[i][j]
    
def generate_new_round_key(key, round_num):
    round_constant_part = x**(round_num - 1)
    temp = [0, 0, 0, 0]
    
    # Rotation, substitution, and constant addition for last key column
    temp[0] = K.fetch_int(s_box[key[1][3].integer_representation()]) + round_constant_part
    temp[1] = K.fetch_int(s_box[key[2][3].integer_representation()])
    temp[2] = K.fetch_int(s_box[key[3][3].integer_representation()])
    temp[3] = K.fetch_int(s_box[key[0][3].integer_representation()])
    
    # Column 1
    key[0][0] = key[0][0] + temp[0]
    key[1][0] = key[1][0] + temp[1]
    key[2][0] = key[2][0] + temp[2]
    key[3][0] = key[3][0] + temp[3]
    
    # Columns 2-4
    for i in range(1, 4):
        key[0][i] = key[0][i] + key[0][i - 1]
        key[1][i] = key[1][i] + key[1][i - 1]
        key[2][i] = key[2][i] + key[2][i - 1]
        key[3][i] = key[3][i] + key[3][i - 1]

def aes_key_schedule(key, num_rounds):
    key_state = int_to_gf_state(key)
    keys = [copy.deepcopy(key_state)]
    for i in range(1, num_rounds + 1):
        generate_new_round_key(key_state, i)
        keys.append(copy.deepcopy(key_state))
    
    return keys
    
def aes_encrypt(data, keys, num_rounds, sbox = s_box):
    data_state = int_to_gf_state(data)
    key_state = int_to_gf_state(key)
    
    # Whitening
    add_round_key(data_state, keys[0])
    
    # Run rounds
    for i in range(0, num_rounds - 1):
        #generate_new_round_key(key_state, i + 1)
        byte_substitution(data_state, sbox)
        shift_rows(data_state)
        mix_columns(data_state)
        add_round_key(data_state, keys[i + 1])
        
    # Final round
    #generate_new_round_key(key_state, num_rounds)
    byte_substitution(data_state, sbox)
    shift_rows(data_state)
    add_round_key(data_state, keys[num_rounds])
    
    ciphertext = gf_state_to_int(data_state)
    return ciphertext
    
def aes_decrypt(data, keys, num_rounds):
    data_state = int_to_gf_state(data)
    key_state = int_to_gf_state(key)
    
    #keys = [copy.deepcopy(key_state)]
    #for i in range(1, num_rounds + 1):
    #    generate_new_round_key(key_state, i)
    #    keys.append(copy.deepcopy(key_state))
        
    # Undo last round
    add_round_key(data_state, keys[num_rounds])
    shift_rows_inverse(data_state)
    byte_substitution_inv(data_state)
    
    for i in range(1, num_rounds):
        add_round_key(data_state, keys[num_rounds - i])
        mix_columns_inverse(data_state)
        shift_rows_inverse(data_state)
        byte_substitution_inv(data_state)
        
    add_round_key(data_state, keys[0])
    
    plaintext = gf_state_to_int(data_state)
    return plaintext
    
def find_sbox_4_rounds():
    dim = 256
    num_rounds = 4
    key = 0 # test with random later
    keys = aes_key_schedule(key, num_rounds)
    # <dim> sets of Lambda-sets (each of it has <dim> (plaintext, ciphertext) pairs)
    lambda_sets = []
    for i in range(0, dim):
        lambda_sets.append([])
        for j in range(0, dim):
            ciphertext = j | (i << 8)
            plaintext = aes_decrypt(ciphertext, keys, num_rounds)
            lambda_sets[i].append([plaintext, ciphertext])
            
    
    # Set up equations and start solving :)
    R = PolynomialRing(K, ['z' + str(i) for i in range(0, dim)], order="lex")
    R.inject_variables()
    z_vars = [z0.args()[i] for i in range(0, dim)]
    equations = []
    for i in range(0, dim):
        eq = 0
        for j in range(0, dim):
            z_index = (lambda_sets[i][j][0] & 0xFF)
            eq += z_vars[z_index]
        equations.append(eq)

    # 1) Find 9 variables such that fixing them reduces the dimension of the ideal to zero
    # 1) Fix them to some linearly independent values

    values_to_assign = [0b00000001, 0b00000010, 0b00000100, 0b00001000, 0b00010000, 0b00100000, 0b01000000, 0b10000000, 0b0]
    
    gb = None
    counter = 0
    value_counter = 0
    I = R.ideal(equations)
    if I.dimension() > 9:
        print "[ERROR] Dimension of the ideal > 9!"
        exit()
    vars_fixed = []

    while I.dimension() > 0:
        print "Ideal dimension:", I.dimension()
        print "Adding", z_vars[counter]
        equations.append(z_vars[counter] + K.fetch_int(values_to_assign[value_counter]))
        vars_fixed.append(z_vars[counter])
        counter += 1
        value_counter += 1
        print value_counter
        I = R.ideal(equations)
        if I.dimension() > 0:
            continue
        gb = I.groebner_basis(algorithm="singular:slimgb")
        if 1 in list(gb):
            print "Removing", z_vars[counter - 1]
            del equations[-1]
            del vars_fixed[-1]
            I = R.ideal(equations)
            value_counter -= 1
            continue
        #print "Solutions:", list(gb)
        break

    print "Vars fixed:", vars_fixed

    permutation_test = []
    for sol in list(gb):
        if len(sol.coefficients()) > 1:
            permutation_test.append(sol.coefficients()[1])
        else:
            permutation_test.append(0)

    len_1 = len(permutation_test)
    permutation_test = list(set(permutation_test))
    len_2 = len(permutation_test)
    if (len_1 == len_2):
        print "[INFO] The result is a permutation."
    else:
        print "[ERROR] The result is not a permutation."

    equiv_sbox = []
    for sol in list(gb):
        if len(sol.coefficients()) > 1:
            equiv_sbox.append(sol.coefficients()[1])
        else:
            equiv_sbox.append(0)

    return equiv_sbox

def find_sbox_3_rounds(key):
    dim = 256*3
    num_rounds = 3
    #key = 0x0
    keys = aes_key_schedule(key, num_rounds)
    # <dim> sets of Lambda-sets (each of it has <dim> (plaintext, ciphertext) pairs)
    lambda_sets = []
    psi = 0x0
    phi = 0x0
    for i in range(0, dim):
        lambda_sets.append([])
        # Generate plaintexts
        z_1 = (i + int(i/256) + 1) & 0xFF
        z_2 = (i + int(i/256) + 4) & 0xFF
        w_1 = (i + int(i/256) + 2) & 0xFF
        w_2 = (i + int(i/256) + 8) & 0xFF
        psi = int(i/256) + 1
        phi = int(i/256) + 2
        p_1 = z_1 | (w_1 << 8)
        p_2 = z_2 | (w_2 << 8)
        p_1_tilde = z_1 | (w_2 << 8) | (psi << 16) | (phi << 24)
        p_2_tilde = z_2 | (w_1 << 8) | (psi << 16) | (phi << 24)

        # Get ciphertexts
        c_1 = aes_encrypt(p_1, keys, num_rounds)
        c_2 = aes_encrypt(p_2, keys, num_rounds)
        c_1_tilde = aes_encrypt(p_1_tilde, keys, num_rounds)
        c_2_tilde = aes_encrypt(p_2_tilde, keys, num_rounds)

        # Test property
        # k_used = (keys[3][0][0]).integer_representation()
        # part_used = 0
        # mask = 0xFF << (part_used * 8)
        # shift = part_used * 8
        # print (s_box_inv[((c_1 & mask) >> shift) ^^ k_used] ^^ s_box_inv[((c_2 & mask) >> shift) ^^ k_used] ^^ s_box_inv[((c_1_tilde & mask) >> shift) ^^ k_used] ^^ s_box_inv[((c_2_tilde & mask) >> shift) ^^ k_used])
        
        # Add to lambda sets
        lambda_sets[i].append([p_1, c_1])
        lambda_sets[i].append([p_2, c_2])
        lambda_sets[i].append([p_1_tilde, c_1_tilde])
        lambda_sets[i].append([p_2_tilde, c_2_tilde])
            
    # Set up equations and start solving :)
    R = PolynomialRing(K, ['z' + str(i) for i in range(0, 256)], order="lex")
    R.inject_variables()
    z_vars = [z0.args()[i] for i in range(0, 256)]
    equations = []
    M = matrix(K, 768 + 9, 256)
    for i in range(0, dim):
        eq = z_vars[0] + z_vars[0]
        for j in range(0, 4):
            z_index = (lambda_sets[i][j][1] & 0xFF)
            eq += z_vars[z_index]
            M[i, z_index] += 1
        equations.append(eq)

    # 1) Find 9 variables such that fixing them reduces the dimension of the ideal to zero
    # 1) Fix them to linearly independent values

    # Remark: The calculated S-box is S-box(\cdot k^(3)), where k^(3) is the corresponding (constant) part of the third round key
    # Hence, when comparing with the AES inverse S-box, the result should be XORed with k^(3)
    values_to_assign = [0b00000001, 0b00000010, 0b00000100, 0b00001000, 0b00010000, 0b00100000, 0b01000000, 0b10000000, 0b0]

    # Working with purely linear equation systems
    rank = M.rank()
    if rank < 247:
        print "[ERROR] Matrix rank < 247!"
        exit()

    t = walltime()
    variable_counter = 255
    value_counter = 0
    solve_vector = vector([K.fetch_int(0)] * (dim + 9))
    vars_fixed = []
    S = []
    last_rank = M.rank()
    while M.rank() < 256:
        print "Matrix rank:", M.rank()
        print "Adding", z_vars[variable_counter]
        M[dim + value_counter, variable_counter] = K.fetch_int(1)
        solve_vector[dim + value_counter] = K.fetch_int(values_to_assign[value_counter])
        vars_fixed.append(z_vars[variable_counter])
        variable_counter -= 1
        value_counter += 1
        print value_counter

        if last_rank == M.rank():
            print "Removing", z_vars[variable_counter + 1]
            M[dim + (value_counter - 1), variable_counter + 1] = K.fetch_int(0)
            solve_vector[dim + (value_counter - 1)] = K.fetch_int(0)
            del vars_fixed[-1]
            value_counter -= 1
            continue
        else:
            last_rank = M.rank()

        if M.rank() < 256:
            continue

        # Get solution
        S = M.solve_right(solve_vector)

        # try:
        #     S = M.solve_right(solve_vector)
        # except ValueError:
        #     print "Removing", z_vars[counter - 1]
        #     M[dim + (value_counter - 1), counter - 1] = K.fetch_int(0)
        #     solve_vector[dim + (value_counter - 1)] = K.fetch_int(0)
        #     del vars_fixed[-1]
        #     value_counter -= 1
        #     continue
        # print "Solutions:", list(gb)
        break
    print "[INFO] Time for S-box finding: {t:5.1f}s".format(t=walltime(t))
    
    equiv_sbox_inv = [e.integer_representation() for e in list(S)]
    len_1 = len(equiv_sbox_inv)
    ordered_unique = list(set(equiv_sbox_inv))
    len_2 = len(ordered_unique)
    if (len_1 == len_2):
        print "[INFO] The result is a permutation."
    else:
        print "[ERROR] The result is not a permutation."
        exit()
    
    return equiv_sbox_inv

    #variety = None
    # gb = None
    # counter = 0
    # value_counter = 0
    # I = R.ideal(equations)
    # if I.dimension() > 9:
    #     print "[ERROR] Dimension of the ideal > 9!"
    #     exit()
    # vars_fixed = []

    # t = walltime()
    # while I.dimension() > 0:
    #     print "Ideal dimension:", I.dimension()
    #     print "Adding", z_vars[counter]
    #     equations.append(z_vars[counter] + K.fetch_int(values_to_assign[value_counter]))
    #     vars_fixed.append(z_vars[counter])
    #     counter += 1
    #     value_counter += 1
    #     print value_counter
    #     I = R.ideal(equations)
    #     if I.dimension() > 0:
    #         continue
    #     #variety = I.variety()
    #     gb = I.groebner_basis(algorithm="singular:slimgb")
    #     #if len(variety) == 0:
    #     if 1 in list(gb):
    #         print "Removing", z_vars[counter - 1]
    #         del equations[-1]
    #         del vars_fixed[-1]
    #         I = R.ideal(equations)
    #         value_counter -= 1
    #         continue
    #     print "Solutions:", list(gb)
    #     break
    # #variety = I.variety()
    # print "Finding S-box time: {t:5.1f}s".format(t=walltime(t))
    # print "Vars fixed:", vars_fixed
    # exit()

    # permutation_test = []
    #for sol in sorted((variety[0]).items(), key=operator.itemgetter(1)):
    #   permutation_test.append(sol[1])
    #for sol in list(gb):
    # for sol in list(S):
    #     if len(sol.coefficients()) > 1:
    #         permutation_test.append(sol.coefficients()[1])
    #     else:
    #         permutation_test.append(0)

    # len_1 = len(permutation_test)
    # permutation_test = list(set(permutation_test))
    # len_2 = len(permutation_test)
    # if (len_1 == len_2):
    #     print "[INFO] The result is a permutation."
    # else:
    #     print "[ERROR] The result is not a permutation."
    #     exit()

    # equiv_sbox = []
    #for sol in reversed(sorted((variety[0]).items(), key=operator.itemgetter(0))):
    #    print [sol[0], sol[1]]
    #    equiv_sbox.append(sol[1])
    #for sol in list(gb):
    # for sol in list(S):
    #     if len(sol.coefficients()) > 1:
    #         equiv_sbox.append(sol.coefficients()[1])
    #     else:
    #         equiv_sbox.append(0)

    # return equiv_sbox

# Key is only used for verifying dependencies
def key_recovery_3_rounds(equiv_sbox_inv, key):
    #print equiv_sbox_inv
    num_rounds = 3
    keys = aes_key_schedule(key, num_rounds)
    dim = 256
    psi = 0x0
    phi = 0x0
    for i in range(0, dim):
        # Generate plaintexts
        z_1 = (i + int(i/256) + 1) & 0xFF
        z_2 = (i + int(i/256) + 4) & 0xFF
        w_1 = (i + int(i/256) + 2) & 0xFF
        w_2 = (i + int(i/256) + 8) & 0xFF
        psi = int(i/256) + 1
        phi = int(i/256) + 2
        p_1 = z_1 | (w_1 << 8)
        p_2 = z_2 | (w_2 << 8)
        p_1_tilde = z_1 | (w_2 << 8) | (psi << 16) | (phi << 24)
        p_2_tilde = z_2 | (w_1 << 8) | (psi << 16) | (phi << 24)

        # Get ciphertexts
        c_1 = aes_encrypt(p_1, keys, num_rounds)
        c_2 = aes_encrypt(p_2, keys, num_rounds)
        c_1_tilde = aes_encrypt(p_1_tilde, keys, num_rounds)
        c_2_tilde = aes_encrypt(p_2_tilde, keys, num_rounds)

        # Find 15 relations (a + k_i)
        relations = [0] * 15
        counter = 0
        for rel in range(1, 16):
            mask = 0xFF << (rel * 8)
            shift = rel * 8
            #print hex(c_1)
            #print hex((c_1 & mask) >> shift)
            for ak in range(0, 256):
                l = (equiv_sbox_inv[((c_1 & mask) >> shift) ^^ ak] ^^ equiv_sbox_inv[((c_2 & mask) >> shift) ^^ ak] ^^ equiv_sbox_inv[((c_1_tilde & mask) >> shift) ^^ ak] ^^ equiv_sbox_inv[((c_2_tilde & mask) >> shift) ^^ ak])
                if l == 0:
                    relations[rel - 1] = ak
                    counter += 1
        if counter != 15:
            continue

        # Verify dependencies
        print "--- Verification ---"
        print "[1]", [hex(relations[m] ^^ relations[m + 1]) for m in range(0, 14)]
        print "[2]", [hex((keys[3][(m + 1) % 4][n + int((m + 1) / 4)]).integer_representation() ^^ (keys[3][(m + 2) % 4][n + int((m + 2) / 4)]).integer_representation()) for n in range(0, 4) for m in range(0, 4) if not (m + 1 % 4 == 0 and n == 0) and (n + int((m + 2) / 4) != 4)]
        break

# num_rounds = 2
# plaintext = 0x6bc1bee22e409f96e93d7e117393172a
# #plaintext = 0
# key = 0x2b7e151628aed2a6abf7158809cf4f3c
# #key = 0
# keys = aes_key_schedule(key, num_rounds)
# ciphertext = aes_encrypt(plaintext, keys, num_rounds)
# print "Plaintext:", hex(plaintext)
# print "Key:", hex(key)
# print "Ciphertext:", hex(ciphertext)

# plaintext = aes_decrypt(ciphertext, keys, num_rounds)
# print "Plaintext:", hex(plaintext)

# R = PolynomialRing(K, ['z' + str(i) for i in range(0, 3)])
# R.inject_variables()
# z_vars = [z0.args()[i] for i in range(0, 3)]
# equations = []
# for i in range(0, 3):
#     eq = z_vars[i]
#     for j in range(0, 1):
#         eq += K.fetch_int(j+3+i)
#     equations.append(eq)
# print equations
# I = R.ideal(equations)
# print I.groebner_basis()
# print I
# variety = I.variety()
# print variety

#equiv_sbox = find_sbox_4_rounds()
#print "Equivalent S-box:", equiv_sbox

key = (K.random_element()).integer_representation() # for testing
equiv_sbox_inv = find_sbox_3_rounds(key)
#print "Equivalent S-box 2:", equiv_sbox_inv

t = walltime()
key_recovery_3_rounds(equiv_sbox_inv, key)
print "[INFO] Time for key finding: {t:5.1f}s".format(t=walltime(t))

#M = Matrix(K, [[K.fetch_int(1), K.fetch_int(2)], [K.fetch_int(0), K.fetch_int(1)]])
#print M.solve_right(vector([K.fetch_int(0), K.fetch_int(3)]))

#print list(M.kernel())

#FI = K^2

#vecs = [FI(row) for row in M.rows()]
#print FI.linear_dependence(vecs)
#print len(FI.linear_dependence(vecs))

#key = 0
#key_gf = int_to_gf_state(key)
#generate_new_round_key(key_gf, 1)
#print hex(gf_state_to_int(key_gf))
#generate_new_round_key(key_gf, 2)
#print hex(gf_state_to_int(key_gf))
#generate_new_round_key(key_gf, 3)
#print hex(gf_state_to_int(key_gf))
#generate_new_round_key(key_gf, 4)
#print hex(gf_state_to_int(key_gf))
#generate_new_round_key(key_gf, 5)
#print hex(gf_state_to_int(key_gf))