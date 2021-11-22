#include <iostream>
#include <seal/seal.h>
#include <random>
#include <vector>

using namespace seal;

/*
Helper function: Prints a vector of floating-point values.
*/
template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::endl;
    if (slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}

int main(){
    // Parameters
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 54, 46, 46, 46, 46, 46, 46 })); // 80 bits
    // double scale = pow(2.0, 46);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 54, 36, 36, 36, 36, 36, 36 })); // 100 bits
    // double scale = pow(2.0, 36
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 54, 26, 26, 26, 26, 26, 34 }));
    double scale = pow(2.0, 26);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    
    SEALContext context(parms, true, sec_level_type::none);
    
    // Initialize keys
    KeyGenerator keygen(context);

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(gal_keys);

    // Ciphertext handlers
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
 	
    CKKSEncoder encoder(context);

    // Initializes plaintexts and encrypt
    Ciphertext c0, c1, c2;
    Plaintext p0, p1, p2;
    std::vector<double> input(poly_modulus_degree>>1);
    input[0] = 3.14159265;
    encoder.encode(input, scale, p0);
    encryptor.encrypt(p0, c0);

    input[0] = 0.4;
    encoder.encode(input, scale, p1);
    encryptor.encrypt(p1, c1);
    
    input[0] = 1.0;
    encoder.encode(input, scale, p2);
    encryptor.encrypt(p2, c2);

    // Computes p0 * p1 + p2
    Ciphertext cR;
    evaluator.multiply(c0, c1, cR);
    evaluator.relinearize_inplace(cR, relin_keys);
    evaluator.rescale_to_next_inplace(cR);

    // Discards not used upper levels of c2 to match cR
    parms_id_type last_parms_id = cR.parms_id();
    evaluator.mod_switch_to_inplace(c2, last_parms_id);
    cR.scale() = scale;
    evaluator.add_inplace(cR, c2);

    /*
    Decrypt, decode, and print the result.
    */
   	Plaintext pR;
    decryptor.decrypt(cR, pR);
    std::vector<double> result;
    encoder.decode(pR, result);
    std::cout << "    + Computed result ......." << std::endl;
    print_vector(result, 3, 7);
    std::cout << "Expected " << (3.14159265*0.4+1) << std::endl;
}
