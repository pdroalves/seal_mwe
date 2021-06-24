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

    // 80-bit
    // size_t poly_modulus_degree = 1024;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 41 }));
    // double scale = pow(2.0, 18);
    // 
    // 100-bit
    // size_t poly_modulus_degree = 1024;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 34 }));
    // double scale = pow(2.0, 16);
    // 
    // 128-bit
    // size_t poly_modulus_degree = 1024;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 27 }));
    // double scale = pow(2.0, 13);
    // 
    // 80-bit
    // size_t poly_modulus_degree = 2048;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, 16, 33}));
    // double scale = pow(2.0, 16);
    // 
    // 100-bit
    // size_t poly_modulus_degree = 2048;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 37, 31}));
    // double scale = pow(2.0, 16);
    // 
    // 128-bit
    // size_t poly_modulus_degree = 2048;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 31 , 23}));
    // double scale = pow(2.0, 15);
    // 
    // 80-bit
    // size_t poly_modulus_degree = 4096;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 21, 21, 21, 21, 40}));
    // double scale = pow(2.0, 21);
    // 
    // 100-bit
    // size_t poly_modulus_degree = 4096;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, 21, 21, 21, 35}));
    // double scale = pow(2.0, 21);
    // 
    // 128-bit
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, 21, 21, 30}));
    double scale = pow(2.0, 21);
    
    SEALContext context(parms, true, sec_level_type::none);
    
    const int nmuls = 1;
    // Initialize keys
    KeyGenerator keygen(context);

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    if(context.using_keyswitching())
        keygen.create_relin_keys(relin_keys);

    // Ciphertext handlers
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
 	
    CKKSEncoder encoder(context);

    // Initializes plaintexts and encrypt
    Ciphertext c0, c1;
    Plaintext p0, p1;
    double m0 = 2.2;
    double m1 = 1.1;
    double mR = m0 * m1;
    encoder.encode(m0, scale, p0);
    encryptor.encrypt(p0, c0);
    encoder.encode(m1, scale, p1);
    encryptor.encrypt(p1, c1);

    Ciphertext cR;
    evaluator.multiply(c0, c1, cR);
    for(int i = 1; i < nmuls; i++){
        evaluator.relinearize_inplace(cR, relin_keys);
        evaluator.rescale_to_next_inplace(cR);
        parms_id_type last_parms_id = cR.parms_id();
        evaluator.mod_switch_to_inplace(c1, last_parms_id);
        cR.scale() = scale;

        evaluator.multiply_inplace(cR, c1);
        mR *= m1;
    }
    // evaluator.rescale_to_next_inplace(cR);
    
    /*
    Decrypt, decode, and print the result.
    */
   	Plaintext pR;
    decryptor.decrypt(cR, pR);
    std::vector<double> result;
    encoder.decode(pR, result);
    std::cout << "    + Computed result ......" << std::endl;
    print_vector(result, 3, 7);
    std::cout << "Expected: " << mR << std::endl;
}
