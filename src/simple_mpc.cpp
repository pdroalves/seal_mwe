#include <iostream>
#include <seal/seal.h>
#include <random>
#include <vector>
#include <seal/util/polycore.h>
#include "seal/util/rlwe.h"
#include "seal/util/polyarithsmallmod.h"

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
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 60}));
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    double scale = pow(2.0, 40);
    
    SEALContext context(parms);
    
    // Initialize keys
    int num_parties = 2;
    std::cout << "num_parties: " << num_parties << std::endl;

    std::vector<SecretKey> secret_keys;
    // Each party runs the default algorithm to generate a secret key
    // The outcome will be its share of the ideal secret key
    for(int i = 0; i < num_parties; i++){
        KeyGenerator keygen_node(context);
        secret_keys.push_back(keygen_node.secret_key());
    }

    KeyGenerator keygen(context);

    // Collective public key
    // A public polynomial is sampled from the uniform distribution
    auto p1 = keygen.create_p1();
    
    // Each party runs a modified public key generator 
    // to generate a part of the collective public key
    std::vector<PublicKey> public_keys(num_parties);
    for(int i = 0; i < num_parties; i++){
        KeyGenerator keygen_node(context, secret_keys[i]);
        keygen_node.create_mpc_share_public_key(p1, public_keys[i]);
    }
    
    // Collective relin key
    // A public polynomial is sampled from the uniform distribution
    auto a = keygen.create_p1();
    std::vector<RelinKeys> relin_keys_st1(num_parties);
    for(int i = 0; i < num_parties; i++){
        KeyGenerator keygen_node(context, secret_keys[i]);
        keygen_node.execute_mpc_step1_relin_keys(a, relin_keys_st1[i]);
    }
    RelinKeys rlk_s1;
    keygen.combine_relin_keys(rlk_s1, relin_keys_st1);

    std::vector<RelinKeys> relin_keys_st2(num_parties);
    for(int i = 0; i < num_parties; i++){
        KeyGenerator keygen_node(context, secret_keys[i]);
        keygen_node.execute_mpc_step2_relin_keys(rlk_s1, relin_keys_st2[i]);
    }
    RelinKeys rlk_s2;
    keygen.combine_relin_keys(rlk_s2, relin_keys_st2);

    // The collective public key is the outcome when we combine all the shares
    PublicKey public_key;
    keygen.create_collective_public_key(public_key, public_keys);
    RelinKeys relin_keys;
    keygen.create_collective_relin_keys(rlk_s1, rlk_s2, relin_keys);
    
    // Do something
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    Ciphertext c0, c1, c2;
    Plaintext pt0, pt1, pt2;
    double m0 = 3.14159265;
    double m1 = 0.4;
    double m2 = 1.0;
    double mR = (m0 + m1) * m2;
    Encryptor encryptor(context, public_key);

    encoder.encode(m0, scale, pt0);
    encryptor.encrypt(pt0, c0);

    encoder.encode(m1, scale, pt1);
    encryptor.encrypt(pt1, c1);
    
    encoder.encode(m2, scale, pt2);
    encryptor.encrypt(pt2, c2);

    // Computes p0 * p1 + p2
    Ciphertext cR;
    evaluator.add(c0, c1, cR);
    evaluator.multiply(cR, c2, cR);
    // evaluator.relinearize_inplace(cR, relin_keys);
    // evaluator.rescale_to_next_inplace(cR);

    // Discards not used upper levels of c2 to match cR
    // parms_id_type last_parms_id = cR.parms_id();
    // evaluator.mod_switch_to_inplace(c2, last_parms_id);
    // cR.scale() = scale;

    /*
    Decrypt, decode, and print the result.
    */
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_count = parms.poly_modulus_degree();
    Plaintext ptR;
    // Each party runs default decryption with its share of the 
    // secret key and combines to the decryption outcome of the other
    // parties. 
    if(cR.size() > 2){
        Ciphertext cS;
        for(int i = 0; i < num_parties-1; i++){
            Decryptor decryptor(context, secret_keys[i]);
            decryptor.combined_decrypt(cR, cS);
        }
        {
            Decryptor decryptor(context, secret_keys[num_parties-1]);
            decryptor.combined_decrypt(cR, cS, true);
        }
        cR = cS;
    }
        
    for(int i = 0; i < num_parties-1; i++){
        Decryptor decryptor(context, secret_keys[i]);
        decryptor.combined_decrypt(cR, ptR);
    }
    {
        Decryptor decryptor(context, secret_keys[num_parties-1]);
        decryptor.combined_decrypt(cR, ptR, true);
    }

    std::vector<double> result;
    encoder.decode(ptR, result);

    std::cout << "Computed result:" << std::endl;
    print_vector(result, 3, 7);
    std::cout << "Expected: " << mR << std::endl;

}
