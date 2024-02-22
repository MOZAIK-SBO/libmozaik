#include <iostream>
#include "neural_net.h"
#include "neural_net_evaluator.h"


using namespace ckks_nn;

int main() {

    NeuralNet test;

    NeuralNetEvaluator evaluator;
    auto cc = evaluator.m_cc;
    auto keys = evaluator.m_key;
    std::vector<double> test_vec(evaluator.m_batch_size);
    auto pt = cc->MakeCKKSPackedPlaintext(test_vec);



    auto ct = cc->Encrypt(keys.secretKey, pt);
    auto res = evaluator.eval_network(test, ct);

    std::cout << "Hello, World!" << std::endl;
    return 0;
}
