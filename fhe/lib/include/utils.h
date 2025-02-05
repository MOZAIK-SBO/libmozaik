//
// Created by leonard on 2/5/25.
//

#ifndef FHE_UTILS_H
#define FHE_UTILS_H

#include <iostream>
#include <vector>

namespace ckks_nn {

    std::vector<std::pair<int, std::vector<double>>> readCSV(std::istream& in);

}


#endif //FHE_UTILS_H
