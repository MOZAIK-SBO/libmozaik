//
// Created by leonard on 2/5/25.
//

#include <cmath>
#include "utils.h"

namespace ckks_nn {
    enum class CSVState {
        UnquotedField,
        QuotedField,
        QuotedQuote
    };

    std::pair<int, std::vector<double>> readCSVRow(const std::string &row) {
        CSVState state = CSVState::UnquotedField;
        std::vector<std::string> fields {""};

        size_t i = 0; // index of the current field
        for (char c : row) {
            switch (state) {
                case CSVState::UnquotedField:
                    switch (c) {
                        case ',': // end of field
                            fields.push_back(""); i++;
                            break;
                        case '"': state = CSVState::QuotedField;
                            break;
                        default:  fields[i].push_back(c);
                            break; }
                    break;
                case CSVState::QuotedField:
                    switch (c) {
                        case '"': state = CSVState::QuotedQuote;
                            break;
                        default:  fields[i].push_back(c);
                            break; }
                    break;
                case CSVState::QuotedQuote:
                    switch (c) {
                        case ',': // , after closing quote
                            fields.push_back(""); i++;
                            state = CSVState::UnquotedField;
                            break;
                        case '"': // "" -> "
                            fields[i].push_back('"');
                            state = CSVState::QuotedField;
                            break;
                        default:  // end of quote
                            state = CSVState::UnquotedField;
                            break; }
                    break;
            }
        }

        std::vector<double> values;
        for(auto& str : fields) {
            auto dd = std::stod(str);
            values.push_back(dd);
        }

        auto cls = (int)std::round(values[values.size() - 1]);
        values.pop_back();

        return std::make_pair(cls, values);
    }

/// Read CSV file, Excel dialect. Accept "quoted fields ""with quotes"""
    std::vector<std::pair<int, std::vector<double>>> readCSV(std::istream &in) {
        std::vector<std::pair<int, std::vector<double>>> table;
        std::string row;
        while (!in.eof()) {
            std::getline(in, row);
            if (in.bad() || in.fail()) {
                break;
            }
            auto fields = readCSVRow(row);
            table.push_back(fields);
        }
        return table;
    }
}