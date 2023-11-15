#include "userFunctions.h"

int main(int argc, char** argv){

    if(argc < 2){
        std::cout << "Usage: ./userFunctionsTest <fileToAnalyze>" << std::endl;
        return 1;
    }

    driver(argv[1]);
}

// g++ userFunctionsTest.cpp -o userFunctionsTest && ./userFunctionsTest fileInfo_sandbox.o
