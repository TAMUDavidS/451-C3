#ifndef USERFUNCTIONS_H
#define USERFUNCTIONS_H

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <utility>
#include <stdio.h>

void print_vector_strings_pair(std::vector<std::pair<std::string, std::string>> &vec){
    for(int i = 0; i < vec.size(); i++){
        std::cout << vec[i].first << " found at " << vec[i].second << std::endl;
    }
}

std::vector<std::pair<std::string, std::string>> user_defined_functions_and_entries(const char* fileName){
    // setup nm fileName > temp-funcs-entry.txt
    std::vector<std::pair<std::string, std::string>> functions;
    std::string cmd = "nm ";
    std::string newFile = "temp-funcs-entry.txt";
    std::string inFile = " > ";
    std::string command = (cmd + fileName + inFile + newFile).c_str();

    // call command and save dump to temp file
    system(command.c_str());

    // parse dump temp file, put into vector
    std::string line;
    std::string userDefined = " T "; // string to search for, means user or entry
    std::ifstream MyReadFile(newFile);
    while(getline(MyReadFile, line)){
        size_t found = line.find(userDefined);
        if(found != std::string::npos){
            std::pair<std::string, std::string> p;

            p.second = line.substr(0, line.find_first_of(" "));
            p.first = "<" + line.substr(line.find(" T ") + 3, line.size() - 1) + ">";
            functions.push_back(p); 
        }
    }

    // close and delete file
    MyReadFile.close();
    system("rm temp-funcs-entry.txt");

    return functions;
}

std::vector<std::string> fullFunc(std::string func, const char* fileName){
    std::vector<std::string> funcs;
    std::string c = "objdump -d ";
    std::string p = " | awk -v RS= '/^[[:xdigit:]]+ ";
    std::string end = "/' > instructions-fullFunc.txt";
    std::string cmd = (c + fileName).c_str();
    std::string cmd0 = (cmd + p + func + end).c_str();

    system(cmd0.c_str());
    std::string newFile = "instructions-fullFunc.txt";
    std::string line;
    std::ifstream MyReadFile(newFile); //error check later
    while (getline(MyReadFile, line)) {
        funcs.push_back(line);
    }
    // Close the file and delete
    MyReadFile.close();
    system("rm instructions-fullFunc.txt");

    return funcs;
}

void driver(const char* fileName){
    std::cout << "User Defined Functions:" << std::endl;
    std::vector<std::pair<std::string, std::string>> userDefinedFunctions = user_defined_functions_and_entries(fileName);
    print_vector_strings_pair(userDefinedFunctions);
    printf("\n");

    std::cout << "ASM of User Defined Functions:" << std::endl;
    for(int i = 0; i < userDefinedFunctions.size(); i++){
        std::vector<std::string> a = fullFunc(userDefinedFunctions[i].first, fileName);
        for(int j = 0; j < a.size(); j++){
            std::cout << a[j] << std::endl;
        }
        printf("\n");
    }
}

#endif
