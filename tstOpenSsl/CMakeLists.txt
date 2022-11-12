cmake_minimum_required(VERSION 3.23)
project(tstOpenSsl)

set(CMAKE_CXX_STANDARD 14)

find_package(OpenSSL REQUIRED)

link_libraries("crypto")

add_executable(${PROJECT_NAME} main.cpp openssl_aes.cpp openssl_rnd.cpp openssl_rsa.cpp utils.cpp)
