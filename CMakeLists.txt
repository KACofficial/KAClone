cmake_minimum_required(VERSION 3.10)
project(KAClone)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add the executable target
add_executable(kaclone src/main.cpp src/utils/utils.cpp)

# Include directories
target_include_directories(kaclone PRIVATE src/utils)

# Link OpenSSL libraries
target_link_libraries(kaclone PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Install target
install(TARGETS kaclone DESTINATION bin)
