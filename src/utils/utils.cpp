#include <argparse/argparse.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <regex>
#include <sstream>
#include "utils.hpp"

namespace fs = std::filesystem;
void backupFile(const fs::path &sourcePath, const fs::path &destinationPath,
                const argparse::Argument &verbose);
bool checkValidity(const std::string &path, const std::string &exclude,
                   const std::string &only);
std::string computeSHA256(const fs::path &filePath);

void startBackupTool(argparse::ArgumentParser &parser) {
  std::cout << "Started Backup..." << std::endl;

  auto start = std::chrono::high_resolution_clock::now();

  std::vector<std::string> sources =
      parser.get<std::vector<std::string>>("source");
  fs::path output(parser.get<std::string>("-o"));
  std::string onlyPattern = parser.get<std::string>("-on");

  if (!fs::exists(output)) {
    fs::create_directory(output);
  }

  for (const std::string &sourceStr : sources) {
    fs::path source(sourceStr);

    if (fs::is_regular_file(source)) {
      if (checkValidity(source.string(), parser.get<std::string>("-ex"),
                        onlyPattern)) {
        fs::path destination = output / source.filename();
        backupFile(source, destination, parser["-V"]);
      }
      continue;
    }

    // Handle directories
    for (const auto &entry : fs::recursive_directory_iterator(source)) {
      if (!entry.is_regular_file()) {
        continue;
      }
      if (fs::is_directory(output) &&
          fs::proximate(entry.path(), source)
                  .string()
                  .find(fs::proximate(output, source).string()) == 0) {
        continue;
      }

      if (checkValidity(entry.path().string(), parser.get<std::string>("-ex"),
                        onlyPattern)) {
        // Create the destination path for backup
        fs::path destination = output / fs::relative(entry.path(), source);
        backupFile(entry.path(), destination, parser["-V"]);
      } else {
        // Optionally log if the file is skipped due to the onlyPattern
        // if (parser["-V"] == true)
        //   VERBOSE_LOG("Skipping file (does not match -on/--only): " +
        //               entry.path().string());
      }
    }
  }

  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end - start;

  // Print the total time taken
  std::cout << "Total time taken: " << duration.count() << " seconds"
            << std::endl;
}

bool checkValidity(const std::string &path, const std::string &exclude,
                   const std::string &only) {
  std::regex excludeRegex(exclude);
  std::regex onlyRegex(only);

  // Check if the path should be excluded
  if (std::regex_search(path, excludeRegex)) {
    return false; // Excluded
  }

  // Check if the path matches the only pattern
  if (std::regex_search(path, onlyRegex)) {
    return true; // Included
  }

  return false; // Not included
}

void backupFile(const fs::path &sourcePath, const fs::path &destinationPath,
                const argparse::Argument &verbose) {
  try {
    // Ensure the destination directory exists
    fs::create_directories(destinationPath.parent_path());

    // Check if the file already exists in the destination
    if (fs::exists(destinationPath)) {
      // Compare SHA-256 hashes
      std::string sourceHash = computeSHA256(sourcePath);
      std::string destinationHash = computeSHA256(destinationPath);

      if (sourceHash == destinationHash) {
        if (verbose == true)
          VERBOSE_LOG("File is unchanged, skipping backup: " +
                      sourcePath.string());
        return; // Skip backup for this file if it is unchanged
      } else {
        if (verbose == true)
          VERBOSE_LOG("File has changed, backing up: " + sourcePath.string());
      }
    } // else {
    //   if (verbose == true)
    //     VERBOSE_LOG("Backing up: " + sourcePath.string());
    // }

    // Copy the file
    fs::copy_file(sourcePath, destinationPath,
                  fs::copy_options::overwrite_existing);
    if (verbose == true)
      VERBOSE_LOG("Successfully copied " + sourcePath.string() + " to " +
                  destinationPath.string());
  } catch (const fs::filesystem_error &e) {
    std::cerr << "Error copying file: " << e.what() << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "General error: " << e.what() << std::endl;
  }
}

std::string computeSHA256(const fs::path &filePath) {
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLength;

  // Create the message digest context
  mdctx = EVP_MD_CTX_new();
  if (mdctx == nullptr) {
    throw std::runtime_error("Failed to create EVP_MD_CTX");
  }

  // Load the SHA-256 algorithm
  md = EVP_sha256();
  if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
    EVP_MD_CTX_free(mdctx);
    throw std::runtime_error("Failed to initialize digest");
  }

  // Open the file
  std::ifstream file(filePath, std::ios::binary);
  if (!file.is_open()) {
    EVP_MD_CTX_free(mdctx);
    throw std::runtime_error("Could not open file: " + filePath.string());
  }

  // Read the file in chunks and update the digest
  char buffer[8192*2];
  while (file.read(buffer, sizeof(buffer))) {
    EVP_DigestUpdate(mdctx, buffer, file.gcount());
  }
  // Handle the last chunk
  EVP_DigestUpdate(mdctx, buffer, file.gcount());

  // Finalize the digest
  if (EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1) {
    EVP_MD_CTX_free(mdctx);
    throw std::runtime_error("Failed to finalize digest");
  }

  // Free the context
  EVP_MD_CTX_free(mdctx);

  // Convert hash to hex string
  std::ostringstream oss;
  for (unsigned int i = 0; i < hashLength; ++i) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(hash[i]);
  }
  return oss.str();
}
