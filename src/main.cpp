#include "utils/utils.hpp"
#include <argparse/argparse.hpp>
#include <iostream>
#include <ostream>

int main(int argc, char *argv[]) {
  argparse::ArgumentParser program("kaclone", "0.0.1");

  program.add_description("Backup your files fast, and reliably");

  program.add_argument("-V", "--verbose")
      .help("increase output verbosity")
      .default_value(false)
      .implicit_value(true);

  program.add_argument("-ex", "--exclude")
      .help("exclude these files(regex)")
      .default_value("^$");

  program.add_argument("-on", "--only")
      .help("only backup these files(regex)")
      .default_value(".*");

  program.add_argument("-o", "--output")
      .help("The folder to place the backup")
      .default_value("./backup");

  program.add_argument("source")
      .help("The folder/file to backup")
      .remaining()
      .required();

  try {
    program.parse_args(argc, argv); // Parse command-line arguments
  } catch (const std::runtime_error &err) {
    std::cout << err.what() << std::endl;
    std::cerr << program;
    std::exit(1);
  }

  startBackupTool(program);

  return 0;
}
