#define CONFIG_ONLY
#include "ptlsim.cpp"

int main(int argc, char* argv[]) {
  PTLsimConfig config;
  config.reset();
  ConfigurationParser<PTLsimConfig> configparser;
  configparser.setup();
  configparser.printusage(cout, config);
  return 0;
}
