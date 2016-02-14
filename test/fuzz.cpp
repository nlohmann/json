/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (fuzz test support)
|  |  |__   |  |  | | | |  version 2.0.0
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

To run under afl:
  afl-fuzz -i testcases -o output ./fuzz

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
*/

#include <json.hpp>

using json = nlohmann::json;

int main()
{
	json *jp;

#ifdef __AFL_HAVE_MANUAL_CONTROL
	while (__AFL_LOOP(1000)) {
#endif
		jp = new json();
		json j = *jp;
		try {
			j << std::cin;
		} catch (std::invalid_argument e) {
			std::cout << "Invalid argument in parsing" << e.what() << '\n';
		}

		if (j.find("foo") != j.end()) {
			std::cout << "Found a foo";
		}

		std::cout << j.type() << j << std::endl;

		delete jp;
#ifdef __AFL_HAVE_MANUAL_CONTROL
	}
#endif
}
