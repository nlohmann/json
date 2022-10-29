
// Random number generator in range of (min,max)
// in linear_congruential_engine

#include <iostream>
#include <chrono>
#include <random>
using namespace std;
 
// driver program
int main ()
{
 
    // finds the time between the system clock
    //(present time) and clock's epoch
    unsigned seed = chrono::system_clock::now().time_since_epoch().count();
     
    // minstd_rand0 is a standard
    // linear_congruential_engine
    minstd_rand0 generator (seed);
     
    // generates the random number
    cout << generator() << " is a random number between ";
     
    //use of min and max functions
    cout << generator.min() << " and " << generator.max();
     
    return 0;
}
