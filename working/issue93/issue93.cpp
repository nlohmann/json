#include "src/json.hpp"

using namespace nlohmann;

int main()
{
      {
          json a = {1, 2, 3};
          json::reverse_iterator rit = a.rbegin();
          ++rit;
          std::cerr << "*" << std::endl;
      }

      {
          json a = {1,2,3};
          json::reverse_iterator rit = ++a.rbegin();
          std::cerr << "*" << std::endl;
      }

      {
          json a = {1,2,3};
          json::reverse_iterator rit = a.rbegin();
          ++rit;
          std::cerr << "*" << std::endl;
      }
      
      {
          json a = {1,2,3};
          json::reverse_iterator rit = a.rbegin();
          ++rit;
          std::cerr << "*" << std::endl;
          json b = {0,0,0};
          std::transform(rit,a.rend(),b.rbegin(),[](json el){return el;});
          std::cout<<b <<std::endl;
          std::cerr << "*" << std::endl;
      }
      
      {
          json a = {1,2,3};
          json b = {0,0,0};
          std::transform(++a.rbegin(),a.rend(),b.rbegin(),[](json el){return el;});
          std::cout<<b <<std::endl;
          std::cerr << "*" << std::endl;
      }
}
