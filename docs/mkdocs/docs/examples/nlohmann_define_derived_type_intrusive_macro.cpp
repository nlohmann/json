#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;

class A
{
  private:
    double Aa = 0.0;
    double Ab = 0.0;

  public:
    A() = default;
    A(double a, double b) : Aa(a), Ab(b) {}
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(A, Aa, Ab)
};

class B : public A
{
  private:
    int Ba = 0;
    int Bb = 0;

  public:
    B() = default;
    B(int a, int b, double aa, double ab) : A(aa, ab), Ba(a), Bb(b) {}
    NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE(B, A, Ba, Bb)
};

int main()
{
    B example(23, 42, 3.142, 1.777);
    json example_json = example;

    std::cout << std::setw(4) << example_json << std::endl;
}