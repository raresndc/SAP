#include <iostream>
#include <string>
using namespace std;

namespace ism
{
	class string
	{
	private:
		int length;
		char* ps;
	public:
		__declspec(dllexport) string();
		__declspec(dllexport) string(const char*);
		__declspec(dllexport) string(const string&);
		__declspec(dllexport) ~string();
		__declspec(dllexport) const string& operator=(const string&);

		__declspec(dllexport) int getLength();

		__declspec(dllexport) const string& operator+=(const string&);

		//concatenation
		__declspec(dllexport) const string& operator+(const string&);
		__declspec(dllexport) const string& operator+(const char*);
		__declspec(dllexport) friend const string& operator+(const char*, const string&);

		__declspec(dllexport) friend ostream& operator<<(ostream&, ism::string&);
		__declspec(dllexport) friend istream& operator>>(istream&, ism::string&);

		//overloading unary operators 
		__declspec(dllexport) bool operator!() const; //test sir vid
		__declspec(dllexport) char& operator[](int);
		__declspec(dllexport) const char& operator[](int) const;
		//overloading binary operators 
		__declspec(dllexport) bool operator==(const string&) const;
		__declspec(dllexport) bool operator!=(const string&) const;
		__declspec(dllexport) bool operator<(const string&) const;
		__declspec(dllexport) bool operator>(const string&) const;
		__declspec(dllexport) bool operator<=(const string&) const;
		__declspec(dllexport) bool operator>=(const string&) const;

	}; //end class
}